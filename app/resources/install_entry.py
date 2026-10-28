#!/usr/bin/env python3
"""Fresh Debian/Ubuntu VLESS REALITY installer and transactional geodata updater."""
import argparse
import base64
import copy
import datetime
import getpass
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import uuid
import zipfile

BIN = Path('/usr/local/bin/xray')
ETC = Path('/usr/local/etc/xray')
CONFIG = ETC / 'config.json'
ASSETS = Path('/usr/local/share/xray')
DB = ASSETS / 'ru-blocked.dat'
MANAGER = Path('/usr/local/lib/xray-setup/manager.py')
STATE = Path('/var/lib/xray-setup')
SYSTEMD = Path('/etc/systemd/system')
GEO_SOURCE = 'https://raw.githubusercontent.com/runetfreedom/russia-blocked-geosite/release/'
RULE = 'ext:ru-blocked.dat:ru-blocked'
PRIVATE_IPS = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
               '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4',
               '240.0.0.0/4', '::/128', '::1/128', 'fc00::/7', 'fe80::/10', 'ff00::/8']


def say(message):
    print(message, flush=True)


def run(args, timeout=60, check=True, env=None):
    result = subprocess.run([str(a) for a in args], capture_output=True, text=True,
                            timeout=timeout, env=env)
    if check and result.returncode:
        # Do not print command arguments: they can contain private keys.
        raise RuntimeError('Команда ' + str(args[0]) + ' завершилась с кодом ' + str(result.returncode))
    return result


def fetch(url, maximum=128 * 1024 * 1024):
    error = None
    for attempt in range(3):
        try:
            request = urllib.request.Request(url, headers={'User-Agent': 'VLESS-Reality-Setup/1.0'})
            with urllib.request.urlopen(request, timeout=35) as response:
                data = response.read(maximum + 1)
            if len(data) > maximum:
                raise ValueError('Слишком большой загружаемый файл')
            return data
        except (OSError, ValueError) as exc:
            error = exc
            if attempt < 2:
                time.sleep(2)
    raise RuntimeError('Не удалось загрузить ' + url.split('?')[0]) from error


def atomic(path, data, mode=0o644, gid=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data if isinstance(data, bytes) else data.encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, mode)
        if gid is not None:
            os.chown(name, 0, gid)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def valid_host(host):
    if not host or any(ch.isspace() for ch in host):
        raise ValueError('Некорректный IP-адрес или домен')
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        domain = host.rstrip('.').encode('idna').decode('ascii').lower()
        if len(domain) > 253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x)
                                        for x in domain.split('.')):
            raise ValueError('Некорректный домен')
        return domain


def parse_vless(link):
    link = link.strip()
    try:
        p = urllib.parse.urlsplit(link)
        if p.scheme.lower() != 'vless' or p.password is not None or not p.hostname or not p.username:
            raise ValueError()
        user_id = str(uuid.UUID(urllib.parse.unquote(p.username)))
        port = p.port
        if port is None or not 1 <= port <= 65535:
            raise ValueError()
        host = valid_host(p.hostname)
    except (ValueError, UnicodeError):
        raise ValueError('Ожидается vless://UUID@HOST:PORT?... с корректным UUID и портом') from None
    q = urllib.parse.parse_qs(p.query, keep_blank_values=True)
    if any(len(v) != 1 for v in q.values()):
        raise ValueError('В ссылке есть повторяющиеся параметры')
    q = {k: v[0] for k, v in q.items()}
    if q.get('security') != 'reality' or q.get('type', 'tcp') not in ('tcp', 'raw'):
        raise ValueError('Поддерживается upstream VLESS + REALITY с транспортом TCP/RAW')
    if q.get('headerType', 'none') != 'none' or q.get('encryption', 'none') != 'none':
        raise ValueError('Поддерживаются headerType=none и encryption=none')
    if q.get('flow', '') not in ('', 'xtls-rprx-vision'):
        raise ValueError('Поддерживается flow=xtls-rprx-vision либо пустой flow')
    public = q.get('pbk', '')
    try:
        decoded = base64.b64decode(public + '=' * (-len(public) % 4), altchars=b'-_', validate=True)
    except Exception:
        decoded = b''
    if len(decoded) != 32 or not re.fullmatch(r'[A-Za-z0-9_-]{43}', public):
        raise ValueError('В ссылке отсутствует корректный публичный ключ pbk')
    short = q.get('sid', '')
    if not re.fullmatch(r'(?:[0-9a-fA-F]{2}){0,8}', short):
        raise ValueError('sid должен содержать 0–16 шестнадцатеричных символов, чётное число')
    if not q.get('sni'):
        raise ValueError('В ссылке отсутствует sni')
    sni = valid_host(q['sni'])
    reality = {'serverName': sni, 'fingerprint': q.get('fp') or 'chrome',
               'publicKey': public, 'shortId': short.lower()}
    if q.get('spx'):
        reality['spiderX'] = q['spx']
    outbound = {'tag': 'upstream', 'protocol': 'vless',
                'settings': {'address': host, 'port': port, 'id': user_id,
                             'encryption': 'none', 'flow': q.get('flow', '')},
                'streamSettings': {'network': 'tcp', 'security': 'reality',
                                   'realitySettings': reality}}
    return outbound


def client_link(host, port, user_id, public_key, short_id, sni, name):
    host = valid_host(host)
    if ':' in host:
        host = '[' + host + ']'
    query = urllib.parse.urlencode({'encryption': 'none', 'flow': 'xtls-rprx-vision',
        'type': 'tcp', 'headerType': 'none', 'security': 'reality', 'fp': 'chrome',
        'sni': sni, 'pbk': public_key, 'sid': short_id})
    return 'vless://' + user_id + '@' + host + ':' + str(port) + '?' + query + '#' + urllib.parse.quote(name, safe='')


def build_config(upstream, user_id, private_key, short_id, sni, port, socks_port, only_blocked=False):
    domains = [RULE]
    if not only_blocked:
        domains += ['ext:ru-blocked.dat:' + service for service in ('youtube', 'telegram', 'instagram', 'openai')]
    return {'log': {'loglevel': 'warning', 'access': '/var/log/xray/access.log', 'error': '/var/log/xray/error.log'},
        'inbounds': [
            {'tag': 'vless-reality-in', 'listen': '0.0.0.0', 'port': port, 'protocol': 'vless',
             'settings': {'decryption': 'none', 'clients': [{'id': user_id, 'flow': 'xtls-rprx-vision'}]},
             'streamSettings': {'network': 'tcp', 'security': 'reality', 'realitySettings': {
                 'show': False, 'target': sni + ':443', 'serverNames': [sni],
                 'privateKey': private_key, 'shortIds': [short_id]}},
             'sniffing': {'enabled': True, 'destOverride': ['http', 'tls']}},
            {'tag': 'socks-local', 'listen': '127.0.0.1', 'port': socks_port, 'protocol': 'socks',
             'settings': {'auth': 'noauth', 'udp': True},
             'sniffing': {'enabled': True, 'destOverride': ['http', 'tls']}}],
        'outbounds': [{'tag': 'direct', 'protocol': 'freedom'},
                      {'tag': 'block', 'protocol': 'blackhole'}, copy.deepcopy(upstream)],
        'routing': {'domainStrategy': 'IPIfNonMatch', 'rules': [
            {'type': 'field', 'ip': PRIVATE_IPS, 'outboundTag': 'block'},
            {'type': 'field', 'domain': domains, 'outboundTag': 'upstream'}]}}


def get_geodata():
    # Retry the pair too, in case the release changes between the two downloads.
    for _ in range(3):
        checksum = fetch(GEO_SOURCE + 'geosite.dat.sha256sum', 4096).decode().split()[0].lower()
        if not re.fullmatch(r'[a-f0-9]{64}', checksum):
            raise RuntimeError('Некорректная контрольная сумма геобазы')
        data = fetch(GEO_SOURCE + 'geosite.dat', 100 * 1024 * 1024)
        if len(data) >= 100000 and hashlib.sha256(data).hexdigest() == checksum:
            return data
    raise RuntimeError('SHA256 геобазы не совпадает; рабочие файлы не изменены')


def download_xray(version=None):
    arch = {'x86_64': '64', 'aarch64': 'arm64-v8a', 'arm64': 'arm64-v8a'}.get(platform.machine().lower())
    if not arch:
        raise RuntimeError('Поддерживаются x86_64 и ARM64')
    endpoint = 'https://api.github.com/repos/XTLS/Xray-core/releases/'
    if version:
        if not re.fullmatch(r'v?[0-9][0-9A-Za-z._-]*', version):
            raise ValueError('Некорректная версия Xray')
        endpoint += 'tags/' + (version if version.startswith('v') else 'v' + version)
    else:
        endpoint += 'latest'
    release = json.loads(fetch(endpoint, 4 * 1024 * 1024))
    asset_name = 'Xray-linux-' + arch + '.zip'
    asset = next((x for x in release['assets'] if x['name'] == asset_name), None)
    if not asset:
        raise RuntimeError('В релизе нет архива для этой архитектуры')
    url = asset['browser_download_url']
    if not url.startswith('https://github.com/XTLS/Xray-core/releases/download/'):
        raise RuntimeError('Неожиданный источник архива Xray')
    data = fetch(url, 160 * 1024 * 1024)
    digest = asset.get('digest') or ''
    if re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
        expected = digest.split(':', 1)[1]
    else:
        manifest = fetch(url + '.dgst', 65536).decode()
        match = re.search(r'(?im)^.*SHA2?-?256.*?=\s*([a-f0-9]{64})\s*$', manifest)
        if not match:
            raise RuntimeError('Не найдена SHA256 архива Xray')
        expected = match.group(1).lower()
    if hashlib.sha256(data).hexdigest() != expected:
        raise RuntimeError('SHA256 архива Xray не совпадает')
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        binary = archive.read('xray')
    if not binary.startswith(b'\x7fELF'):
        raise RuntimeError('В архиве нет ожидаемого ELF-файла Xray')
    return binary, release['tag_name']


def validate(config, gid):
    fd, name = tempfile.mkstemp(prefix='.check-', suffix='.json', dir=ETC)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(config, stream)
        os.chown(name, 0, gid)
        os.chmod(name, 0o640)
        result = run(['runuser', '-u', 'xray', '--', 'env', 'XRAY_LOCATION_ASSET=' + str(ASSETS),
                      BIN, 'run', '-test', '-config', name], check=False)
        if result.returncode:
            raise RuntimeError('Проверка конфига Xray не прошла. Приватные параметры не выводятся.')
    finally:
        os.unlink(name)


def socks_port():
    return next(i['port'] for i in json.loads(CONFIG.read_bytes())['inbounds'] if i['tag'] == 'socks-local')


def http_check(port, host):
    r = run(['curl', '-sS', '-o', '/dev/null', '-w', '%{http_code}', '--connect-timeout', '10',
             '--max-time', '20', '--socks5-hostname', '127.0.0.1:' + str(port), 'https://' + host + '/'], timeout=25)
    if not re.fullmatch(r'[1-5][0-9]{2}', r.stdout.strip()):
        raise RuntimeError('Нет HTTP-ответа от ' + host)
    return r.stdout.strip()


def healthy():
    run(['systemctl', 'is-active', '--quiet', 'xray'])
    port = socks_port()
    # Connection and forwarding checks, including the existing always-proxied service.
    for host in ('www.youtube.com', 'example.com'):
        say('Проверка ' + host + ': HTTP ' + http_check(port, host))


def loopback_test(config, public_key, user_id, short_id, sni):
    # Exercise the generated client settings through the real REALITY inbound.
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
    inbound = config['inbounds'][0]
    uri = client_link('127.0.0.1', inbound['port'], user_id, public_key, short_id, sni, 'self-test')
    out = parse_vless(uri)
    test = {'log': {'loglevel': 'none'}, 'inbounds': [{'listen': '127.0.0.1', 'port': port,
            'protocol': 'socks', 'settings': {'auth': 'noauth'}}], 'outbounds': [out]}
    with tempfile.TemporaryDirectory(prefix='xray-loopback-') as temp:
        path = Path(temp) / 'client.json'
        path.write_text(json.dumps(test))
        path.chmod(0o600)
        p = subprocess.Popen([str(BIN), 'run', '-config', str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            time.sleep(1)
            if p.poll() is not None:
                raise RuntimeError('Тестовый клиент Xray не запустился')
            say('Проверка готовой клиентской ссылки: HTTP ' + http_check(port, 'www.youtube.com'))
        finally:
            p.terminate()
            p.wait(timeout=5)


def update_geodata():
    import fcntl
    import pwd
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (STATE / 'update.lock').open('w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            say('Обновление уже запущено')
            return
        original = CONFIG.read_bytes()
        config = json.loads(original)
        if not any(RULE in rule.get('domain', []) for rule in config['routing']['rules']):
            raise RuntimeError('Правило ru-blocked отсутствует; обновление отменено')
        old = DB.read_bytes()
        new = get_geodata()
        if old == new:
            say('Геобаза не изменилась; перезапуск не нужен')
            return
        gid = pwd.getpwnam('xray').pw_gid
        fd, name = tempfile.mkstemp(prefix='ru-candidate-', suffix='.dat', dir=ASSETS)
        os.close(fd)
        candidate = Path(name)
        try:
            atomic(candidate, new)
            changed = copy.deepcopy(config)
            for rule in changed['routing']['rules']:
                if 'domain' in rule:
                    rule['domain'] = [d.replace('ext:ru-blocked.dat:', 'ext:' + candidate.name + ':') for d in rule['domain']]
            validate(changed, gid)
            healthy()
            if CONFIG.read_bytes() != original:
                raise RuntimeError('Конфиг изменился во время обновления; повторите позже')
            atomic(STATE / 'previous-geodata.dat', old, 0o600)
            atomic(DB, new)
            try:
                validate(config, gid)
                run(['systemctl', 'restart', 'xray'])
                time.sleep(1)
                healthy()
            except Exception:
                atomic(DB, old)
                run(['systemctl', 'restart', 'xray'])
                say('Предыдущая геобаза восстановлена после ошибки применения')
                raise
            say('Геобаза обновлена; Xray проверен')
        finally:
            candidate.unlink(missing_ok=True)


XRAY_UNIT = '''[Unit]
Description=Xray VLESS REALITY server
Wants=network-online.target
After=network-online.target nss-lookup.target

[Service]
User=xray
Group=xray
Environment=XRAY_LOCATION_ASSET=/usr/local/share/xray
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/xray
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LimitNOFILE=1048576
UMask=0027

[Install]
WantedBy=multi-user.target
'''
UPDATE_UNIT = '''[Unit]
Description=Update RuNet Freedom domain list with validation and rollback
Wants=network-online.target
After=network-online.target xray.service

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/local/lib/xray-setup/manager.py --update-geodata
TimeoutStartSec=15min
UMask=0077
'''
TIMER_UNIT = '''[Unit]
Description=Refresh Xray blocked-domain list every six hours

[Timer]
OnCalendar=*-*-* 00,06,12,18:15:00 UTC
RandomizedDelaySec=5min
Persistent=true
Unit=xray-geodata-update.service

[Install]
WantedBy=timers.target
'''


def free_port(port):
    with socket.socket() as sock:
        sock.bind(('0.0.0.0', port))


def check_cover(sni):
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_alpn_protocols(['h2', 'http/1.1'])
    with socket.create_connection((sni, 443), timeout=12) as sock:
        with ctx.wrap_socket(sock, server_hostname=sni) as tls:
            if tls.selected_alpn_protocol() != 'h2':
                raise RuntimeError('Домен маскировки не согласовал HTTP/2; выберите другой --sni')


def install(args):
    import pwd
    if platform.system() != 'Linux' or os.geteuid() != 0:
        raise RuntimeError('Запустите скрипт от root на Ubuntu/Debian с systemd')
    if not Path('/run/systemd/system').is_dir():
        raise RuntimeError('Нужен сервер с работающим systemd')
    managed = [BIN, CONFIG, DB, MANAGER, ETC / 'client.txt', Path('/etc/logrotate.d/xray'),
               Path('/etc/systemd/system/xray.service.d'), Path('/var/log/xray'),
               SYSTEMD / 'xray.service', SYSTEMD / 'xray-geodata-update.service',
               SYSTEMD / 'xray-geodata-update.timer']
    if any(p.exists() for p in managed) or run(['systemctl', 'cat', 'xray.service'], check=False).returncode == 0:
        raise RuntimeError('Найдена существующая установка Xray. Скрипт предназначен для чистого сервера.')
    try:
        pwd.getpwnam('xray')
        raise RuntimeError('Пользователь xray уже существует; нужна чистая установка')
    except KeyError:
        pass
    link = args.upstream_vless
    if not link:
        if args.non_interactive:
            raise ValueError('Укажите --upstream-vless')
        link = getpass.getpass('Вставьте vless:// ссылку второго сервера (ввод скрыт): ')
    upstream = parse_vless(link)
    detected = ''
    if not args.public_host:
        try:
            detected = valid_host(fetch('https://api.ipify.org', 128).decode().strip())
        except Exception:
            pass
    if args.non_interactive:
        if not args.public_host:
            raise ValueError('В автоматическом режиме укажите --public-host')
        host = valid_host(args.public_host)
        port = args.port or 443
        sni = args.sni or 'www.microsoft.com'
    else:
        host = valid_host(args.public_host or (input('Публичный IPv4/домен сервера [' + detected + ']: ').strip() or detected))
        port = args.port or int(input('Порт VLESS [443]: ').strip() or '443')
        sni = args.sni or (input('Домен маскировки REALITY [www.microsoft.com]: ').strip() or 'www.microsoft.com')
    sni = valid_host(sni)
    try:
        ipaddress.ip_address(sni)
    except ValueError:
        pass
    else:
        raise ValueError('Для SNI нужен домен, а не IP')
    try:
        public_address = ipaddress.ip_address(host)
    except ValueError:
        public_address = None
    if public_address is not None and public_address.version == 6:
        raise ValueError('Этот установщик создаёт IPv4-вход. Укажите публичный IPv4 или его домен.')
    if not 1 <= port <= 65535 or not 1 <= args.socks_port <= 65535 or port == args.socks_port:
        raise ValueError('Порты должны быть разными и находиться в диапазоне 1–65535')
    if host == upstream['settings']['address'] and port == upstream['settings']['port']:
        raise ValueError('Upstream указывает на создаваемый вход; получится петля')
    free_port(port)
    free_port(args.socks_port)
    say('Проверка домена маскировки: ' + sni)
    check_cover(sni)
    say('Загрузка официального Xray и проверка SHA256…')
    binary, version = download_xray(args.version)
    say('Загрузка геобазы RuNet Freedom и проверка SHA256…')
    geodata = get_geodata()
    created = []
    firewall = None
    created_user = False
    logs_created = False
    try:
        run(['useradd', '--system', '--user-group', '--no-create-home', '--home-dir', '/nonexistent',
             '--shell', '/usr/sbin/nologin', 'xray'])
        created_user = True
        account = pwd.getpwnam('xray')
        ETC.mkdir(parents=True, exist_ok=True)
        os.chown(ETC, 0, account.pw_gid)
        ETC.chmod(0o750)
        ASSETS.mkdir(parents=True, exist_ok=True)
        ASSETS.chmod(0o755)
        STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
        logs = Path('/var/log/xray')
        logs.mkdir(exist_ok=True)
        logs_created = True
        os.chown(logs, account.pw_uid, account.pw_gid)
        logs.chmod(0o750)
        def put(path, data, mode=0o644, gid=None):
            if Path(path).exists():
                raise RuntimeError('Отказ от перезаписи файла: ' + str(path))
            atomic(path, data, mode, gid)
            created.append(Path(path))
        put(BIN, binary, 0o755)
        put(DB, geodata)
        keys = run([BIN, 'x25519']).stdout
        fields = {k.strip().lower().replace(' ', ''): v.strip() for k, sep, v in
                  (line.partition(':') for line in keys.splitlines()) if sep}
        private = fields.get('privatekey')
        public = fields.get('password(publickey)') or fields.get('publickey') or fields.get('password')
        if not private or not public:
            raise RuntimeError('Не удалось разобрать вывод xray x25519')
        user_id = str(uuid.uuid4())
        short_id = secrets.token_hex(8)
        config = build_config(upstream, user_id, private, short_id, sni, port, args.socks_port, args.only_blocked)
        put(CONFIG, json.dumps(config, ensure_ascii=False, indent=2) + '\n', 0o640, account.pw_gid)
        validate(config, account.pw_gid)
        put(MANAGER, Path(__file__).read_bytes(), 0o700)
        put(SYSTEMD / 'xray.service', XRAY_UNIT)
        put(SYSTEMD / 'xray-geodata-update.service', UPDATE_UNIT)
        put(SYSTEMD / 'xray-geodata-update.timer', TIMER_UNIT)
        for name in ('xray.service', 'xray-geodata-update.service', 'xray-geodata-update.timer'):
            run(['systemd-analyze', 'verify', SYSTEMD / name])
        if not args.no_firewall and shutil.which('ufw'):
            status = run(['ufw', 'status'], env={**os.environ, 'LC_ALL': 'C'}).stdout
            if re.search(r'^Status: active', status, re.M):
                # Add/remove a uniquely commented rule, without changing the firewall policy.
                existing = run(['ufw', 'show', 'added']).stdout
                spec = 'allow ' + str(port) + '/tcp'
                pattern = r'^ufw allow ' + str(port) + r'(?:/tcp)?(?:\s|$)'
                if not any(re.match(pattern, line.strip()) for line in existing.splitlines()):
                    run(['ufw', 'allow', str(port) + '/tcp', 'comment', 'VLESS-REALITY-setup'])
                    firewall = ('ufw', port, False)
        if not args.no_firewall and not firewall and shutil.which('firewall-cmd'):
            if run(['firewall-cmd', '--state'], check=False).returncode == 0:
                value = str(port) + '/tcp'
                if run(['firewall-cmd', '--query-port=' + value], check=False).returncode != 0:
                    run(['firewall-cmd', '--add-port=' + value])
                    had_permanent = run(['firewall-cmd', '--permanent', '--query-port=' + value], check=False).returncode == 0
                    firewall = ('firewalld', port, had_permanent)
                    if not had_permanent:
                        run(['firewall-cmd', '--permanent', '--add-port=' + value])
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'start', 'xray'])
        time.sleep(1)
        healthy()
        loopback_test(config, public, user_id, short_id, sni)
        uri = client_link(host, port, user_id, public, short_id, sni, args.name)
        put(ETC / 'client.txt', uri + '\n', 0o600)
        put(Path('/etc/logrotate.d/xray'), '''/var/log/xray/*.log {
    daily
    rotate 7
    maxsize 20M
    missingok
    notifempty
    copytruncate
    compress
}
''')
        run(['systemctl', 'enable', 'xray'])
        run(['systemctl', 'enable', '--now', 'xray-geodata-update.timer'])
        say('\nГотово. Xray ' + version + ', VLESS + REALITY + Vision, TCP ' + str(port))
        say('Заблокированные домены → upstream; остальное → напрямую.')
        say('Геобаза обновляется каждые 6 часов; изменённая база применяется с коротким перезапуском.')
        say('Готовая строка подключения (также сохранена в /usr/local/etc/xray/client.txt):\n\n' + uri)
        say('\nВ firewall панели хостинга должен быть разрешён входящий TCP ' + str(port) + '.')
        say('Проверены локальный REALITY-вход и цепочка; внешнюю доступность проверьте клиентом.')
    except BaseException:
        for unit in ('xray-geodata-update.timer', 'xray-geodata-update.service', 'xray.service'):
            run(['systemctl', 'disable', '--now', unit], check=False)
        if firewall:
            kind, number, had_permanent = firewall
            if kind == 'ufw':
                run(['ufw', '--force', 'delete', 'allow', str(number) + '/tcp', 'comment', 'VLESS-REALITY-setup'], check=False)
            else:
                run(['firewall-cmd', '--remove-port=' + str(number) + '/tcp'], check=False)
                if not had_permanent:
                    run(['firewall-cmd', '--permanent', '--remove-port=' + str(number) + '/tcp'], check=False)
        for path in reversed(created):
            path.unlink(missing_ok=True)
        run(['systemctl', 'daemon-reload'], check=False)
        if logs_created:
            archived = STATE / ('failed-logs-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
            shutil.move(str(logs), str(archived))
        if created_user:
            run(['userdel', 'xray'], check=False)
        say('Установка не завершена; созданные службы и конфиги удалены. Системные пакеты и журналы сохранены.')
        raise


def main():
    parser = argparse.ArgumentParser(description='Чистая установка VLESS REALITY и цепочки по геосписку (Ubuntu/Debian)')
    parser.add_argument('--upstream-vless', help='VLESS REALITY TCP-ссылка второго сервера; без параметра запрашивается скрыто')
    parser.add_argument('--public-host', help='Публичный IPv4 или домен нового сервера')
    parser.add_argument('--port', type=int, help='Порт входа, по умолчанию 443')
    parser.add_argument('--socks-port', type=int, default=1080, help='Локальный SOCKS, по умолчанию 1080')
    parser.add_argument('--sni', help='Домен маскировки, по умолчанию www.microsoft.com')
    parser.add_argument('--name', default='MyVLESS_Reality', help='Имя профиля в готовой ссылке')
    parser.add_argument('--version', help='Версия Xray, например v26.3.27; по умолчанию latest stable')
    parser.add_argument('--non-interactive', action='store_true', help='Не задавать вопросов; нужны --public-host и --upstream-vless')
    parser.add_argument('--only-blocked', action='store_true', help='Только ru-blocked, без дополнительных категорий youtube/telegram/instagram/openai')
    parser.add_argument('--no-firewall', action='store_true', help='Не добавлять правила UFW/firewalld')
    parser.add_argument('--update-geodata', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.update_geodata:
        if platform.system() != 'Linux' or os.geteuid() != 0:
            raise RuntimeError('Для обновления нужен root на Linux')
        update_geodata()
    else:
        install(args)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        say('\nПрервано пользователем')
        sys.exit(130)
    except Exception as error:
        say('Ошибка: ' + str(error))
        sys.exit(1)
