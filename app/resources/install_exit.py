#!/usr/bin/env python3
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

BIN=Path('/usr/local/bin/xray')
ETC=Path('/usr/local/etc/xray')
CONFIG=ETC/'config.json'
ASSETS=Path('/usr/local/share/xray')
SYSTEMD=Path('/etc/systemd/system')
STATE=Path('/var/lib/xray-exit-setup')
PRIVATE_IPS=['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4', '240.0.0.0/4', '::/128', '::1/128', 'fc00::/7', 'fe80::/10', 'ff00::/8']

def parse_allow_from(value):
    networks = []
    for item in (value or '').split(','):
        if not item.strip():
            continue
        network = ipaddress.ip_network(item.strip(), strict=False)
        if network.version != 4:
            raise ValueError('Вход IPv4: --allow-from должен содержать IPv4 или IPv4 CIDR')
        if network.prefixlen == 0:
            raise ValueError('Для доступа с любого IP оставьте --allow-from пустым')
        if str(network) not in networks:
            networks.append(str(network))
    return networks


def build_exit_config(user_id, private_key, short_id, sni, port, socks_port, allowed):
    rules = [{'type': 'field', 'ip': PRIVATE_IPS, 'outboundTag': 'block'}]
    if allowed:
        rules += [
            {'type': 'field', 'inboundTag': ['socks-local'], 'outboundTag': 'direct'},
            {'type': 'field', 'inboundTag': ['vless-reality-in'],
             'sourceIP': ['127.0.0.1/32'] + list(allowed), 'outboundTag': 'direct'},
            {'type': 'field', 'inboundTag': ['vless-reality-in'], 'outboundTag': 'block'}]
    return {'log': {'loglevel': 'warning', 'access': '/var/log/xray/access.log',
                    'error': '/var/log/xray/error.log'},
        'inbounds': [
            {'tag': 'vless-reality-in', 'listen': '0.0.0.0', 'port': port, 'protocol': 'vless',
             'settings': {'decryption': 'none', 'clients': [{'id': user_id, 'flow': 'xtls-rprx-vision'}]},
             'streamSettings': {'network': 'tcp', 'security': 'reality', 'realitySettings': {
                 'show': False, 'target': sni + ':443', 'serverNames': [sni],
                 'privateKey': private_key, 'shortIds': [short_id]}},
             'sniffing': {'enabled': True, 'destOverride': ['http', 'tls']}},
            {'tag': 'socks-local', 'listen': '127.0.0.1', 'port': socks_port, 'protocol': 'socks',
             'settings': {'auth': 'noauth', 'udp': True}}],
        'outbounds': [{'tag': 'direct', 'protocol': 'freedom'}, {'tag': 'block', 'protocol': 'blackhole'}],
        'routing': {'domainStrategy': 'IPIfNonMatch', 'rules': rules}}


def existing_ufw_allow(status, port, source):
    for line in status.splitlines():
        match = re.match(r'^\s*(\d+)(?:/tcp)?\s+ALLOW(?: IN)?\s+(\S+)', line)
        if not match or int(match.group(1)) != port or '(v6)' in line:
            continue
        existing = match.group(2)
        if existing == 'Anywhere':
            return True
        if source:
            try:
                if ipaddress.ip_network(source).subnet_of(ipaddress.ip_network(existing, strict=False)):
                    return True
            except ValueError:
                pass
    return False


def configure_exit_firewall(port, allowed, undo):
    sources = list(allowed) or [None]
    if shutil.which('ufw'):
        status = run(['ufw', 'status'], env={**os.environ, 'LC_ALL': 'C'}).stdout
        if re.search(r'^Status: active', status, re.M):
            for source in sources:
                if existing_ufw_allow(status, port, source):
                    continue
                spec = (['proto', 'tcp', 'from', source, 'to', 'any', 'port', str(port)]
                        if source else [str(port) + '/tcp'])
                run(['ufw', 'allow'] + spec + ['comment', 'VLESS-REALITY-exit'])
                undo.append(['ufw', '--force', 'delete', 'allow'] + spec + ['comment', 'VLESS-REALITY-exit'])
            return
    if shutil.which('firewall-cmd') and run(['firewall-cmd', '--state'], check=False).returncode == 0:
        for source in sources:
            if source:
                value = 'rule family="ipv4" source address="' + source + '" port port="' + str(port) + '" protocol="tcp" accept'
                query, add, remove = '--query-rich-rule=', '--add-rich-rule=', '--remove-rich-rule='
            else:
                value = str(port) + '/tcp'
                query, add, remove = '--query-port=', '--add-port=', '--remove-port='
            for permanent in (False, True):
                prefix = ['firewall-cmd'] + (['--permanent'] if permanent else [])
                if run(prefix + [query + value], check=False).returncode != 0:
                    run(prefix + [add + value])
                    undo.append(prefix + [remove + value])


def install_exit(args):
    import pwd
    if platform.system() != 'Linux' or os.geteuid() != 0 or not Path('/run/systemd/system').is_dir():
        raise RuntimeError('Нужен root на Debian/Ubuntu с работающим systemd')
    managed = [BIN, CONFIG, ETC / 'client.txt', SYSTEMD / 'xray.service',
               Path('/etc/systemd/system/xray.service.d'), Path('/etc/logrotate.d/xray'), Path('/var/log/xray')]
    if any(path.exists() for path in managed) or run(['systemctl', 'cat', 'xray.service'], check=False).returncode == 0:
        raise RuntimeError('Найдена существующая установка Xray; нужна чистая установка')
    try:
        pwd.getpwnam('xray')
    except KeyError:
        pass
    else:
        raise RuntimeError('Пользователь xray уже существует; нужна чистая установка')
    detected = ''
    if not args.public_host and not args.non_interactive:
        try:
            detected = valid_host(fetch('https://api.ipify.org', 128).decode().strip())
        except Exception:
            pass
    if args.non_interactive:
        if not args.public_host:
            raise ValueError('В автоматическом режиме нужен --public-host')
        host, port, sni = valid_host(args.public_host), args.port or 443, args.sni or 'www.microsoft.com'
        allowed = parse_allow_from(args.allow_from)
    else:
        host = valid_host(args.public_host or (input('Публичный IPv4/домен выходного сервера [' + detected + ']: ').strip() or detected))
        port = args.port or int(input('Порт VLESS REALITY [443]: ').strip() or '443')
        sni = args.sni or (input('Домен маскировки [www.microsoft.com]: ').strip() or 'www.microsoft.com')
        value = args.allow_from
        if value is None:
            value = input('Разрешённые IP/CIDR первых серверов через запятую [пусто = любой IP с верными ключами]: ').strip()
        allowed = parse_allow_from(value)
    sni = valid_host(sni)
    try:
        ipaddress.ip_address(sni)
    except ValueError:
        pass
    else:
        raise ValueError('SNI должен быть доменом')
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address and address.version != 4:
        raise ValueError('Нужен публичный IPv4 или домен с A-записью')
    if not (1 <= port <= 65535 and 1 <= args.socks_port <= 65535) or port == args.socks_port:
        raise ValueError('Нужны два разных порта в диапазоне 1–65535')
    free_port(port)
    free_port(args.socks_port)
    say('Проверка домена маскировки ' + sni + '…')
    check_cover(sni)
    say('Загрузка официального Xray и проверка SHA256…')
    binary, version = download_xray(args.version)
    created, firewall_undo = [], []
    created_user = False
    logs_created = False
    try:
        run(['useradd', '--system', '--user-group', '--no-create-home', '--home-dir', '/nonexistent',
             '--shell', '/usr/sbin/nologin', 'xray'])
        created_user = True
        account = pwd.getpwnam('xray')
        ETC.mkdir(parents=True, exist_ok=True)
        ETC.chmod(0o750)
        os.chown(ETC, 0, account.pw_gid)
        ASSETS.mkdir(parents=True, exist_ok=True)
        ASSETS.chmod(0o755)
        STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
        logs = Path('/var/log/xray')
        logs.mkdir()
        logs_created = True
        os.chown(logs, account.pw_uid, account.pw_gid)
        logs.chmod(0o750)
        def put(path, data, mode=0o644, gid=None):
            if path.exists():
                raise RuntimeError('Отказ от перезаписи файла: ' + str(path))
            atomic(path, data, mode, gid)
            created.append(path)
        put(BIN, binary, 0o755)
        fields = {k.strip().lower().replace(' ', ''): v.strip() for k, sep, v in
                  (line.partition(':') for line in run([BIN, 'x25519']).stdout.splitlines()) if sep}
        private = fields.get('privatekey')
        public = fields.get('password(publickey)') or fields.get('publickey') or fields.get('password')
        if not private or not public:
            raise RuntimeError('Не удалось прочитать ключи X25519')
        user_id, short_id = str(uuid.uuid4()), secrets.token_hex(8)
        config = build_exit_config(user_id, private, short_id, sni, port, args.socks_port, allowed)
        put(CONFIG, json.dumps(config, ensure_ascii=False, indent=2) + '\n', 0o640, account.pw_gid)
        validate(config, account.pw_gid)
        put(SYSTEMD / 'xray.service', XRAY_UNIT)
        run(['systemd-analyze', 'verify', SYSTEMD / 'xray.service'])
        if not args.no_firewall:
            configure_exit_firewall(port, allowed, firewall_undo)
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
        say('\nГотово: выходной сервер Xray ' + version + ', VLESS REALITY Vision, TCP ' + str(port))
        say('Принятый трафик выходит в Интернет напрямую; локальные и частные адреса блокируются.')
        if allowed:
            say('Пересылка разрешена только с: ' + ', '.join(allowed) + ' (и локальный тест с 127.0.0.1).')
        say('\nВставьте эту строку в install-vless.sh на первом сервере:\n\n' + uri)
        say('\nСтрока сохранена в /usr/local/etc/xray/client.txt (доступна только root).')
        say('В панели хостинга откройте TCP ' + str(port) + ' для нужных IP.')
        say('Внешнюю доступность проверьте установкой/подключением первого сервера.')
    except BaseException:
        run(['systemctl', 'disable', '--now', 'xray.service'], check=False)
        for command in reversed(firewall_undo):
            run(command, check=False)
        for path in reversed(created):
            path.unlink(missing_ok=True)
        run(['systemctl', 'daemon-reload'], check=False)
        if logs_created:
            archived = STATE / ('failed-logs-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
            shutil.move(str(logs), str(archived))
        if created_user:
            run(['userdel', 'xray'], check=False)
        say('Установка отменена; созданные службы, файлы и добавленные правила удалены. Пакеты и журналы сохранены.')
        raise


def main():
    parser = argparse.ArgumentParser(description='Чистая установка выходного VLESS REALITY сервера для цепочки')
    parser.add_argument('--public-host', help='Публичный IPv4 или домен выходного сервера')
    parser.add_argument('--port', type=int, help='Порт REALITY, по умолчанию 443')
    parser.add_argument('--socks-port', type=int, default=1080, help='Локальный SOCKS-порт, по умолчанию 1080')
    parser.add_argument('--sni', help='Домен маскировки, по умолчанию www.microsoft.com')
    parser.add_argument('--allow-from', help='Разрешённые IPv4/CIDR первых серверов через запятую; пусто = любой IP с верными ключами')
    parser.add_argument('--name', default='VLESS_Exit_Reality', help='Имя профиля в готовой ссылке')
    parser.add_argument('--version', help='Закрепить официальный релиз Xray вместо latest stable')
    parser.add_argument('--non-interactive', action='store_true', help='Не задавать вопросов; обязателен --public-host')
    parser.add_argument('--no-firewall', action='store_true', help='Не добавлять правила UFW/firewalld; whitelist в Xray сохраняется')
    install_exit(parser.parse_args())


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        say('\nПрервано пользователем')
        sys.exit(130)
    except Exception as error:
        say('Ошибка: ' + str(error))
        sys.exit(1)
