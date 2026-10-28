"""Executed on a Linux server only after a user confirms a write operation.
inspect_remote() is a separate, read-only entry point.
"""
import base64
import contextlib
import datetime
import fcntl
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import subprocess
import tempfile
import time
import traceback
import types
import urllib.request
import uuid

BACKUPS = Path('/var/backups/vless-manager')
GEO = 'https://raw.githubusercontent.com/runetfreedom/russia-blocked-geosite/release/'

def sha(data): return hashlib.sha256(data).hexdigest()

def command(args, timeout=40, check=True):
    r = subprocess.run([str(a) for a in args], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode:
        raise RuntimeError(str(args[0]) + ': ' + (r.stderr or r.stdout)[-1800:])
    return r

def paths(request):
    config = Path(request.get('config_path', '/usr/local/etc/xray/config.json'))
    binary = Path(request.get('binary_path', '/usr/local/bin/xray'))
    assets = Path(request.get('assets_path', '/usr/local/share/xray'))
    service = request.get('service', 'xray')
    for p in (config, binary, assets):
        if not p.is_absolute() or '..' in p.parts or '\n' in str(p): raise ValueError('Нужен абсолютный путь без ..')
    if not re.fullmatch(r'[A-Za-z0-9_.@-]+', service): raise ValueError('Некорректное имя службы')
    return config, binary, assets, service

def inspect_remote(request):
    config, binary, assets, service = paths(request)
    result = {'hostname': socket.gethostname(), 'uid': os.geteuid(), 'config_path': str(config), 'installed': config.is_file(), 'config': None, 'config_sha': None, 'state_sha': None, 'backups': []}
    if config.is_file():
        data = config.read_bytes()
        result.update(config=json.loads(data), config_sha=sha(data))
    state = config.parent / 'manual-exceptions.json'
    if state.is_file(): result['state_sha'] = sha(state.read_bytes())
    for name, args in {
        'version': [binary, 'version'],
        'service': ['systemctl', 'show', service, '-p', 'ActiveState', '-p', 'SubState', '-p', 'MainPID', '-p', 'User', '-p', 'ExecMainStartTimestamp', '-p', 'NRestarts', '-p', 'ExecStart'],
        'network': ['sysctl', 'net.ipv4.tcp_congestion_control', 'net.core.default_qdisc', 'net.ipv4.tcp_max_orphans'],
        'sockets': ['ss', '-s'],
        'logs': ['journalctl', '-u', service, '-n', '70', '--no-pager', '-o', 'short-iso'],
    }.items():
        try: result[name] = command(args, check=False).stdout[-22000:]
        except (OSError, subprocess.TimeoutExpired) as e: result[name] = str(e)
    if BACKUPS.is_dir():
        for p in sorted(BACKUPS.glob('*/metadata.json'), reverse=True)[:50]:
            try:
                meta = json.loads(p.read_bytes())
                if meta.get('config_path') == str(config) and meta.get('service') == service:
                    result['backups'].append({'id': p.parent.name, 'time': meta.get('time'), 'reason': meta.get('reason')})
            except (OSError, ValueError): pass
    result['geo_present'] = (assets / 'ru-blocked.dat').is_file()
    return result

def atomic(path, data, mode=0o600, uid=0, gid=0):
    path = Path(path)
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        os.chmod(name, mode); os.chown(name, uid, gid)
        os.replace(name, path)
    finally:
        if os.path.exists(name): os.unlink(name)

def config_service_check(config, binary, service):
    raw = command(['systemctl', 'show', service, '-p', 'ExecStart', '--value']).stdout
    if '-confdir' in raw or '-confdir=' in raw:
        raise RuntimeError('Служба использует confdir. Автоматическое изменение такой установки не поддерживается.')
    if str(config) not in raw or str(binary) not in raw:
        raise RuntimeError('Пути конфига/бинарника не совпадают с ExecStart службы. Проверьте поля подключения.')

def validate(config, binary, assets, service, candidate):
    fd, name = tempfile.mkstemp(prefix='.vless-manager-check-', suffix='.json', dir=config.parent)
    try:
        with os.fdopen(fd, 'wb') as f: f.write(candidate)
        user = command(['systemctl', 'show', service, '-p', 'User', '--value']).stdout.strip() or 'root'
        args = ['env', 'XRAY_LOCATION_ASSET=' + str(assets), binary, 'run', '-test', '-config', name]
        if user != 'root':
            account = pwd.getpwnam(user)
            os.chown(name, 0, account.pw_gid); os.chmod(name, 0o640)
            args = ['runuser', '-u', user, '--'] + args
        r = command(args, check=False)
        if r.returncode: raise RuntimeError('Xray отклонил конфиг:\n' + (r.stdout + r.stderr)[-2200:])
    finally: Path(name).unlink(missing_ok=True)

def state_from_config(config):
    entries = []
    for r in config.get('routing', {}).get('rules', []):
        if not str(r.get('ruleTag', '')).startswith('xray-manual-'): continue
        for kind in ('domain', 'ip'):
            for value in r.get(kind, []):
                tag = r.get('outboundTag')
                entries.append({'kind': kind, 'value': value, 'route': 'direct' if tag == 'direct' else 'block' if tag == 'block' else 'proxy'})
    return {'version': 1, 'entries': entries}

def checks(config, service, urls):
    command(['systemctl', 'is-active', '--quiet', service])
    # Check that configured TCP listening ports actually appeared after startup.
    listeners = command(['ss', '-H', '-lnt']).stdout
    ports = set(re.findall(r':(\d+)\s', listeners))
    needed = [str(i['port']) for i in config.get('inbounds', []) if isinstance(i.get('port'), int) and i.get('protocol') in ('vless', 'socks')]
    for p in needed:
        if p not in ports: raise RuntimeError('После запуска не появился TCP-порт ' + p)
    results = []
    if urls:
        inbound = next((i for i in config.get('inbounds', []) if i.get('protocol') == 'socks' and i.get('listen') in ('127.0.0.1', '::1') and i.get('settings', {}).get('auth', 'noauth') == 'noauth'), None)
        if not inbound: raise RuntimeError('Для HTTP-проверки нужен локальный SOCKS без пароля; снимите HTTP-проверку или добавьте такой вход.')
        endpoint = ('[::1]' if inbound['listen'] == '::1' else '127.0.0.1') + ':' + str(inbound['port'])
        for url in urls:
            if not re.fullmatch(r'https://[^\s]+', url): raise ValueError('Проверка поддерживает только HTTPS URL')
            r = command(['curl', '-sS', '-L', '-o', '/dev/null', '-w', '%{http_code}', '--connect-timeout', '8', '--max-time', '15', '--socks5-hostname', endpoint, url], timeout=20, check=False)
            code = r.stdout.strip()
            results.append({'url': url, 'http': code, 'exit': r.returncode})
            print('HTTP-проверка:', url, code, flush=True)
            if r.returncode or not re.fullmatch(r'[23]\d\d', code):
                raise RuntimeError('HTTP-проверка не прошла: ' + url + ' (HTTP ' + code + ')')
    return results

def fetch_geo():
    def fetch(name, limit):
        req = urllib.request.Request(GEO + name, headers={'User-Agent': 'VLESS-Manager/1.0'})
        with urllib.request.urlopen(req, timeout=60) as r: data = r.read(limit + 1)
        if len(data) > limit: raise RuntimeError('Слишком большой файл геобазы')
        return data
    for _ in range(3):
        expected = fetch('geosite.dat.sha256sum', 4096).decode().split()[0].lower()
        if not re.fullmatch(r'[0-9a-f]{64}', expected): raise RuntimeError('Некорректная SHA256 геобазы')
        data = fetch('geosite.dat', 120 * 1024 * 1024)
        if len(data) > 100000 and sha(data) == expected: return data
    raise RuntimeError('SHA256 геобазы не совпадает')

@contextlib.contextmanager
def locks():
    files = []
    try:
        for p in [Path('/run/lock/vless-manager.lock'), Path('/var/lib/xray-ru-blocked/update.lock'), Path('/var/lib/xray-setup/update.lock')]:
            p.parent.mkdir(parents=True, exist_ok=True)
            f = p.open('a'); files.append(f)
            try: fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError: raise RuntimeError('Другой процесс меняет Xray или геобазу. Повторите позже.')
        yield
    finally:
        for f in reversed(files): f.close()

def create_backup(config, service, state, geo, reason):
    BACKUPS.mkdir(mode=0o700, parents=True, exist_ok=True)
    ident = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8]
    folder = BACKUPS / ident; folder.mkdir(mode=0o700)
    targets = [('config', config), ('state', state)] + ([('geo', geo)] if geo else [])
    meta = {'config_path': str(config), 'service': service, 'reason': reason, 'time': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'files': {}}
    for name, p in targets:
        if p.is_file():
            st = p.stat(); shutil.copyfile(p, folder / name); (folder / name).chmod(0o600)
            meta['files'][name] = {'path': str(p), 'exists': True, 'mode': st.st_mode & 0o777, 'uid': st.st_uid, 'gid': st.st_gid}
        else: meta['files'][name] = {'path': str(p), 'exists': False}
    atomic(folder / 'metadata.json', json.dumps(meta).encode())
    return folder, meta

def restore_files(folder, meta):
    for name in ('geo', 'state', 'config'):
        info = meta['files'].get(name)
        if not info: continue
        path = Path(info['path'])
        if info['exists']: atomic(path, (folder / name).read_bytes(), info['mode'], info['uid'], info['gid'])
        else: path.unlink(missing_ok=True)

def apply(request):
    config, binary, assets, service = paths(request)
    config_service_check(config, binary, service)
    with locks():
        original = config.read_bytes()
        if sha(original) != request.get('expected_sha'): raise RuntimeError('Конфиг изменился после чтения. Загрузите его заново и повторите просмотр различий.')
        state = config.parent / 'manual-exceptions.json'
        state_sha = sha(state.read_bytes()) if state.is_file() else None
        if state_sha != request.get('state_sha'): raise RuntimeError('Список исключений изменился после чтения. Загрузите сервер заново.')
        candidate = request['config']
        encoded = (json.dumps(candidate, ensure_ascii=False, indent=2) + '\n').encode()
        use_geo = request.get('update_geo', False) or any('ext:ru-blocked.dat:' in d for r in candidate.get('routing', {}).get('rules', []) for d in r.get('domain', [])) and not (assets / 'ru-blocked.dat').is_file()
        new_geo = fetch_geo() if use_geo else None
        if new_geo is not None and (assets / 'ru-blocked.dat').is_file() and new_geo == (assets / 'ru-blocked.dat').read_bytes(): new_geo = None
        geo = assets / 'ru-blocked.dat' if new_geo is not None else None
        old_service = command(['systemctl', 'is-active', '--quiet', service], check=False).returncode == 0
        if json.loads(original) == candidate and new_geo is None: return {'ok': True, 'message': 'Изменений нет; перезапуск не выполнялся.'}
        folder, meta = create_backup(config, service, state, geo, request.get('reason', 'Изменение конфига'))
        print('Резервная копия:', folder.name, flush=True)
        config_changed = False
        geo_changed = False
        try:
            if new_geo is not None:
                assets.mkdir(parents=True, exist_ok=True); atomic(geo, new_geo, 0o644); geo_changed = True
            validate(config, binary, assets, service, encoded)
            # Recheck after slow downloads and validation.
            if config.read_bytes() != original: raise RuntimeError('Конфиг параллельно изменён; применение отменено')
            info = meta['files']['config']
            config_changed = True
            atomic(state, (json.dumps(state_from_config(candidate), ensure_ascii=False, indent=2) + '\n').encode())
            atomic(config, encoded, info['mode'], info['uid'], info['gid'])
            command(['systemctl', 'restart', service])
            time.sleep(2)
            results = checks(candidate, service, request.get('check_urls', []))
            return {'ok': True, 'backup': folder.name, 'message': 'Конфиг применён. Служба и порты проверены.' + (' HTTP-проверки пройдены.' if results else ' Внешний доступ не проверялся.'), 'checks': results}
        except BaseException:
            if config_changed:
                restore_files(folder, meta)
                command(['systemctl', 'restart' if old_service else 'stop', service])
                print('ОТКАТ: прежние конфиг, исключения и геобаза восстановлены.', flush=True)
            elif geo_changed:
                geo_meta = {'files': {'geo': meta['files']['geo']}}
                restore_files(folder, geo_meta)
            raise

def restore(request):
    ident = request.get('backup_id', '')
    if not re.fullmatch(r'\d{8}T\d{6}Z-[0-9a-f]{8}', ident): raise ValueError('Некорректный идентификатор копии')
    config, binary, assets, service = paths(request)
    config_service_check(config, binary, service)
    with locks():
        if sha(config.read_bytes()) != request.get('expected_sha'): raise RuntimeError('Конфиг изменился. Обновите сведения о сервере.')
        folder = BACKUPS / ident; meta = json.loads((folder / 'metadata.json').read_bytes())
        if meta['config_path'] != str(config) or meta['service'] != service: raise RuntimeError('Копия относится к другой установке')
        # Backups are root-only and paths must still match the selected installation.
        allowed = {'config': str(config), 'state': str(config.parent / 'manual-exceptions.json'), 'geo': str(assets / 'ru-blocked.dat')}
        if any(v['path'] != allowed.get(k) for k,v in meta['files'].items()): raise RuntimeError('В копии неожиданные пути')
        state = config.parent / 'manual-exceptions.json'
        save, save_meta = create_backup(config, service, state, assets / 'ru-blocked.dat' if 'geo' in meta['files'] else None, 'Перед восстановлением ' + ident)
        try:
            restore_files(folder, meta)
            validate(config, binary, assets, service, config.read_bytes())
            command(['systemctl', 'restart', service]); time.sleep(2)
            checks(json.loads(config.read_bytes()), service, request.get('check_urls', []))
            return {'ok': True, 'backup': save.name, 'message': 'Резервная копия восстановлена.'}
        except BaseException:
            restore_files(save, save_meta); command(['systemctl', 'restart', service])
            raise

def install(request, job):
    # Reuse the bundled installers: refuse all existing installations, verify downloads,
    # generate credentials, test REALITY inbound and forwarding, and undo own files on failure.
    script = job / ('install_entry.py' if request['role'] == 'entry' else 'install_exit.py')
    spec = importlib.util.spec_from_file_location('vless_fresh_installer', script)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    options = dict(request['options'])
    options.update(non_interactive=True, update_geodata=False)
    defaults = {'public_host': None, 'port': 443, 'socks_port': 1080, 'sni': 'www.microsoft.com', 'name': 'VLESS Reality', 'version': None, 'no_firewall': False, 'upstream_vless': None, 'only_blocked': False, 'allow_from': None}
    defaults.update(options)
    import transport_install
    cleanup,success=transport_install.configure(module,defaults)
    with Path('/run/lock/xray-setup-install.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            (module.install if request['role'] == 'entry' else module.install_exit)(types.SimpleNamespace(**defaults))
            success()
        except BaseException:
            cleanup();raise
    return {'ok': True, 'message': 'Установка завершена.', 'client_uri': Path('/usr/local/etc/xray/client.txt').read_text().strip()}

def main(job_path):
    job = Path(job_path)
    request = json.loads((job / 'request.json').read_bytes())
    try:
        if os.geteuid() != 0: raise RuntimeError('Для изменений подключитесь как root')
        action = request['action']
        if action == 'install': result = install(request, job)
        elif action == 'apply': result = apply(request)
        elif action == 'restore': result = restore(request)
        elif action in ('start', 'stop', 'restart'):
            config, binary, assets, service = paths(request)
            config_service_check(config, binary, service)
            with locks(): command(['systemctl', action, service])
            result = {'ok': True, 'message': 'Команда службе выполнена: ' + action}
        else: raise ValueError('Неизвестная операция')
    except BaseException as e:
        print('Ошибка:', str(e), flush=True)
        result = {'ok': False, 'message': str(e)}
    atomic(job / 'result.json', json.dumps(result, ensure_ascii=False).encode())
    # Do not retain upstream URI / submitted private configuration in a job request.
    (job / 'request.json').unlink(missing_ok=True)
    print('Задание завершено.', flush=True)
