import base64
import hashlib
import json
import os
from pathlib import Path
import shlex
import sys
import time
import uuid

import paramiko

def resource(name):
    return Path(getattr(sys, '_MEIPASS', Path(__file__).parent)) / 'resources' / name

def data_dir():
    if os.environ.get('VLESS_MANAGER_DATA'):
        directory = Path(os.environ['VLESS_MANAGER_DATA'])
    elif sys.platform == 'darwin':
        directory = Path.home() / 'Library' / 'Application Support' / 'VLESSManager'
    else:
        directory = Path(os.environ.get('APPDATA', str(Path.home()))) / 'VLESSManager'
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    return directory

class InteractiveHostKey(paramiko.MissingHostKeyPolicy):
    def __init__(self, confirm): self.confirm = confirm

    def missing_host_key(self, client, hostname, key):
        fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')
        if not self.confirm('Первое подключение', 'Сервер: %s\nКлюч: %s\n%s\n\nСверьте отпечаток с сервером. Доверять этому ключу?' % (hostname, key.get_name(), fingerprint)):
            raise RuntimeError('Ключ сервера не подтверждён')
        client.get_host_keys().add(hostname, key.get_name(), key)
        client.save_host_keys(str(data_dir() / 'known_hosts'))

class SSH:
    def __init__(self, profile, password, confirm):
        self.profile = profile.copy(); self.password = password; self.confirm = confirm
        self.client = None

    def connect(self):
        if self.client:
            transport = self.client.get_transport()
            if transport and transport.is_active(): return
            self.client.close()
        client = paramiko.SSHClient()
        path = data_dir() / 'known_hosts'
        if path.is_file(): client.load_host_keys(str(path))
        client.set_missing_host_key_policy(InteractiveHostKey(self.confirm))
        p = self.profile
        options = dict(hostname=p['host'], port=int(p.get('port', 22)), username=p.get('username') or 'root', timeout=15, banner_timeout=20, auth_timeout=25, allow_agent=False, look_for_keys=False)
        if p.get('keyfile'):
            options.update(key_filename=p['keyfile'], passphrase=self.password or None)
        else: options['password'] = self.password
        try: client.connect(**options)
        except Exception:
            client.close(); raise
        client.get_transport().set_keepalive(20)
        self.client = client

    def close(self):
        if self.client: self.client.close()
        self.client = None

    def command(self, command, stdin_data=None, timeout=60):
        self.connect()
        channel = self.client.get_transport().open_session(timeout=20)
        channel.settimeout(timeout)
        channel.exec_command(command)
        if stdin_data:
            channel.sendall(stdin_data.encode() if isinstance(stdin_data, str) else stdin_data)
        channel.shutdown_write()
        output, errors = bytearray(), bytearray()
        start = time.monotonic()
        try:
            while True:
                while channel.recv_ready(): output.extend(channel.recv(65536))
                while channel.recv_stderr_ready(): errors.extend(channel.recv_stderr(65536))
                if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready(): break
                if time.monotonic() - start > timeout: raise TimeoutError('Истекло время ожидания команды SSH')
                time.sleep(0.025)
            code = channel.recv_exit_status()
            if code: raise RuntimeError((errors or output).decode('utf-8', 'replace')[-2500:] or 'Команда SSH завершилась с кодом ' + str(code))
            return output.decode('utf-8', 'replace')
        finally: channel.close()

    def inspect(self, options):
        # Python code is read from SSH stdin. No agent files are created on the server.
        source = resource('remote_agent.py').read_text(encoding='utf-8')
        source += '\nprint(json.dumps(inspect_remote(' + repr(options) + '), ensure_ascii=False))\n'
        try: return json.loads(self.command('python3 -', source, 90))
        except RuntimeError as e:
            if 'not found' in str(e): raise RuntimeError('Для чтения установленного сервера нужен python3. Чистая установка установит его после подтверждения.') from e
            raise

    def submit(self, request):
        self.connect()
        ident = uuid.uuid4().hex
        folder = '/var/lib/vless-manager/jobs/' + ident
        self.command('umask 077; mkdir -p /var/lib/vless-manager/jobs; mkdir ' + shlex.quote(folder))
        with self.client.open_sftp() as sftp:
            for name in ['remote_agent.py', 'install_entry.py', 'install_exit.py', 'vless_profile.py', 'transport_install.py']:
                with sftp.file(folder + '/' + name, 'wb') as f: f.write(resource(name).read_bytes())
                sftp.chmod(folder + '/' + name, 0o600)
            with sftp.file(folder + '/request.json', 'wb') as f: f.write(json.dumps(request, ensure_ascii=False).encode())
            sftp.chmod(folder + '/request.json', 0o600)
            bootstrap = '#!/bin/bash\nset -euo pipefail\numask 077\ncd ' + shlex.quote(folder) + '\n'
            bootstrap += "trap 'rc=$?; if [ \"$rc\" -ne 0 ] && [ ! -f result.json ]; then printf \"{\\\"ok\\\":false,\\\"message\\\":\\\"Подготовка завершилась ошибкой. См. журнал задания.\\\"}\\n\" > result.json; rm -f request.json; fi' EXIT\n"
            bootstrap += '[ "$(id -u)" = 0 ] || { echo "Нужен root"; exit 1; }\n'
            if request['action'] == 'install':
                bootstrap += '''[ -d /run/systemd/system ] && command -v apt-get >/dev/null || { echo 'Нужен Debian/Ubuntu с systemd'; exit 1; }
for path in /usr/local/bin/xray /usr/local/etc/xray/config.json /etc/systemd/system/xray.service; do
  [ ! -e "$path" ] || { echo 'Найдена существующая установка. Используйте настройку сервера.'; exit 1; }
done
need=0
for cmd in python3 curl ip useradd runuser flock logrotate; do command -v "$cmd" >/dev/null || need=1; done
[ -f /etc/ssl/certs/ca-certificates.crt ] || need=1
if [ "$need" = 1 ]; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 curl ca-certificates iproute2 util-linux passwd logrotate
fi
'''
                options=request.get('options',{})
                if options.get('security')=='tls':
                    packages=['openssl']+(['certbot']if options.get('tls_method')=='acme'else[])
                    bootstrap+='if '+ ' || '.join('! command -v '+name+' >/dev/null'for name in packages)+'; then\n  apt-get update\n  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends '+' '.join(packages)+'\nfi\n'
            bootstrap += "python3 -u -c 'from remote_agent import main; main(\".\")'\n"
            with sftp.file(folder + '/bootstrap.sh', 'wb') as f: f.write(bootstrap.encode())
            sftp.chmod(folder + '/bootstrap.sh', 0o700)
        self.command('umask 077; nohup bash ' + shlex.quote(folder + '/bootstrap.sh') + ' > ' + shlex.quote(folder + '/output.log') + ' 2>&1 < /dev/null &')
        return ident

    def job(self, ident):
        if len(ident) != 32 or any(c not in '0123456789abcdef' for c in ident): raise ValueError('Некорректный номер задания')
        self.connect()
        folder = '/var/lib/vless-manager/jobs/' + ident
        with self.client.open_sftp() as sftp:
            with sftp.file(folder + '/output.log', 'rb') as f:
                stat = f.stat()
                if stat.st_size > 120000: f.seek(stat.st_size - 120000)
                log = f.read().decode('utf-8', 'replace')
            try:
                with sftp.file(folder + '/result.json', 'rb') as f: result = json.loads(f.read())
            except FileNotFoundError: result = None
        return {'log': log, 'result': result}
