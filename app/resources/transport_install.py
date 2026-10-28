"""Adapt the transactional fresh installers to selectable VLESS transports."""
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import ssl
import subprocess
try:import vless_profile as vp
except ImportError:from . import vless_profile as vp

def configure(module,options):
    settings=vp.profile(options)
    if settings['security']=='tls'and options.get('tls_method')=='acme'and options.get('port')==80:raise ValueError('TCP 80 нужен для выдачи и продления сертификата. Выберите другой порт VLESS.')
    created=[];firewall_undo=[];tls_sources={}
    old_cover=module.check_cover
    original_say=module.say

    def say(text):
        label='VLESS + '+settings['security'].upper()+' / '+settings['transport'].upper()+(' / Vision'if settings['flow']else'')
        text=text.replace('VLESS + REALITY + Vision, TCP',label+', TCP-порт').replace('VLESS REALITY Vision, TCP',label+', TCP-порт')
        original_say(text)
    module.say=say

    def write_extra(path,data,mode,gid=0):
        path=Path(path)
        if path.exists():raise RuntimeError('Отказ от перезаписи TLS-файла: '+str(path))
        module.atomic(path,data,mode,gid);created.append(path)

    def open_http_port():
        if options.get('no_firewall'):return
        if shutil.which('ufw'):
            if re.search(r'^Status: active',module.run(['ufw','status'],env={**os.environ,'LC_ALL':'C'}).stdout,re.M):
                added=module.run(['ufw','show','added']).stdout
                if not any(re.match(r'^ufw allow 80(?:/tcp)?(?:\s|$)',line.strip())for line in added.splitlines()):
                    module.run(['ufw','allow','80/tcp','comment','VLESS-Manager-ACME'])
                    firewall_undo.append(['ufw','--force','delete','allow','80/tcp','comment','VLESS-Manager-ACME'])
                return
        if shutil.which('firewall-cmd')and module.run(['firewall-cmd','--state'],check=False).returncode==0:
            for prefix in (['firewall-cmd'],['firewall-cmd','--permanent']):
                if module.run(prefix+['--query-port=80/tcp'],check=False).returncode:
                    module.run(prefix+['--add-port=80/tcp']);firewall_undo.append(prefix+['--remove-port=80/tcp'])

    def check_cover(domain):
        if settings['security']=='reality':return old_cover(domain)
        method=options.get('tls_method','existing')
        if method=='acme':
            if not options.get('acme_agree'):raise ValueError('Подтвердите получение сертификата и условия Let’s Encrypt в плане установки')
            module.free_port(80);open_http_port()
            args=['certbot','certonly','--standalone','--non-interactive','--agree-tos','--preferred-challenges','http','--cert-name',domain,'-d',domain,'--keep-until-expiring']
            email=options.get('acme_email','').strip()
            args+=['--email',email]if email else['--register-unsafely-without-email']
            say('Получение TLS-сертификата Let’s Encrypt для '+domain+' (TCP 80 должен быть доступен извне)…')
            result=module.run(args,timeout=600,check=False)
            if result.returncode:raise RuntimeError('Certbot не выдал сертификат. Проверьте DNS домена и доступность TCP 80.\n'+(result.stderr or result.stdout)[-2200:])
            cert=Path('/etc/letsencrypt/live')/domain/'fullchain.pem';key=cert.parent/'privkey.pem'
        elif method=='existing':
            cert=Path(options.get('tls_cert_file',''));key=Path(options.get('tls_key_file',''))
            if not cert.is_absolute()or not key.is_absolute():raise ValueError('Укажите абсолютные пути к сертификату и приватному ключу на сервере')
        else:raise ValueError('Неизвестный способ получения сертификата')
        for p in (cert,key):
            if not p.is_file()or p.stat().st_size>2*1024*1024:raise ValueError('TLS-файл отсутствует или слишком большой: '+str(p))
        # Check pairing, hostname and remaining validity before creating Xray files.
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(str(cert),str(key))
        result=module.run(['openssl','x509','-in',str(cert),'-noout','-checkhost',domain],check=False,env={**os.environ,'LC_ALL':'C'})
        if result.returncode or 'does match certificate'not in result.stdout:raise ValueError('TLS-сертификат не соответствует SNI '+domain)
        module.run(['openssl','x509','-in',str(cert),'-noout','-checkend','86400'])
        tls_sources.update(cert=cert,key=key,domain=domain)
    module.check_cover=check_cover

    def adjust(config):
        cert_file=key_file=None
        if settings['security']=='tls':
            import pwd
            account=pwd.getpwnam('xray')
            cert_file=module.ETC/'tls-fullchain.pem';key_file=module.ETC/'tls-privkey.pem'
            write_extra(cert_file,tls_sources['cert'].read_bytes(),0o640,account.pw_gid)
            write_extra(key_file,tls_sources['key'].read_bytes(),0o640,account.pw_gid)
            if options.get('tls_method')=='acme':
                folder=Path('/etc/letsencrypt/renewal-hooks/deploy');folder.mkdir(parents=True,exist_ok=True)
                lineage=str(tls_sources['cert'].parent)
                hook='#!/bin/sh\nset -eu\n[ "${RENEWED_LINEAGE:-}" = '+shlex.quote(lineage)+' ] || exit 0\n'
                hook+='install -o root -g xray -m 640 "$RENEWED_LINEAGE/fullchain.pem" '+shlex.quote(str(cert_file))+'\n'
                hook+='install -o root -g xray -m 640 "$RENEWED_LINEAGE/privkey.pem" '+shlex.quote(str(key_file))+'\n'
                hook+='/usr/local/bin/xray run -test -config /usr/local/etc/xray/config.json\nsystemctl try-restart xray\n'
                write_extra(folder/'vless-manager-xray.sh',hook,0o700)
        config['inbounds'][0]=vp.inbound(config['inbounds'][0],options,cert_file,key_file)
        return config

    name='build_config'if hasattr(module,'build_config')else'build_exit_config'
    original=getattr(module,name)
    def build(*args,**kwargs):return adjust(original(*args,**kwargs))
    setattr(module,name,build)
    module.parse_vless=lambda text:vp.parse(text,tag='upstream',flat=True)
    module.client_link=lambda address,port,user_id,public,short,sni,name:vp.link(address,port,user_id,public,short,sni,name,options)

    def cleanup():
        for path in reversed(created):path.unlink(missing_ok=True)
        for args in reversed(firewall_undo):module.run(args,check=False)

    def success():
        if settings['security']=='tls'and options.get('tls_method')=='acme':
            r=module.run(['systemctl','enable','--now','certbot.timer'],check=False)
            if r.returncode:say('Сертификат получен, но таймер certbot не включён. Настройте продление вручную.')
            else:say('Продление сертификата: certbot.timer; после продления Xray кратко перезапускается.')
    return cleanup,success
