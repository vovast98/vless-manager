"""Shared, pure VLESS profile/config/URI logic for desktop and installers."""
import base64
import copy
import ipaddress
import json
import re
import uuid
from urllib.parse import parse_qs, quote, unquote, urlencode, urlsplit

TRANSPORTS = ('tcp','xhttp','grpc','ws','httpupgrade')
REALITY_TRANSPORTS = ('tcp','xhttp','grpc')

def host(value):
    value=value.strip()
    try:return str(ipaddress.ip_address(value))
    except ValueError:
        value=value.rstrip('.').encode('idna').decode('ascii').lower()
        if not value or len(value)>253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',x)for x in value.split('.')):raise ValueError('Некорректный IP или домен')
        return value

def profile(options):
    network=options.get('transport','tcp').lower()
    network={'raw':'tcp','websocket':'ws','splithttp':'xhttp'}.get(network,network)
    security=options.get('security','reality').lower()
    flow=options.get('flow','xtls-rprx-vision'if network=='tcp'else'')
    flow=''if flow in ('none','Без Vision')else flow
    if network not in TRANSPORTS:raise ValueError('Поддерживаются TCP/RAW, XHTTP, gRPC, WebSocket и HTTPUpgrade')
    if security not in ('reality','tls'):raise ValueError('Поддерживаются Reality и TLS')
    if security=='reality'and network not in REALITY_TRANSPORTS:raise ValueError('Reality несовместим с WebSocket/HTTPUpgrade. Выберите TLS.')
    if flow not in ('','xtls-rprx-vision'):raise ValueError('Поддерживается Vision или пустой flow')
    if flow and network!='tcp':raise ValueError('Vision с encryption=none поддерживается только для TCP/RAW')
    path=options.get('path','/vless')or'/vless'
    if not path.startswith('/')or any(c in path for c in '\r\n\x00'):raise ValueError('HTTP-путь должен начинаться с / и не содержать управляющих символов')
    service=options.get('service_name','vless')or'vless'
    if not re.fullmatch(r'[a-zA-Z0-9_.-]{1,128}',service):raise ValueError('gRPC serviceName: буквы, цифры, _, точка и дефис')
    mode=options.get('xhttp_mode','auto')or'auto'
    if mode not in ('auto','packet-up','stream-up','stream-one'):raise ValueError('Некорректный режим XHTTP')
    http_host=options.get('http_host','').strip()
    if http_host:http_host=host(http_host)
    return {'transport':network,'security':security,'flow':flow,'path':path,'service_name':service,'xhttp_mode':mode,'http_host':http_host}

def transport_settings(p,server=False):
    network=p['transport'];stream={'network':network}
    if network=='xhttp':
        settings={'path':p['path'],'mode':'auto'if server else p['xhttp_mode']}
        if p['http_host']:settings['host']=p['http_host']
        stream['xhttpSettings']=settings
    elif network=='grpc':
        stream['grpcSettings']={'serviceName':p['service_name'],'multiMode':False}
        if p['http_host']:stream['grpcSettings']['authority']=p['http_host']
    elif network=='ws':
        settings={'path':p['path']}
        if p['http_host']:settings['headers']={'Host':p['http_host']}
        stream['wsSettings']=settings
    elif network=='httpupgrade':
        settings={'path':p['path']}
        if p['http_host']:settings['host']=p['http_host']
        stream['httpupgradeSettings']=settings
    return stream

def alpn(network):return ['http/1.1']if network in ('ws','httpupgrade')else['h2','http/1.1']

def inbound(original,options,cert_file=None,key_file=None):
    p=profile(options);i=copy.deepcopy(original);old=i.get('streamSettings',{}).get('realitySettings',{})
    sni=host(options.get('sni')or old.get('serverNames',[''])[0])
    stream=transport_settings(p,server=True);stream['security']=p['security']
    if p['security']=='reality':
        stream['realitySettings']=old
    else:
        if not cert_file or not key_file:raise ValueError('Для TLS нужны сертификат и приватный ключ')
        stream['tlsSettings']={'serverName':sni,'minVersion':'1.3'if p['flow']else'1.2','alpn':alpn(p['transport']),'certificates':[{'certificateFile':str(cert_file),'keyFile':str(key_file)}]}
    i['streamSettings']=stream
    for user in i.get('settings',{}).get('clients',[]):
        if p['flow']:user['flow']=p['flow']
        else:user.pop('flow',None)
    return i

def link(address,port,user_id,public_key,short_id,sni,name,options):
    p=profile(options);address=host(address)
    if ':'in address:address='['+address+']'
    q={'encryption':'none','type':p['transport'],'security':p['security'],'sni':sni}
    if p['flow']:q['flow']=p['flow']
    if p['security']=='reality':q.update(pbk=public_key,sid=short_id,fp='chrome')
    else:q['alpn']=','.join(alpn(p['transport']))
    if p['transport']in ('xhttp','ws','httpupgrade'):q['path']=p['path']
    if p['http_host']:q['authority'if p['transport']=='grpc'else'host']=p['http_host']
    if p['transport']=='xhttp':q['mode']=p['xhttp_mode']
    if p['transport']=='grpc':q.update(serviceName=p['service_name'],mode='gun')
    return 'vless://%s@%s:%s?%s#%s'%(str(uuid.UUID(user_id)),address,port,urlencode(q),quote(name,safe=''))

def parse(link_text,tag='upstream',flat=False):
    try:
        parsed=urlsplit(link_text.strip())
        if parsed.scheme!='vless'or parsed.password is not None or not parsed.hostname:raise ValueError()
        uid=str(uuid.UUID(unquote(parsed.username or'')));address=host(parsed.hostname);port=parsed.port
        if port is None or not 1<=port<=65535:raise ValueError()
    except (ValueError,UnicodeError):raise ValueError('Нужна VLESS-ссылка с UUID, адресом и портом')from None
    values=parse_qs(parsed.query,keep_blank_values=True)
    if any(len(v)!=1 for v in values.values()):raise ValueError('Повторяющиеся параметры VLESS-ссылки')
    q={k:v[0]for k,v in values.items()}
    if q.get('encryption','none')!='none'or q.get('headerType','none')!='none':raise ValueError('Поддерживается encryption=none и headerType=none')
    if q.get('allowInsecure','0')not in ('0','false',''):raise ValueError('Небезопасная TLS-ссылка allowInsecure не поддерживается')
    opts={'transport':q.get('type','tcp'),'security':q.get('security','none'),'flow':q.get('flow',''),'path':q.get('path','/'),'service_name':q.get('serviceName','vless'),'xhttp_mode':q.get('mode','auto')if q.get('type')in ('xhttp','splithttp')else'auto','http_host':q.get('host',q.get('authority',''))}
    p=profile(opts);sni=host(q.get('sni')or q.get('serverName')or(address if p['security']=='tls'else''))
    if p['transport']=='grpc'and q.get('mode','gun')not in ('gun',''):raise ValueError('Поддерживается gRPC mode=gun, без multiMode')
    stream=transport_settings(p);stream['security']=p['security']
    if p['security']=='reality':
        public=q.get('pbk','');sid=q.get('sid','')
        if not re.fullmatch(r'[A-Za-z0-9_-]{43}',public)or len(base64.b64decode(public+'=',altchars=b'-_',validate=True))!=32:raise ValueError('Некорректный ключ pbk')
        if not re.fullmatch(r'(?:[0-9a-fA-F]{2}){0,8}',sid):raise ValueError('sid: до 16 hex-символов, чётное число')
        reality={'serverName':sni,'fingerprint':q.get('fp')or'chrome','publicKey':public,'shortId':sid.lower()}
        for source,dest in [('spx','spiderX'),('pqv','mldsa65Verify')]:
            if q.get(source):reality[dest]=q[source]
        stream['realitySettings']=reality
    else:
        stream['tlsSettings']={'serverName':sni,'alpn':q.get('alpn',','.join(alpn(p['transport']))).split(',')}
        if q.get('fp'):stream['tlsSettings']['fingerprint']=q['fp']
    settings={'address':address,'port':port,'id':uid,'encryption':'none','flow':p['flow']}
    if not flat:settings={'vnext':[{'address':address,'port':port,'users':[{'id':uid,'encryption':'none','flow':p['flow']}]}]}
    return {'tag':tag,'protocol':'vless','settings':settings,'streamSettings':stream}

def from_inbound(i,address,public_key,user_index=0,name='VLESS'):
    stream=i.get('streamSettings',{});security=stream.get('security','none');network=stream.get('network',stream.get('method','tcp'))
    if i.get('protocol')!='vless':raise ValueError('Выбран вход не VLESS')
    user=i['settings']['clients'][user_index]
    options={'transport':network,'security':security,'flow':user.get('flow','')}
    if network in ('xhttp','splithttp'):
        st=stream.get('xhttpSettings',stream.get('splithttpSettings',{}));options.update(path=st.get('path','/'),xhttp_mode=st.get('mode','auto'),http_host=st.get('host',''))
        if st.get('extra'):raise ValueError('Для этого XHTTP-входа заданы расширенные extra. Создайте ссылку с extra вручную, чтобы не потерять параметры.')
    elif network=='grpc':
        st=stream.get('grpcSettings',{});options.update(service_name=st.get('serviceName','vless'),http_host=st.get('authority',''))
        if st.get('multiMode'):raise ValueError('gRPC multiMode пока не экспортируется автоматически')
    elif network in ('ws','websocket'):
        st=stream.get('wsSettings',{});options.update(path=st.get('path','/'),http_host=st.get('headers',{}).get('Host',st.get('host','')))
    elif network=='httpupgrade':
        st=stream.get('httpupgradeSettings',{});options.update(path=st.get('path','/'),http_host=st.get('host',''))
    if security=='reality':
        r=stream['realitySettings']
        if r.get('mldsa65Seed'):raise ValueError('Для этого входа нужен параметр pqv; сформируйте ссылку вручную')
        sni=r['serverNames'][0];sid=r['shortIds'][0]
    else:sni=stream.get('tlsSettings',{}).get('serverName')or host(address);sid=''
    return link(address,i['port'],user['id'],public_key,sid,sni,name,options)
