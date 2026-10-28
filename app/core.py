"""Pure configuration operations; this module never connects to a server."""
import base64
import copy
import difflib
import hashlib
import ipaddress
import json
import re
import uuid
from urllib.parse import parse_qs, quote, unquote, urlencode, urlsplit
from resources import vless_profile

PREFIX = 'xray-manual-'

def sha(data):
    return hashlib.sha256(data).hexdigest()

def host(value):
    value = value.strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        value = value.rstrip('.').encode('idna').decode('ascii').lower()
        if not value or len(value) > 253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x) for x in value.split('.')):
            raise ValueError('Некорректный IP-адрес или домен')
        return value

def parse_vless(link, tag='upstream'):
    return vless_profile.parse(link, tag)

def outbound_summary(out):
    s = out.get('settings', {})
    s = (s.get('vnext') or [s])[0]
    return '%s:%s' % (s.get('address', '?'), s.get('port', '?'))

def replace_upstream(config, link, tag):
    c = copy.deepcopy(config)
    new = parse_vless(link, tag)
    current = next((o for o in c.get('outbounds', []) if o.get('tag') == tag), None)
    if current:
        if current.get('protocol') != 'vless':
            raise ValueError('Выбранный выход не VLESS; выберите другой тег')
        # Preserve transport socket tuning and other independent outbound options.
        for k in ('sockopt',):
            if k in current.get('streamSettings', {}):
                new['streamSettings'][k] = copy.deepcopy(current['streamSettings'][k])
        c['outbounds'][c['outbounds'].index(current)] = new
    else:
        c.setdefault('outbounds', []).append(new)
    for inbound in c.get('inbounds', []):
        address = new['settings']['vnext'][0]
        if inbound.get('port') == address['port'] and address['address'] in ('127.0.0.1', '::1', 'localhost'):
            raise ValueError('Перенаправление указывает на свой локальный вход')
    return c

def normalize_target(value):
    value = value.strip()
    try:
        return 'ip', str(ipaddress.ip_network(value.removeprefix('ip:') if hasattr(str, 'removeprefix') else value[3:] if value.startswith('ip:') else value, strict=False))
    except ValueError:
        if '/' in value or value.startswith('ip:'):
            raise ValueError('Некорректный IP или CIDR')
    mode = 'full:' if value.startswith('full:') else 'domain:'
    value = value.split(':', 1)[1] if value.startswith(('full:', 'domain:')) else value
    if value.startswith('*.'):
        if mode == 'full:': raise ValueError('Для full: маска недопустима')
        value = value[2:]
    name = host(value)
    if '.' not in name or all(ch in '0123456789.' for ch in name):
        raise ValueError('Укажите домен, IP или CIDR, а не URL')
    return 'domain', mode + name

def route_sort(entry):
    if entry['kind'] == 'domain':
        mode, name = entry['value'].split(':', 1)
        return (0, -len(name.split('.')), -len(name), 0 if mode == 'full' else 1, name)
    net = ipaddress.ip_network(entry['value'])
    return (1, -net.prefixlen, net.version, int(net.network_address), '')

def proxy_tag(c):
    tags = {o.get('tag') for o in c.get('outbounds', []) if o.get('protocol') == 'vless'}
    for tag in ('telegram-proxy', 'upstream'):
        if tag in tags: return tag
    return next(iter(tags), 'upstream')

def route_state(config):
    entries = []
    for r in config.get('routing', {}).get('rules', []):
        if not str(r.get('ruleTag', '')).startswith(PREFIX): continue
        for kind in ('domain', 'ip'):
            for value in r.get(kind, []):
                tag = r.get('outboundTag')
                route = 'direct' if tag == 'direct' else 'block' if tag == 'block' else 'proxy'
                entries.append({'kind': kind, 'value': value, 'route': route})
    return {'version': 1, 'entries': sorted(entries, key=route_sort)}

def change_route(config, route, target, remove=False, upstream=None):
    c = copy.deepcopy(config)
    kind, value = normalize_target(target)
    state = route_state(c)
    entries = [e for e in state['entries'] if (e['kind'], e['value']) != (kind, value)]
    if not remove: entries.append({'kind': kind, 'value': value, 'route': route})
    tags = {o.get('tag') for o in c.get('outbounds', [])}
    mapping = {'direct': 'direct', 'block': 'block', 'proxy': upstream or proxy_tag(c)}
    generated = []
    existing = {}
    for old in c.get('routing', {}).get('rules', []):
        if str(old.get('ruleTag', '')).startswith(PREFIX):
            for old_kind in ('domain', 'ip'):
                if len(old.get(old_kind, [])) == 1:
                    existing[(old_kind, old[old_kind][0])] = old
    for e in sorted(entries, key=route_sort):
        identity = (e['kind'], e['value'])
        if identity != (kind, value) and identity in existing:
            generated.append(copy.deepcopy(existing[identity]))
            continue
        tag = mapping[e['route']]
        if tag not in tags: raise ValueError('В конфиге нет выхода: ' + tag)
        ident = sha((e['kind'] + ':' + e['value']).encode())[:16]
        generated.append({'type': 'field', 'ruleTag': PREFIX + ident, 'outboundTag': tag, e['kind']: [e['value']]})
    rules = c.setdefault('routing', {}).setdefault('rules', [])
    c['routing']['rules'] = generated + [r for r in rules if not str(r.get('ruleTag', '')).startswith(PREFIX)]
    return c

def geo_route(config, tag, mode):
    c = copy.deepcopy(config)
    rules = c.setdefault('routing', {}).setdefault('rules', [])
    rules[:] = [r for r in rules if r.get('ruleTag') not in ('vless-manager-geo', 'vless-manager-all')]
    if mode == 'blocked':
        matching = [r for r in rules if 'ext:ru-blocked.dat:ru-blocked' in r.get('domain', [])]
        if matching:
            for r in matching: r['outboundTag'] = tag
        else: rules.append({'type': 'field', 'ruleTag': 'vless-manager-geo', 'domain': ['ext:ru-blocked.dat:ru-blocked'], 'outboundTag': tag})
    elif mode == 'all':
        rules.append({'type': 'field', 'ruleTag': 'vless-manager-all', 'network': 'tcp,udp', 'outboundTag': tag})
    elif mode != 'keep': raise ValueError('Неизвестный режим маршрутизации')
    return c

def encode(config):
    if not isinstance(config, dict) or not isinstance(config.get('inbounds'), list) or not isinstance(config.get('outbounds'), list):
        raise ValueError('Ожидается объект Xray с inbounds и outbounds')
    return (json.dumps(config, ensure_ascii=False, indent=2) + '\n').encode('utf-8')

def config_diff(before, after):
    return ''.join(difflib.unified_diff(encode(before).decode().splitlines(True), encode(after).decode().splitlines(True), fromfile='На сервере', tofile='После применения')) or 'Конфиг не изменился.\n'

def client_uri(config, address, public_key, inbound_index=0, client_index=0, name='VLESS'):
    return vless_profile.from_inbound(config['inbounds'][inbound_index], address, public_key, client_index, name)
