import copy
import json
import unittest
from urllib.parse import urlencode
import core

UUID='12345678-1234-4234-9234-123456789abc'
KEY='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
LINK='vless://'+UUID+'@203.0.113.9:8443?'+urlencode({'security':'reality','type':'tcp','pbk':KEY,'sni':'www.microsoft.com','sid':'aa12','flow':'xtls-rprx-vision'})

def config():
    return {'inbounds':[{'protocol':'vless','port':443,'settings':{'clients':[{'id':UUID,'flow':'xtls-rprx-vision'}]},'streamSettings':{'security':'reality','realitySettings':{'serverNames':['www.microsoft.com'],'shortIds':['aa12'],'privateKey':'private'}}}], 'outbounds':[{'tag':'direct','protocol':'freedom'},{'tag':'block','protocol':'blackhole'},core.parse_vless(LINK,'telegram-proxy')], 'routing':{'domainStrategy':'IPIfNonMatch','rules':[{'type':'field','domain':['geosite:youtube'],'outboundTag':'telegram-proxy'},{'type':'field','ip':['geoip:private'],'outboundTag':'block'}]}}

class CoreTests(unittest.TestCase):
    def test_parse_exact_credentials(self):
        o=core.parse_vless(LINK);self.assertEqual(o['settings']['vnext'][0]['users'][0]['id'],UUID);self.assertEqual(o['streamSettings']['realitySettings']['publicKey'],KEY)
    def test_ipv6_uri(self):
        link=LINK.replace('203.0.113.9','[2001:db8::1]');self.assertEqual(core.parse_vless(link)['settings']['vnext'][0]['address'],'2001:db8::1')
    def test_reject_duplicate(self):
        with self.assertRaises(ValueError):core.parse_vless(LINK+'&sni=example.com')
    def test_tls_supported(self):
        out=core.parse_vless(LINK.replace('security=reality','security=tls'))
        self.assertEqual(out['streamSettings']['security'],'tls')
    def test_reject_bad_sid(self):
        with self.assertRaises(ValueError):core.parse_vless(LINK.replace('sid=aa12','sid=a'))
    def test_reject_bad_uuid(self):
        with self.assertRaises(ValueError):core.parse_vless(LINK.replace(UUID,'not-a-uuid'))
    def test_reject_missing_port(self):
        with self.assertRaises(ValueError):core.parse_vless(LINK.replace(':8443',''))
    def test_reject_ws(self):
        with self.assertRaises(ValueError):core.parse_vless(LINK.replace('type=tcp','type=ws'))
    def test_reject_bad_key(self):
        with self.assertRaises(ValueError):core.parse_vless(LINK.replace(KEY,'bad'))
    def test_change_route_preserves_all_base_rules(self):
        c=config();before=copy.deepcopy(c);new=core.change_route(c,'proxy','hermes-assets.nousresearch.com')
        self.assertEqual(c,before);self.assertEqual(new['routing']['rules'][1:],c['routing']['rules']);self.assertEqual(new['outbounds'],c['outbounds']);self.assertEqual(new['inbounds'],c['inbounds'])
    def test_remove_is_reversible(self):
        c=config();new=core.change_route(c,'proxy','example.com');self.assertEqual(core.change_route(new,'proxy','example.com',remove=True),c)
    def test_route_replacement_not_duplicate(self):
        c=core.change_route(config(),'proxy','example.com');c=core.change_route(c,'direct','example.com');s=core.route_state(c);self.assertEqual(len(s['entries']),1);self.assertEqual(s['entries'][0]['route'],'direct')
    def test_specific_domain_first(self):
        c=core.change_route(config(),'proxy','example.com');c=core.change_route(c,'direct','full:a.example.com');self.assertEqual(c['routing']['rules'][0]['domain'],['full:a.example.com'])
    def test_narrow_cidr_first(self):
        c=core.change_route(config(),'proxy','203.0.113.0/24');c=core.change_route(c,'direct','203.0.113.4');self.assertEqual(c['routing']['rules'][0]['ip'],['203.0.113.4/32'])
    def test_reject_url_as_domain(self):
        with self.assertRaises(ValueError):core.normalize_target('https://example.com/a')
    def test_upstream_preserves_inputs_routes_and_sockopts(self):
        c=config();c['outbounds'][2]['streamSettings']['sockopt']={'tcpMaxSeg':1200}
        new=core.replace_upstream(c,LINK.replace(':8443',':443'),'telegram-proxy');self.assertEqual(new['routing'],c['routing']);self.assertEqual(new['inbounds'],c['inbounds']);self.assertEqual(new['outbounds'][2]['streamSettings']['sockopt'],{'tcpMaxSeg':1200})
    def test_no_overwrite_direct_as_vless(self):
        with self.assertRaises(ValueError):core.replace_upstream(config(),LINK,'direct')
    def test_geo_does_not_remove_explicit_rules(self):
        c=config();new=core.geo_route(c,'telegram-proxy','blocked');self.assertEqual(new['routing']['rules'][:-1],c['routing']['rules'])
    def test_geo_idempotent(self):
        c=core.geo_route(config(),'telegram-proxy','blocked');self.assertEqual(core.geo_route(c,'telegram-proxy','blocked'),c)
    def test_all_is_last(self):
        c=config();new=core.geo_route(c,'telegram-proxy','all');self.assertEqual(new['routing']['rules'][:-1],c['routing']['rules']);self.assertEqual(new['routing']['rules'][-1]['network'],'tcp,udp')
    def test_uri_can_be_reimported(self):
        link=core.client_uri(config(),'203.0.113.8',KEY,name='Тест / iPhone');self.assertEqual(core.parse_vless(link)['settings']['vnext'][0]['address'],'203.0.113.8')
    def test_diff_is_readable(self):
        before=config();after=core.change_route(before,'proxy','example.com');diff=core.config_diff(before,after);self.assertIn('+',diff);self.assertIn('example.com',diff)

if __name__=='__main__':unittest.main()
