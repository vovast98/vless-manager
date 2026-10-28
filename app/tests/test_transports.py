import copy
import json
import unittest
from resources import vless_profile as vp
from resources import transport_install
from test_core import config,KEY,UUID,LINK

class TransportTests(unittest.TestCase):
    def test_all_supported_profiles_roundtrip(self):
        for network in vp.TRANSPORTS:
            for security in ('reality','tls'):
                if security=='reality'and network not in vp.REALITY_TRANSPORTS:continue
                for flow in ('','xtls-rprx-vision')if network=='tcp'else('',):
                    with self.subTest(network=network,security=security,flow=flow):
                        options={'transport':network,'security':security,'flow':flow,'sni':'cert.example.com','path':'/custom','service_name':'custom','xhttp_mode':'auto','http_host':'http.example.com'}
                        i=vp.inbound(config()['inbounds'][0],options,'/cert.pem','/key.pem')
                        uri=vp.from_inbound(i,'203.0.113.8',KEY)
                        o=vp.parse(uri)
                        self.assertEqual(o['streamSettings']['network'],network);self.assertEqual(o['streamSettings']['security'],security)
                        self.assertEqual(o['settings']['vnext'][0]['users'][0]['flow'],flow)
                        section='realitySettings'if security=='reality'else'tlsSettings'
                        # Reality SNI is defined by the original inbound; TLS by options.
                        expected='www.microsoft.com'if security=='reality'else'cert.example.com'
                        self.assertEqual(o['streamSettings'][section]['serverName'],expected)
    def test_reality_rejects_http_upgrade_and_ws(self):
        for net in ('ws','httpupgrade'):
            with self.assertRaisesRegex(ValueError,'несовместим'):vp.profile({'transport':net,'security':'reality','flow':''})
    def test_vision_rejects_non_tcp(self):
        for net in ('xhttp','grpc','ws','httpupgrade'):
            with self.assertRaisesRegex(ValueError,'Vision'):vp.profile({'transport':net,'security':'tls','flow':'xtls-rprx-vision'})
    def test_non_tcp_defaults_to_no_flow(self):
        self.assertEqual(vp.profile({'transport':'grpc'})['flow'],'')
    def test_aliases(self):
        self.assertEqual(vp.profile({'transport':'raw'})['transport'],'tcp')
        self.assertEqual(vp.profile({'transport':'splithttp'})['transport'],'xhttp')
    def test_custom_path_host_and_service_preserved(self):
        for net in ('xhttp','grpc','ws','httpupgrade'):
            options={'transport':net,'security':'tls','flow':'','path':'/test%20path','service_name':'my-service','http_host':'http.example.com'}
            uri=vp.link('203.0.113.8',8443,UUID,'','','cert.example.com','Тест',options);s=vp.parse(uri)['streamSettings']
            if net=='grpc':self.assertEqual(s['grpcSettings']['serviceName'],'my-service');self.assertEqual(s['grpcSettings']['authority'],'http.example.com')
            else:
                key={'xhttp':'xhttpSettings','ws':'wsSettings','httpupgrade':'httpupgradeSettings'}[net]
                self.assertEqual(s[key]['path'],'/test%20path')
    def test_tls_never_includes_reality_keys(self):
        uri=vp.link('203.0.113.8',443,UUID,KEY,'aa12','cert.example.com','Test',{'security':'tls'})
        self.assertNotIn('pbk=',uri);self.assertNotIn('sid=',uri)
        self.assertNotIn('realitySettings',vp.parse(uri)['streamSettings'])
    def test_server_xhttp_accepts_modes_and_client_selects_mode(self):
        for mode in ('auto','packet-up','stream-up','stream-one'):
            p=vp.profile({'transport':'xhttp','xhttp_mode':mode})
            self.assertEqual(vp.transport_settings(p,server=True)['xhttpSettings']['mode'],'auto')
            self.assertEqual(vp.transport_settings(p)['xhttpSettings']['mode'],mode)
    def test_http1_transports_get_http1_alpn(self):
        for network in ('ws','httpupgrade'):self.assertEqual(vp.alpn(network),['http/1.1'])
        self.assertEqual(vp.alpn('grpc')[0],'h2')
    def test_inbound_creation_does_not_mutate_original(self):
        original=config()['inbounds'][0];before=copy.deepcopy(original)
        vp.inbound(original,{'transport':'grpc','security':'tls','sni':'cert.example.com'},'/cert','/key')
        self.assertEqual(original,before)
    def test_tls_requires_certificate(self):
        with self.assertRaisesRegex(ValueError,'сертификат'):vp.inbound(config()['inbounds'][0],{'security':'tls','sni':'cert.example.com'})
    def test_unsafe_tls_uri_refused(self):
        with self.assertRaisesRegex(ValueError,'allowInsecure'):vp.parse(LINK.replace('security=reality','security=tls')+'&allowInsecure=1')
    def test_flat_settings_for_installer_compatible(self):
        parsed=vp.parse(LINK,flat=True);self.assertEqual(parsed['settings']['id'],UUID);self.assertEqual(parsed['settings']['address'],'203.0.113.9')
    def test_injected_path_rejected(self):
        with self.assertRaises(ValueError):vp.profile({'path':'/abc\r\nInjected: test'})
    def test_acme_port80_rejected_before_install(self):
        with self.assertRaisesRegex(ValueError,'TCP 80'):transport_install.configure(None,{'security':'tls','tls_method':'acme','port':80})

if __name__=='__main__':unittest.main()
