import copy
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
from resources import transport_install as adapter
from test_core import config,LINK,UUID,KEY

class InstallerTransportTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.etc=self.root/'etc';self.etc.mkdir()
        self.source_cert=self.root/'source.crt';self.source_cert.write_bytes(b'CERTIFICATE FIXTURE')
        self.source_key=self.root/'source.key';self.source_key.write_bytes(b'PRIVATE FIXTURE')
        self.calls=[];self.messages=[]
        def run(args,**kwargs):
            self.calls.append(args)
            return types.SimpleNamespace(returncode=0,stdout='Hostname cert.example.com does match certificate',stderr='')
        def atomic(path,data,*args):Path(path).write_bytes(data.encode()if isinstance(data,str)else data)
        self.module=types.SimpleNamespace(check_cover=lambda _:None,say=self.messages.append,ETC=self.etc,atomic=atomic,run=run,build_config=lambda *a,**k:config())
        self.options={'transport':'grpc','security':'tls','flow':'','sni':'cert.example.com','tls_method':'existing','tls_cert_file':str(self.source_cert),'tls_key_file':str(self.source_key)}
    def tearDown(self):self.tmp.cleanup()
    def build(self):
        with patch.dict(sys.modules,{'pwd':types.SimpleNamespace(getpwnam=lambda _:types.SimpleNamespace(pw_gid=0))}):return self.module.build_config()
    def test_tls_files_are_tracked_and_cleanup_keeps_sources(self):
        cleanup,_=adapter.configure(self.module,self.options)
        with patch.object(adapter.ssl,'SSLContext'):self.module.check_cover('cert.example.com')
        c=self.build();stream=c['inbounds'][0]['streamSettings']
        self.assertEqual(stream['network'],'grpc');self.assertEqual(stream['security'],'tls')
        self.assertEqual((self.etc/'tls-privkey.pem').read_bytes(),b'PRIVATE FIXTURE')
        self.assertNotIn('flow',c['inbounds'][0]['settings']['clients'][0])
        cleanup();self.assertFalse((self.etc/'tls-privkey.pem').exists());self.assertTrue(self.source_key.is_file())
    def test_certificate_hostname_mismatch_rejected_before_copy(self):
        adapter.configure(self.module,self.options)
        self.module.run=lambda *a,**k:types.SimpleNamespace(returncode=0,stdout='Hostname cert.example.com does NOT match certificate')
        with patch.object(adapter.ssl,'SSLContext'):
            with self.assertRaisesRegex(ValueError,'не соответствует'):self.module.check_cover('cert.example.com')
        self.assertFalse(list(self.etc.iterdir()))
    def test_tls_source_file_never_overwritten(self):
        self.options['tls_key_file']=str(self.etc/'tls-privkey.pem');(self.etc/'tls-privkey.pem').write_bytes(b'EXISTING KEY')
        adapter.configure(self.module,self.options)
        with patch.object(adapter.ssl,'SSLContext'):self.module.check_cover('cert.example.com')
        with self.assertRaisesRegex(RuntimeError,'перезаписи'):self.build()
        self.assertEqual((self.etc/'tls-privkey.pem').read_bytes(),b'EXISTING KEY')
    def test_reality_constructor_preserves_routes(self):
        options={'transport':'xhttp','security':'reality','flow':'','sni':'www.microsoft.com'}
        cleanup,_=adapter.configure(self.module,options)
        c=self.build();self.assertEqual(c['routing'],config()['routing']);self.assertEqual(c['inbounds'][0]['streamSettings']['network'],'xhttp')
        cleanup();self.assertFalse(list(self.etc.iterdir()))
    def test_installer_parses_tls_upstream_as_flat_config(self):
        adapter.configure(self.module,self.options)
        o=self.module.parse_vless(LINK.replace('security=reality','security=tls'))
        self.assertEqual(o['settings']['id'],UUID);self.assertEqual(o['streamSettings']['security'],'tls')
    def test_installer_link_uses_selected_transport(self):
        adapter.configure(self.module,self.options)
        uri=self.module.client_link('203.0.113.8',443,UUID,KEY,'aa12','cert.example.com','Test')
        self.assertIn('type=grpc',uri);self.assertIn('security=tls',uri);self.assertNotIn('pbk=',uri)

if __name__=='__main__':unittest.main()
