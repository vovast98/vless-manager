import contextlib
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

if os.name=='nt':
    sys.modules.setdefault('fcntl',types.SimpleNamespace(LOCK_EX=1,LOCK_NB=2,flock=lambda *a:None))
    sys.modules.setdefault('pwd',types.SimpleNamespace(getpwnam=lambda _:types.SimpleNamespace(pw_gid=0)))
spec=importlib.util.spec_from_file_location('agent',Path(__file__).parents[1]/'resources'/'remote_agent.py')
agent=importlib.util.module_from_spec(spec);spec.loader.exec_module(agent)

class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.config=self.root/'config.json';self.state=self.root/'manual-exceptions.json';self.assets=self.root/'assets';self.assets.mkdir()
        self.old={'inbounds':[],'outbounds':[{'tag':'direct','protocol':'freedom'}],'routing':{'rules':[]}}
        self.config.write_bytes(json.dumps(self.old).encode());self.state.write_bytes(b'{"version":1,"entries":[]}')
        self.raw=self.config.read_bytes();self.state_raw=self.state.read_bytes();self.calls=[]
        def command(args,**kwargs):self.calls.append([str(a)for a in args]);return types.SimpleNamespace(returncode=0,stdout='',stderr='')
        def atomic(p,data,*args,**kwargs):Path(p).write_bytes(data)
        self.stack=contextlib.ExitStack()
        self.stack.enter_context(patch.object(agent.os,'geteuid',lambda:0,create=True))
        for name,value in [('BACKUPS',self.root/'backups'),('locks',contextlib.nullcontext),('config_service_check',lambda *a:None),('atomic',atomic),('command',command),('validate',lambda *a:None),('checks',lambda *a:[])]:self.stack.enter_context(patch.object(agent,name,value))
        self.stack.enter_context(patch.object(agent.time,'sleep',lambda _:None))
    def tearDown(self):self.stack.close();self.tmp.cleanup()
    def request(self):
        c=copy.deepcopy(self.old);c['log']={'loglevel':'warning'}
        return {'config_path':str(self.config),'binary_path':str(self.root/'xray'),'assets_path':str(self.assets),'service':'xray','expected_sha':agent.sha(self.raw),'state_sha':agent.sha(self.state_raw),'config':c,'check_urls':[]}
    def restarts(self):return [x for x in self.calls if x[:2]==['systemctl','restart']]
    def test_success_creates_recoverable_backup(self):
        r=agent.apply(self.request());self.assertTrue(r['ok']);self.assertEqual((agent.BACKUPS/r['backup']/'config').read_bytes(),self.raw);self.assertEqual(len(self.restarts()),1)
    def test_stale_snapshot_rejected(self):
        self.config.write_bytes(b'{"changed":true}')
        with self.assertRaisesRegex(RuntimeError,'после чтения'):agent.apply(self.request())
        self.assertFalse(self.restarts());self.assertEqual(self.config.read_bytes(),b'{"changed":true}')
    def test_stale_manual_state_rejected(self):
        self.state.write_bytes(b'changed')
        with self.assertRaisesRegex(RuntimeError,'исключений изменился'):agent.apply(self.request())
        self.assertFalse(self.restarts())
    def test_validation_failure_leaves_original_bytes(self):
        with patch.object(agent,'validate',side_effect=RuntimeError('invalid')):
            with self.assertRaisesRegex(RuntimeError,'invalid'):agent.apply(self.request())
        self.assertEqual(self.config.read_bytes(),self.raw);self.assertEqual(self.state.read_bytes(),self.state_raw);self.assertFalse(self.restarts())
    def test_failed_http_restores_config_and_state(self):
        with patch.object(agent,'checks',side_effect=RuntimeError('HTTP failed')):
            with self.assertRaises(RuntimeError):agent.apply(self.request())
        self.assertEqual(self.config.read_bytes(),self.raw);self.assertEqual(self.state.read_bytes(),self.state_raw);self.assertEqual(len(self.restarts()),2)
    def test_restart_failure_also_rolls_back(self):
        original=agent.command;n=[0]
        def command(args,**kw):
            if args[:2]==['systemctl','restart']:
                n[0]+=1
                if n[0]==1:raise RuntimeError('startup failed')
            return original(args,**kw)
        with patch.object(agent,'command',command):
            with self.assertRaisesRegex(RuntimeError,'startup'):agent.apply(self.request())
        self.assertEqual(self.config.read_bytes(),self.raw);self.assertEqual(n[0],2)
    def test_semantic_noop_never_restarts(self):
        r=self.request();r['config']=copy.deepcopy(self.old)
        self.assertTrue(agent.apply(r)['ok']);self.assertFalse(self.restarts());self.assertFalse(agent.BACKUPS.exists())
    def test_geo_failure_restores_original_geo(self):
        geo=self.assets/'ru-blocked.dat';geo.write_bytes(b'OLD DATABASE');r=self.request();r['update_geo']=True
        with patch.object(agent,'fetch_geo',return_value=b'NEW DATABASE'),patch.object(agent,'checks',side_effect=RuntimeError('HTTP failed')):
            with self.assertRaises(RuntimeError):agent.apply(r)
        self.assertEqual(geo.read_bytes(),b'OLD DATABASE');self.assertEqual(self.config.read_bytes(),self.raw)
    def test_failed_new_geo_is_removed(self):
        r=self.request();r['update_geo']=True
        with patch.object(agent,'fetch_geo',return_value=b'NEW DATABASE'),patch.object(agent,'validate',side_effect=RuntimeError('invalid')):
            with self.assertRaises(RuntimeError):agent.apply(r)
        self.assertFalse((self.assets/'ru-blocked.dat').exists());self.assertFalse(self.restarts())
    def test_external_config_change_not_overwritten_on_geo_validation_failure(self):
        r=self.request();r['update_geo']=True
        def validate(*a):self.config.write_bytes(b'{"external":true}')
        with patch.object(agent,'fetch_geo',return_value=b'NEW DATABASE'),patch.object(agent,'validate',validate):
            with self.assertRaisesRegex(RuntimeError,'параллельно'):agent.apply(r)
        self.assertEqual(self.config.read_bytes(),b'{"external":true}');self.assertFalse((self.assets/'ru-blocked.dat').exists());self.assertFalse(self.restarts())
    def test_checksum_download_failure_has_no_effect(self):
        r=self.request();r['update_geo']=True
        with patch.object(agent,'fetch_geo',side_effect=RuntimeError('SHA256')):
            with self.assertRaises(RuntimeError):agent.apply(r)
        self.assertEqual(self.config.read_bytes(),self.raw);self.assertFalse(agent.BACKUPS.exists())
    def test_unchanged_geo_no_restart(self):
        (self.assets/'ru-blocked.dat').write_bytes(b'SAME');r=self.request();r['update_geo']=True;r['config']=copy.deepcopy(self.old)
        with patch.object(agent,'fetch_geo',return_value=b'SAME'):self.assertTrue(agent.apply(r)['ok'])
        self.assertFalse(self.restarts())
    def test_restore_success_keeps_before_restore_backup(self):
        result=agent.apply(self.request());changed=self.config.read_bytes();r=self.request();r['expected_sha']=agent.sha(changed);r['backup_id']=result['backup']
        restored=agent.restore(r);self.assertEqual(self.config.read_bytes(),self.raw);self.assertEqual((agent.BACKUPS/restored['backup']/'config').read_bytes(),changed)
    def test_restore_wrong_paths_rejected(self):
        result=agent.apply(self.request());meta=agent.BACKUPS/result['backup']/'metadata.json';data=json.loads(meta.read_bytes());data['files']['config']['path']=str(self.root/'other');meta.write_text(json.dumps(data))
        r=self.request();r['expected_sha']=agent.sha(self.config.read_bytes());r['backup_id']=result['backup']
        with self.assertRaisesRegex(RuntimeError,'пути'):agent.restore(r)
    def test_inspection_does_not_create_files(self):
        before={str(p)for p in self.root.rglob('*')}
        result=agent.inspect_remote(self.request());self.assertTrue(result['installed']);self.assertEqual(before,{str(p)for p in self.root.rglob('*')})

if __name__=='__main__':unittest.main()
