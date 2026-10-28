import base64
import gc
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch
import main
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from test_core import config

class GuiTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.env=patch.dict(os.environ,{'VLESS_MANAGER_DATA':self.tmp.name});self.env.start()
        # The Windows test runner uses an offline sandbox account without a loaded
        # DPAPI profile. Exercise GUI persistence with an authenticated test cipher;
        # the separate credential tests exercise the DPAPI boundary itself.
        def fixture_crypt(data,profile_id,decrypt=False):
            aes=AESGCM(b'T'*32);aad=profile_id.encode()
            if decrypt:return aes.decrypt(data[:12],data[12:],aad)
            nonce=os.urandom(12);return nonce+aes.encrypt(nonce,data,aad)
        def fixture_protect(password, profile_id):
            return 'dpapi-v1:' + base64.b64encode(fixture_crypt(password.encode(), profile_id)).decode()
        def fixture_unprotect(value, profile_id):
            return fixture_crypt(base64.b64decode(value.split(':', 1)[1]), profile_id, True).decode()
        self.credential_patches=[patch.object(main.credentials,'protect',fixture_protect),
                                 patch.object(main.credentials,'unprotect',fixture_unprotect),
                                 patch.object(main.credentials,'forget')]
        for item in self.credential_patches:item.start()
        self.message_patch=patch.object(main.messagebox,'showerror',side_effect=AssertionError('Unexpected error dialog'));self.message_patch.start()
        self.app=main.App();self.app.withdraw();self.app.fields['host'].set('203.0.113.8');self.app.fields['name'].set('Test')
        self.app.ssh=types.SimpleNamespace(profile=self.app.profile(),close=lambda:None)
        c=config()
        self.app.fill_snapshot({'hostname':'fixture','installed':True,'config':c,'config_sha':'fixture','state_sha':None,'backups':[],'geo_present':True})
    def tearDown(self):
        self.app.destroy();self.app=None;gc.collect()
        for item in self.credential_patches:item.stop()
        self.message_patch.stop();self.env.stop();self.tmp.cleanup()
    def test_seven_tabs_and_readonly_default(self):
        self.assertEqual(len(self.app.pages),7);self.assertTrue(self.app.readonly.get())
    def test_snapshot_populates_clients_and_json(self):
        self.assertEqual(len(self.app.clients.get_children()),1);self.assertEqual(json.loads(self.app.config_editor.get('1.0','end')),config())
    def test_password_not_saved_as_plaintext(self):
        self.app.password.set('a-password-never-to-save');self.app.save_profile();text=(Path(self.tmp.name)/'profiles.json').read_text(encoding='utf-8');self.assertNotIn('a-password-never-to-save',text)
        self.assertIn('dpapi-v1:',text)
    def test_password_restored_after_restart(self):
        self.app.password.set('persistent-fixture');self.app.save_profile();self.app.destroy()
        self.app=main.App();self.app.withdraw()
        self.assertEqual(self.app.password.get(),'persistent-fixture')
    def test_profiles_keep_separate_passwords(self):
        self.app.password.set('first-fixture');self.app.save_profile();first=self.app.profiles[0].copy()
        self.app.new_profile();self.assertEqual(self.app.password.get(),'')
        self.app.fields['host'].set('203.0.113.99');self.app.password.set('second-fixture');self.app.save_profile()
        self.app.load_profile(first);self.assertEqual(self.app.password.get(),'first-fixture')
    def test_turning_off_password_storage_removes_ciphertext(self):
        self.app.password.set('temporary-fixture');self.app.save_profile()
        self.app.remember_password.set(False);self.app.save_profile()
        record=json.loads((Path(self.tmp.name)/'profiles.json').read_text(encoding='utf-8'))[0]
        self.assertNotIn('password_protected',record)
        self.app.load_profile(record);self.assertEqual(self.app.password.get(),'')
    def test_clearing_password_removes_old_ciphertext(self):
        self.app.password.set('temporary-fixture');self.app.save_profile();self.app.password.set('');self.app.save_profile()
        self.assertNotIn('password_protected',self.app.profiles[0])
    def test_disabling_storage_requests_system_credential_removal(self):
        self.app.password.set('fixture');self.app.save_profile()
        profile_id=self.app.current_id
        with patch.object(main.credentials,'forget') as forget:
            self.app.remember_password.set(False);self.app.save_profile()
        forget.assert_called_once_with(profile_id)
    def test_deleting_profile_requests_system_credential_removal(self):
        self.app.password.set('fixture');self.app.save_profile()
        profile_id=self.app.current_id
        with patch.object(main.messagebox,'askyesno',return_value=True), patch.object(main.credentials,'forget') as forget:
            self.app.delete_profile()
        forget.assert_called_once_with(profile_id)
        self.assertEqual(self.app.profiles,[])
    def test_password_metadata_not_in_remote_requests(self):
        self.app.password.set('temporary-fixture');self.app.save_profile();self.app.load_profile(self.app.profiles[0])
        p=self.app.profile();self.assertNotIn('password_protected',p);self.assertNotIn('save_password',p)
    def test_pending_job_does_not_drop_saved_password(self):
        self.app.password.set('fixture-keep');self.app.save_profile();self.app.save_pending('a'*32)
        self.app.load_profile(self.app.profiles[0]);self.assertEqual(self.app.password.get(),'fixture-keep')
    def test_changed_host_cannot_use_old_snapshot(self):
        self.app.fields['host'].set('203.0.113.99')
        with self.assertRaisesRegex(ValueError,'изменились'):self.app.need_config()
    def test_readonly_refuses_write(self):
        with patch.object(main.messagebox,'showinfo'):
            self.assertFalse(self.app.write_allowed())
    def test_frozen_controls_restore_combobox_readonly(self):
        self.app.freeze_controls();self.app.unfreeze_controls()
        self.assertIn('readonly',next(w for w in self.app.pages['Перенаправление'].winfo_children() if hasattr(w,'winfo_children') and any(isinstance(c,main.ttk.Combobox) for c in w.winfo_children())).winfo_children()[-1].state())
    def test_generated_public_key_is_valid_x25519(self):
        private=base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip('=')
        key=main.public_key(private);self.assertEqual(len(base64.urlsafe_b64decode(key+'=')),32)
    def test_overview_link_works_without_selecting_client(self):
        c=self.app.snapshot['config'];c['inbounds'][0]['streamSettings']['realitySettings']['privateKey']=base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip('=')
        with patch.object(self.app,'show_text')as display:
            self.app.overview_uri()
        uri=display.call_args.args[1]
        outbound=main.core.parse_vless(uri)['settings']['vnext'][0]
        self.assertEqual(outbound['address'],'203.0.113.8');self.assertEqual(outbound['port'],443)
        self.assertTrue(self.app.readonly.get())
    def test_overview_multiple_clients_can_choose_second(self):
        c=self.app.snapshot['config'];c['inbounds'][0]['settings']['clients'].append({'id':'87654321-1234-4234-9234-123456789abc','email':'Second','flow':'xtls-rprx-vision'})
        with patch.object(self.app,'show_client_uri')as generate:
            self.app.overview_uri()
            dialog=next(w for w in self.app.winfo_children()if isinstance(w,main.tk.Toplevel))
            table=next(w for w in dialog.winfo_children()if isinstance(w,main.ttk.Treeview))
            table.selection_set('0:1')
            controls=next(w for w in dialog.winfo_children()if isinstance(w,main.ttk.Frame))
            next(w for w in controls.winfo_children()if isinstance(w,main.ttk.Button)and w.cget('text')=='Создать ссылку').invoke()
            generate.assert_called_once_with(0,1)
    def test_overview_connection_button_is_present(self):
        def buttons(widget):
            result=[]
            for w in widget.winfo_children():
                if isinstance(w,main.ttk.Button):result.append(w.cget('text'))
                result.extend(buttons(w))
            return result
        self.assertIn('Строка подключения',buttons(self.app.pages['Обзор']))
    def test_websocket_selects_tls_and_disables_vision(self):
        self.app.install_fields['transport'].set('ws');self.app.sync_install_transport()
        self.assertEqual(self.app.install_fields['security'].get(),'tls');self.assertEqual(self.app.install_fields['flow'].get(),'')
        self.assertEqual(tuple(self.app.install_controls['security']['values']),('tls',))
    def test_xhttp_settings_enabled_and_grpc_disabled(self):
        self.app.install_fields['transport'].set('xhttp');self.app.sync_install_transport()
        self.assertEqual(str(self.app.install_controls['path']['state']),'normal')
        self.assertEqual(str(self.app.install_controls['service_name']['state']),'disabled')
    def test_tls_existing_cert_fields_enabled(self):
        self.app.install_fields['security'].set('tls');self.app.sync_install_transport()
        self.assertEqual(str(self.app.install_controls['tls_cert_file']['state']),'normal')
    def test_tls_grpc_link_works_from_overview(self):
        c=self.app.snapshot['config']
        c['inbounds'][0]=main.core.vless_profile.inbound(c['inbounds'][0],{'transport':'grpc','security':'tls','sni':'cert.example.com'},'/cert','/key')
        with patch.object(self.app,'show_text')as display:self.app.overview_uri()
        out=main.core.parse_vless(display.call_args.args[1])
        self.assertEqual(out['streamSettings']['network'],'grpc');self.assertEqual(out['streamSettings']['tlsSettings']['serverName'],'cert.example.com')

if __name__=='__main__':unittest.main()
