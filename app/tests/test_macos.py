import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import credentials
import transport

class MacCredentialTests(unittest.TestCase):
    def setUp(self):
        self.records = {}
        self.backend = Mock()
        self.backend.set_password.side_effect = lambda service, account, secret: self.records.__setitem__((service, account), secret)
        self.backend.get_password.side_effect = lambda service, account: self.records.get((service, account))
        self.backend.delete_password.side_effect = lambda service, account: self.records.pop((service, account))
        self.platform = patch.object(credentials.sys, 'platform', 'darwin')
        self.factory = patch.object(credentials, 'mac_keychain', return_value=self.backend)
        self.platform.start(); self.factory.start()
        self.addCleanup(self.platform.stop); self.addCleanup(self.factory.stop)

    def test_reference_contains_no_password_and_restores_unicode(self):
        value = credentials.protect('пароль 😀', 'profile-A')
        self.assertEqual(value, 'keychain-v1:profile-A')
        self.assertEqual(credentials.unprotect(value, 'profile-A'), 'пароль 😀')

    def test_profile_isolation_and_reference_validation(self):
        a = credentials.protect('first', 'A')
        b = credentials.protect('second', 'B')
        self.assertEqual(credentials.unprotect(a, 'A'), 'first')
        self.assertEqual(credentials.unprotect(b, 'B'), 'second')
        with self.assertRaises(ValueError): credentials.unprotect(a, 'B')

    def test_forget_and_missing_secret(self):
        value = credentials.protect('secret', 'A')
        credentials.forget('A'); credentials.forget('A')
        self.backend.delete_password.assert_called_once_with(credentials.SERVICE, 'A')
        with self.assertRaises(RuntimeError): credentials.unprotect(value, 'A')

    def test_failure_has_no_plaintext_fallback(self):
        self.backend.set_password.side_effect = Exception('sensitive backend detail')
        with self.assertRaises(RuntimeError) as caught: credentials.protect('secret', 'A')
        self.assertNotIn('sensitive backend detail', str(caught.exception))
        self.assertEqual(self.records, {})

    def test_macos_data_location_and_override(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {}, clear=True), patch.object(Path, 'home', return_value=Path(directory)):
                self.assertEqual(transport.data_dir(), Path(directory) / 'Library' / 'Application Support' / 'VLESSManager')
            with patch.dict(os.environ, {'VLESS_MANAGER_DATA': directory}):
                self.assertEqual(transport.data_dir(), Path(directory))

if __name__ == '__main__': unittest.main()
