import unittest
import credentials
import ctypes
import types
import os
from unittest.mock import patch

def require_dpapi(test):
    if os.name != 'nt': test.skipTest('DPAPI is Windows-only')
    try:credentials.protect('availability-probe','test-profile')
    except RuntimeError as e:test.skipTest('No loaded DPAPI user profile in this test session: '+str(e))

class CredentialTests(unittest.TestCase):
    def test_dpapi_roundtrip_unicode(self):
        require_dpapi(self)
        secret='пароль с пробелами / 😀'
        encrypted=credentials.protect(secret,'fixture-profile')
        self.assertNotIn(secret,encrypted)
        self.assertEqual(credentials.unprotect(encrypted,'fixture-profile'),secret)
    def test_ciphertext_bound_to_profile(self):
        require_dpapi(self)
        encrypted=credentials.protect('fixture-secret','profile-A')
        with self.assertRaises(RuntimeError):credentials.unprotect(encrypted,'profile-B')
    def test_tampered_ciphertext_rejected(self):
        require_dpapi(self)
        encrypted=credentials.protect('fixture-secret','profile-A')
        changed=encrypted[:-8]+'AAAAAAAA'
        with self.assertRaises((RuntimeError,ValueError)):credentials.unprotect(changed,'profile-A')
    def test_plaintext_rejected(self):
        with self.assertRaises(ValueError):credentials.unprotect('plaintext','fixture')

    @unittest.skipUnless(os.name == 'nt', 'DPAPI is Windows-only')
    def test_dpapi_uses_user_scope_and_frees_memory(self):
        allocations=[];seen={}
        class Function:
            def __init__(self,fn):self.fn=fn
            def __call__(self,*args):return self.fn(*args)
        def encrypt(*args):
            seen['flags']=args[5]
            inp=ctypes.cast(args[0],ctypes.POINTER(credentials.Blob)).contents
            seen['input']=ctypes.string_at(inp.data,inp.size)
            entropy=ctypes.cast(args[2],ctypes.POINTER(credentials.Blob)).contents
            seen['entropy']=ctypes.string_at(entropy.data,entropy.size)
            output=ctypes.cast(args[-1],ctypes.POINTER(credentials.Blob)).contents
            buf=ctypes.create_string_buffer(b'ENCRYPTED');allocations.append(buf)
            output.size=9;output.data=ctypes.cast(buf,ctypes.POINTER(ctypes.c_ubyte));return 1
        def free(pointer):seen['freed']=True
        library=types.SimpleNamespace(CryptProtectData=Function(encrypt))
        kernel=types.SimpleNamespace(LocalFree=Function(free))
        with patch.object(ctypes,'WinDLL',side_effect=[library,kernel]):result=credentials.crypt(b'fixture-secret','profile-A')
        self.assertEqual(result,b'ENCRYPTED');self.assertEqual(seen['flags'],1)
        self.assertIn(b'profile-A',seen['entropy']);self.assertTrue(seen['freed'])
        self.assertEqual(allocations[0].raw[:9],b'\x00'*9)

if __name__=='__main__':unittest.main()
