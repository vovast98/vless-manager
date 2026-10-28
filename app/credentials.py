"""Per-user DPAPI on Windows; explicit system Keychain backend on macOS."""
import base64
import ctypes
from ctypes import wintypes
import os
import sys

SERVICE = 'VLESSManager.SSH'

def mac_keychain():
    if sys.platform != 'darwin':
        raise RuntimeError('Пароль из Связки ключей доступен только на macOS')
    try:
        from keyring.backends.macOS import Keyring
        return Keyring()
    except Exception as exc:
        raise RuntimeError('Не удалось открыть Связку ключей macOS') from exc

def keychain_call(method, *args):
    try:
        return getattr(mac_keychain(), method)(SERVICE, *args)
    except Exception as exc:
        raise RuntimeError('Не удалось прочитать или изменить пароль в Связке ключей macOS') from exc

def forget(profile_id):
    if sys.platform == 'darwin':
        if keychain_call('get_password', profile_id) is not None:
            keychain_call('delete_password', profile_id)

class Blob(ctypes.Structure):
    _fields_ = [('size', wintypes.DWORD), ('data', ctypes.POINTER(ctypes.c_ubyte))]

def blob(data):
    buffer = ctypes.create_string_buffer(data, len(data) + 1)
    return Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))), buffer

def crypt(data, profile_id, decrypt=False):
    if os.name != 'nt': raise RuntimeError('Сохранение пароля поддерживается только в Windows')
    library = ctypes.WinDLL('crypt32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    value, value_buffer = blob(data)
    entropy, entropy_buffer = blob(('VLESSManager/password/v1:' + profile_id).encode('utf-8'))
    output = Blob()
    function = library.CryptUnprotectData if decrypt else library.CryptProtectData
    function.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p if decrypt else wintypes.LPCWSTR,
                         ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.c_void_p,
                         wintypes.DWORD, ctypes.POINTER(Blob)]
    function.restype = wintypes.BOOL
    # CRYPTPROTECT_UI_FORBIDDEN. Deliberately omit CRYPTPROTECT_LOCAL_MACHINE.
    success = function(ctypes.byref(value), None if decrypt else 'VLESS Manager SSH credential',
                       ctypes.byref(entropy), None, None, 1, ctypes.byref(output))
    if not success:
        raise RuntimeError('Windows не удалось ' + ('расшифровать' if decrypt else 'зашифровать') + ' пароль (код ' + str(ctypes.get_last_error()) + ')')
    try: return ctypes.string_at(output.data, output.size)
    finally:
        if output.data:
            ctypes.memset(output.data, 0, output.size)
            kernel.LocalFree(ctypes.cast(output.data, ctypes.c_void_p))

def protect(password, profile_id):
    if sys.platform == 'darwin':
        keychain_call('set_password', profile_id, password)
        return 'keychain-v1:' + profile_id
    return 'dpapi-v1:' + base64.b64encode(crypt(password.encode('utf-8'), profile_id)).decode('ascii')

def unprotect(value, profile_id):
    if isinstance(value, str) and value.startswith('keychain-v1:'):
        if value != 'keychain-v1:' + profile_id:
            raise ValueError('Пароль принадлежит другому профилю')
        password = keychain_call('get_password', profile_id)
        if password is None:
            raise RuntimeError('Пароль не найден в Связке ключей macOS')
        return password
    if not isinstance(value, str) or not value.startswith('dpapi-v1:'):
        raise ValueError('Неизвестный формат сохранённого пароля')
    try: raw = base64.b64decode(value[len('dpapi-v1:'):], validate=True)
    except ValueError: raise ValueError('Повреждён сохранённый пароль') from None
    return crypt(raw, profile_id, decrypt=True).decode('utf-8')
