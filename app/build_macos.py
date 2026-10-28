"""Native macOS build, verification and distribution; run via build_macos.command."""
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

def run(*args, **kwargs):
    print('+', ' '.join(map(str, args)), flush=True)
    return subprocess.run(list(map(str, args)), check=True, **kwargs)

def main():
    if sys.platform != 'darwin':
        raise SystemExit('Сборка .app выполняется только на macOS.')
    root = Path(__file__).resolve().parent
    os.chdir(root)
    architecture = platform.machine()
    if architecture not in ('arm64', 'x86_64'):
        raise SystemExit('Неизвестная архитектура Python: ' + architecture)
    from main import APP_VERSION
    run(sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-v')
    run(sys.executable, '-m', 'PyInstaller', '--noconfirm', '--windowed', '--onedir',
        '--noupx', '--name', 'VLESS Manager', '--icon', 'resources/app.icns',
        '--osx-bundle-identifier', 'local.vlessmanager.desktop',
        '--target-architecture', architecture, '--add-data', 'resources:resources',
        '--collect-all', 'paramiko', '--collect-all', 'keyring',
        '--hidden-import', 'keyring.backends.macOS', '--paths', '.', 'main.py')
    app = root / 'dist' / 'VLESS Manager.app'
    # Changing bundle metadata invalidates PyInstaller's ad-hoc signature.
    import plistlib
    plist_path = app / 'Contents' / 'Info.plist'
    info = plistlib.loads(plist_path.read_bytes())
    info.update(CFBundleShortVersionString=APP_VERSION, CFBundleVersion=APP_VERSION,
                NSHighResolutionCapable=True)
    plist_path.write_bytes(plistlib.dumps(info))
    run('/usr/bin/codesign', '--force', '--deep', '--sign', '-', app)
    run('/usr/bin/codesign', '--verify', '--deep', '--strict', app)
    with tempfile.TemporaryDirectory(prefix='vless-manager-smoke-') as temp:
        report = Path(temp) / 'smoke.json'
        env = dict(os.environ, VLESS_MANAGER_DATA=str(Path(temp) / 'profiles'))
        run(app / 'Contents' / 'MacOS' / 'VLESS Manager', '--self-test', report,
            env=env, timeout=60)
        state = json.loads(report.read_text(encoding='utf-8'))
        if not state.get('ok') or not state.get('readonly_default') or len(state.get('tabs', [])) != 7:
            raise RuntimeError('Проверка запуска приложения не пройдена')
        state.update(platform='macOS', architecture=architecture,
                     keychain_live_test='not performed; system backend covered by mocks',
                     signing='ad-hoc; not notarized')
        (root / 'dist' / 'macos-validation.json').write_text(
            json.dumps(state, ensure_ascii=False, indent=2), encoding='utf-8')
    archive = root / 'dist' / f'VLESS-Manager-{APP_VERSION}-macOS-{architecture}.zip'
    # ditto preserves bundle links, executable bits, resources and metadata.
    run('/usr/bin/ditto', '-c', '-k', '--sequesterRsrc', '--keepParent', app, archive)
    print('\nГотово:', app, '\nАрхив:', archive,
          '\nПриложение можно перетащить в Applications. Сборка имеет локальную подпись; нотариализации Apple нет.')
    if not os.environ.get('CI'):
        run('/usr/bin/open', '-R', app)

if __name__ == '__main__':
    main()
