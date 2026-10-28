$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
py -3.12 -m venv .venv
if ($LASTEXITCODE -ne 0) { throw 'Для сборки установите Python 3.12 x64 с tkinter.' }
& '.\.venv\Scripts\python.exe' -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw 'Не удалось установить зависимости.' }
& '.\.venv\Scripts\python.exe' -m PyInstaller --noconfirm --onefile --windowed --noupx --name VLESS-Manager --icon resources/app.ico --version-file resources/version_info.txt --add-data 'resources;resources' --collect-all paramiko --paths . main.py
if ($LASTEXITCODE -ne 0) { throw 'Сборка не завершилась.' }
Write-Host 'Готово: dist\VLESS-Manager.exe'
