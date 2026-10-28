#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
finish() {
  result=$?
  if [ "$result" -ne 0 ]; then
    printf '\nСборка остановлена. Ошибка показана выше.\n'
  fi
  if [ -t 0 ]; then read -r -p 'Нажмите Enter, чтобы закрыть окно… ' || true; fi
}
trap finish EXIT
if [ "$(uname -s)" != Darwin ]; then
  echo 'Этот скрипт запускается на macOS.'; exit 1
fi
PYTHON="${VLESS_PYTHON:-python3.12}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo 'Установите Python 3.12 для macOS с python.org (включая tkinter), затем повторите запуск.'
  exit 1
fi
"$PYTHON" -c 'import sys, tkinter, platform; assert sys.version_info[:2] == (3,12), "Нужен Python 3.12"; print("Python:", platform.machine(), "Tk:", tkinter.TkVersion)'
"$PYTHON" -m venv .venv-macos
.venv-macos/bin/python -m pip install -r requirements-macos.txt
.venv-macos/bin/python build_macos.py
