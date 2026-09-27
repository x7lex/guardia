@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Run setup-windows.cmd first to install Guardia's dependencies.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" scripts\desktop.py
if errorlevel 1 pause
