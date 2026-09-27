@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 (
  echo Install Python 3.12 from python.org with the Python launcher enabled, then retry.
  goto :failed
)
where npm.cmd >nul 2>nul
if errorlevel 1 (
  echo Install Node.js 24 LTS from nodejs.org, reopen this script, then retry.
  goto :failed
)
if not exist ".venv\Scripts\python.exe" (
  py -3.12 -m venv .venv
  if errorlevel 1 goto :failed
)
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto :failed
call npm.cmd ci --prefix hackthehill3-website-final\website\scanly
if errorlevel 1 goto :failed
echo Setup complete. Double-click run.cmd to open Guardia.
pause
exit /b 0
:failed
echo Setup failed. See the error above.
pause
exit /b 1
