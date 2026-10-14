@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install-DroidboardCertificate.ps1"
if errorlevel 1 (
  echo.
  echo Certificate installation was not completed.
  pause
  exit /b 1
)
echo.
pause
