@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -File "%~dp0scripts\build-release.ps1"
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" echo Build failed. Review the output and startup.log.
pause
exit /b %RC%
