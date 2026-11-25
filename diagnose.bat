@echo off
setlocal
cd /d "%~dp0"
if not exist "Steam Mod Guardian.exe" (
  echo Run this script inside the published folder, next to Steam Mod Guardian.exe.
  pause
  exit /b 1
)
set "LOGDIR=%LOCALAPPDATA%\DuckovModGuardian"
if not exist "%LOGDIR%" mkdir "%LOGDIR%"
if not exist "%LOGDIR%" set "LOGDIR=%TEMP%\DuckovModGuardian"
if not exist "%LOGDIR%" mkdir "%LOGDIR%"
set "COREHOST_TRACE=1"
set "COREHOST_TRACE_VERBOSITY=4"
set "COREHOST_TRACEFILE=%LOGDIR%\host-trace.log"
if exist "%COREHOST_TRACEFILE%" del /q "%COREHOST_TRACEFILE%"
echo Starting Guardian. This window stays open until Guardian exits.
start "" /wait "%~dp0Steam Mod Guardian.exe"
set "RC=%ERRORLEVEL%"
echo Exit code: %RC%
> "%LOGDIR%\last-exit-code.txt" echo %RC%
echo Logs:
echo %LOGDIR%\startup.log
echo %LOGDIR%\host-trace.log
echo %LOGDIR%\last-exit-code.txt
echo If Guardian did not open, share these logs after checking personal paths.
pause
exit /b %RC%
