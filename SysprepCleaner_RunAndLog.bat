@echo off
setlocal

set "SCRIPT=%~dp0sysprep_cleaner.ps1"
if not exist "%SCRIPT%" (
  echo [ERREUR] sysprep_cleaner.ps1 introuvable dans "%~dp0"
  pause
  exit /b 1
)

set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%PS%" set "PS=powershell.exe"

set "LOGDIR=%~dp0logs"
if not exist "%LOGDIR%" md "%LOGDIR%" >nul 2>&1
for /f %%A in ('powershell -NoLogo -NoProfile -Command "(Get-Date).ToString(\"yyyyMMdd-HHmmss\")"') do set "TS=%%A"
set "TRANSCRIPT=%LOGDIR%\run-%TS%.log"

"%PS%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" -Yes -RunSysprep -TranscriptPath "%TRANSCRIPT%" %*

endlocal
exit /b %ERRORLEVEL%

