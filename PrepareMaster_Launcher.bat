@echo off
setlocal
set "SCRIPT=%~dp0prepare_master.ps1"
if not exist "%SCRIPT%" (
  echo [ERREUR] prepare_master.ps1 introuvable dans "%~dp0"
  pause
  exit /b 1
)
set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%PS%" set "PS=powershell.exe"
set "LOGDIR=%~dp0logs"
if not exist "%LOGDIR%" md "%LOGDIR%" >nul 2>&1
for /f %%A in ('powershell -NoLogo -NoProfile -Command "(Get-Date).ToString(\"yyyyMMdd-HHmmss\")"') do set "TS=%%A"
set "TRANSCRIPT=%LOGDIR%\prepare-master-%TS%.log"
echo Transcript principal : %TRANSCRIPT%
echo.
pushd "%~dp0"
"%PS%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" -TranscriptPath "%TRANSCRIPT%" %*
popd
echo.
echo Execution terminee. Transcript : %TRANSCRIPT%
echo Appuyez sur une touche pour fermer...
pause >nul
endlocal
exit /b %ERRORLEVEL%
