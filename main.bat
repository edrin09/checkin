@echo off
rem Unified account switcher: pick the product first, then pick the account.
rem
rem   switch.bat                 pick WorkBuddy / Trae, then pick an account
rem   switch.bat w               WorkBuddy (same behaviour as the old workbuddy\switch.bat)
rem   switch.bat w --list        list accounts only
rem   switch.bat w --verify      show which account the client really reads + token check
rem   switch.bat w Edwin         switch by nickname / index / uid / uid prefix
rem   switch.bat t               Trae (same behaviour as the old trae\switch.bat)
rem   switch.bat t --list        list accounts and each client's current login
rem   switch.bat t edrin --wait  wait for Trae to exit, then switch
rem
rem Product aliases: w / wb / workbuddy / codebuddy, and t / trae.
rem
rem For other programs: switch.bat w <account> --quiet
rem After a successful switch the client that was just switched is started again
rem (Trae / WorkBuddy desktop). Add --no-launch to skip it, or --launch to force
rem it in a non-interactive call; set SWITCH_NO_LAUNCH=1 to disable it globally.
rem Exit codes: 0 ok / 1 error / 2 account not found / 3 token expired or verify failed /
rem             4 write verify failed / 5 desktop app or Trae client is running
rem
rem No argument = menu path (what a double-click does): switch.py shows a Chinese
rem product menu and loops, so after a switch you can switch another account.
rem The account list loops on its own; press Enter there to go back to the menu,
rem Enter again to quit. Scripted calls (switch.bat w <account>) exit right away.
rem
rem Keep this file ASCII-only: cmd re-reads a .bat by byte offset, and non-ASCII
rem text plus chcp makes it resume mid-line. All Chinese prompts live in switch.py
rem and the per-product switch_account.py files instead.
chcp 65001 >nul
set PYTHONUTF8=1
set "PY=C:\uv\py3.14.8\Scripts\python.exe"
if not exist "%PY%" set "PY=python"

set "PICK=%~1"
if not defined PICK goto :menu
if /i "%PICK%"=="w"         goto :wb
if /i "%PICK%"=="wb"        goto :wb
if /i "%PICK%"=="workbuddy" goto :wb
if /i "%PICK%"=="codebuddy" goto :wb
if /i "%PICK%"=="t"         goto :tr
if /i "%PICK%"=="trae"      goto :tr
echo Unknown product "%PICK%": use w (WorkBuddy) or t (Trae).
exit /b 1

:menu
rem Double-click entry: switch.py shows a Chinese menu and loops (pick product,
rem then the per-product script loops on accounts). Plain-ASCII here on purpose.
"%PY%" "%~dp0switch.py"
exit /b %errorlevel%

:wb
shift
set "ARGS="
:wb_args
if "%~1"=="" goto :wb_run
set "ARGS=%ARGS% "%~1""
shift
goto :wb_args
:wb_run
"%PY%" "%~dp0workbuddy\switch_account.py" %ARGS%
exit /b %errorlevel%

:tr
shift
set "ARGS="
:tr_args
if "%~1"=="" goto :tr_run
set "ARGS=%ARGS% "%~1""
shift
goto :tr_args
:tr_run
"%PY%" "%~dp0trae\switch_account.py" %ARGS%
exit /b %errorlevel%

