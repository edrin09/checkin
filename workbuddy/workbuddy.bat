@echo off
rem WorkBuddy 多账号签到 / 登录态捕获入口
rem 优先使用计划任务同一个解释器，找不到就退回 PATH 里的 python
rem
rem 用法：
rem   workbuddy.bat                每日签到（带随机延时）
rem   workbuddy.bat --no-delay     立即签到（验证 / 补签）
rem   workbuddy.bat --list         查看已捕获 / 未捕获账号
rem   workbuddy.bat --refresh      手动续期所有账号 token
rem   workbuddy.bat --watch 15     监听 15 分钟，自动捕获期间登录的账号
rem
rem PowerShell 里运行建议写成 .\workbuddy.bat
rem
set "PY=C:\uv\py3.14.8\Scripts\python.exe"
if not exist "%PY%" set "PY=python"
"%PY%" "%~dp0checkin_workbuddy.py" %*
exit /b %errorlevel%
