@echo off
rem Trae 多账号签到 / 命令行登录入口
rem 优先使用计划任务同一个解释器，找不到就退回 PATH 里的 python
rem
rem 用法：
rem   trae.bat                每日签到（带随机延时）
rem   trae.bat --login        命令行加账号（打开浏览器登录，写入 accounts.json）
rem   trae.bat --no-delay     立即签到（验证 / 补签）
rem   trae.bat --list         查看已捕获账号
rem   trae.bat --watch 15     监听 15 分钟，自动捕获期间登录 / 切换的账号
rem   trae.bat --status-only  只查状态，不领取
rem
rem PowerShell 里运行建议写成 .\trae.bat
rem
set "PY=C:\uv\py3.14.8\Scripts\python.exe"
if not exist "%PY%" set "PY=python"
"%PY%" "%~dp0checkin_trae.py" %*
exit /b %errorlevel%
