@echo off
REM 双击我:启动 youkai 控制台(自动拉起 PostgreSQL、建库、配环境、开浏览器)。
REM youkaid.exe 是服务端不是 GUI,不要直接双击它;双击本文件。
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\start-youkai.ps1"
if errorlevel 1 pause
