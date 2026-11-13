@echo off
REM Double-click to launch the youkai console.
REM It starts PostgreSQL, creates the db, sets the env, and opens the browser.
REM youkaid.exe is a server, NOT a GUI - do not double-click the exe; use this file.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\start-youkai.ps1"
if errorlevel 1 pause
