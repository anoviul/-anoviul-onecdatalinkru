@echo off
cd /d "%~dp0"
set COMPLUS_Version=v4.0.30319
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0helper.ps1"
set COMPLUS_Version=
pause
