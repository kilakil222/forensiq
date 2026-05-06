@echo off
setlocal

set "SRCDIR=%~dp0"
set "SRCDIR=%SRCDIR:~0,-1%"

cd /d "%SRCDIR%"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SRCDIR%\install.ps1"
