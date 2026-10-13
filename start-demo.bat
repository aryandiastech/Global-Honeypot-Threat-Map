@echo off
rem Double-click to start the local demo (calls start-demo.ps1).
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start-demo.ps1" %*
pause
