@echo off
title EnterpriseVMS Server
cd /d "%~dp0"
echo ===================================================
echo Starting EnterpriseVMS...
echo URL: http://127.0.0.1:5000
echo Username: admin
echo Password: Admin@123456
echo ===================================================
timeout /t 2 /nobreak >nul
start http://127.0.0.1:5000
py app.py
pause
