@echo off
echo Starting ODIVORA Home Connectivity Server...
cd /d %~dp0
call venv\Scripts\activate.bat 2>nul || call .venv\Scripts\activate.bat 2>nul
python run_server.py
pause
