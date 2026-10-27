@echo off
REM Double-click this file (Windows) to install Flask and start the website.
cd /d "%~dp0"
where python >nul 2>&1
if %errorlevel%==0 (set PY=python) else (set PY=py)
%PY% -m pip install -r requirements.txt
start "" cmd /c "timeout /t 3 >nul & start http://127.0.0.1:5000"
%PY% app.py
pause
