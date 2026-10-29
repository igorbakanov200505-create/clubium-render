@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (set "PY=py -3") else (set "PY=python")
%PY% -m venv .venv
if errorlevel 1 (echo Python 3.11+ not found. & pause & exit /b 1)
call .venv\Scripts\activate.bat
python -m pip install -q -r requirements.txt
if errorlevel 1 (echo Failed to install dependencies & pause & exit /b 1)
python bootstrap.py
if errorlevel 1 (echo Database setup failed & pause & exit /b 1)
echo.
echo OPEN http://127.0.0.1:8000
python -m uvicorn app:app --host 127.0.0.1 --port 8000
pause
