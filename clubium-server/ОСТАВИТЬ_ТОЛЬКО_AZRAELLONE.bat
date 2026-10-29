@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo.
echo CLEANUP: remove all user accounts except AzraelLone.
echo The program will create a database backup first.
echo Stop the website/server before running this file.
echo.
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" keep_only_azrael.py --apply
) else (
  py -3 keep_only_azrael.py --apply
)
echo.
pause
