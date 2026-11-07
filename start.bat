@echo off
REM One-click start for Windows.
REM Put the unzipped llama.cpp folder anywhere inside this project folder (e.g. .\llama)
REM and the .gguf model file inside .\models
cd /d "%~dp0"

set "LLAMA="
for /r %%F in (llama-server.exe) do if exist "%%F" if not defined LLAMA set "LLAMA=%%F"
if not defined LLAMA (
  echo [ERROR] llama-server.exe not found. Unzip llama.cpp into this folder, e.g. %~dp0llama
  pause & exit /b 1
)

set "MODEL="
for %%M in (models\*.gguf) do if not defined MODEL set "MODEL=%%~fM"
if not defined MODEL (
  echo [ERROR] No .gguf model found in %~dp0models
  pause & exit /b 1
)

echo Using llama-server: %LLAMA%
echo Using model:        %MODEL%
start "llama-server (local model)" "%LLAMA%" -m "%MODEL%" -c 2048 -t 2 --parallel 1 --port 8080 --jinja

if not exist .venv (
  echo Creating Python environment...
  python -m venv .venv || (echo [ERROR] Python not found. Install Python 3.10+ and tick "Add to PATH". & pause & exit /b 1)
)
call .venv\Scripts\activate
pip install -q -r requirements.txt

echo.
echo Waiting for the model to load...
timeout /t 15 /nobreak >nul
start "" http://127.0.0.1:8000
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
pause
