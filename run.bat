@echo off
REM Start the backend (llama-server must already be running on port 8080)
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
