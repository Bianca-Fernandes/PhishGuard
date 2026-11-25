@echo off
REM Starts the PhishGuard machine learning service on http://127.0.0.1:5001
call venv\Scripts\activate
python ml_service\service.py
pause
