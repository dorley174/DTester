@echo off
setlocal
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (
  py -3 -m venv .venv
  if errorlevel 1 python -m venv .venv
)
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt
if not exist .token_secret powershell -NoProfile -Command "[guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N') | Set-Content -NoNewline .token_secret"
if "%TOKEN_SECRET%"=="" set /p TOKEN_SECRET=<.token_secret
if "%TEACHER_INVITE%"=="" set /p TEACHER_INVITE=Задай секретный код регистрации учителя: 
if "%ALLOW_UNSAFE_RUNNER%"=="" set ALLOW_UNSAFE_RUNNER=1
echo.
echo AlgoArena API: http://127.0.0.1:8000
echo AlgoArena сайт: http://127.0.0.1:5500
start "AlgoArena Frontend" cmd /k py -3 -m http.server 5500 --directory "%~dp0..\frontend"
timeout /t 2 >nul
start http://127.0.0.1:5500
echo.
echo ВНИМАНИЕ: runner без Docker НЕ изолирует пользовательский код. Не публикуй API в интернет для незнакомых пользователей.
python -m uvicorn main:app --host 127.0.0.1 --port 8000
pause
