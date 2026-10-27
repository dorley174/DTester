$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
if (-not (Test-Path '.venv\Scripts\python.exe')) { py -3 -m venv .venv }
& '.venv\Scripts\python.exe' -m pip install -r requirements.txt
if (-not $env:TOKEN_SECRET) { $env:TOKEN_SECRET = [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N') }
if (-not $env:TEACHER_INVITE) { $env:TEACHER_INVITE = Read-Host 'Задай секретный код регистрации учителя' }
if (-not $env:ALLOW_UNSAFE_RUNNER) { $env:ALLOW_UNSAFE_RUNNER = '1' }
Write-Host 'API: http://127.0.0.1:8000' -ForegroundColor Green
Write-Host 'Сайт: http://127.0.0.1:5500' -ForegroundColor Green
$frontend = Join-Path $PSScriptRoot '..\frontend'
Start-Process -FilePath 'py' -ArgumentList @('-3','-m','http.server','5500','--directory',$frontend)
Start-Sleep -Seconds 2
Start-Process 'http://127.0.0.1:5500'
Write-Warning 'Runner без Docker не изолирует код. Не открывай API в интернет для незнакомых пользователей.'
& '.venv\Scripts\python.exe' -m uvicorn main:app --host 127.0.0.1 --port 8000
