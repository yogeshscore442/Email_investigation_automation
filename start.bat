@echo off
setlocal enabledelayedexpansion
title PhishScope SOC - AI Email Investigation Platform
color 0A

:: Ensure script runs from its own directory
cd /d "%~dp0"

echo ===============================================================================
echo          PhishScope SOC - AI Email Investigation and Detection Platform
echo ===============================================================================
echo.

:: 1. Clean up any previous stale processes on ports 5000 & 5173
echo [*] Checking and cleaning existing processes on ports 5000 and 5173...
powershell -NoProfile -Command "$p = (Get-NetTCPConnection -LocalPort 5000,5173 -ErrorAction SilentlyContinue).OwningProcess; if ($p) { Stop-Process -Id $p -Force -ErrorAction SilentlyContinue }" >nul 2>&1
for /f "tokens=5" %%p in ('netstat -ano 2^>nul ^| findstr ":5000 "') do taskkill /F /PID %%p >nul 2>&1
for /f "tokens=5" %%p in ('netstat -ano 2^>nul ^| findstr ":5173 "') do taskkill /F /PID %%p >nul 2>&1

:: 2. Check Python
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    color 0C
    echo [!] Python is not installed or not found on PATH.
    echo     Please install Python 3.10+ and add it to your system PATH.
    echo.
    pause
    exit /b 1
)

:: 3. Check Node / npm
call npm --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    color 0C
    echo [!] Node.js / npm is not installed or not found on PATH.
    echo     Please install Node.js 18+ and npm.
    echo.
    pause
    exit /b 1
)

echo [+] Python and Node.js detected successfully.
echo.

:: 4. Check frontend node_modules
if not exist "frontend\node_modules" (
    echo [*] First time setup: Installing frontend dependencies [npm install]...
    cd frontend
    call npm install
    cd ..
    echo [+] Frontend dependencies installed.
    echo.
)

:: 5. Start Backend Server (Flask on port 5000)
echo [*] Starting Backend REST API (Flask on http://127.0.0.1:5000)...
start "PhishScope SOC - Backend (Port 5000)" /D "%~dp0backend" /min cmd /k "python run.py"

:: 6. Start Frontend Server (React Vite on port 5173)
echo [*] Starting Frontend UI (Vite on http://127.0.0.1:5173)...
start "PhishScope SOC - Frontend (Port 5173)" /D "%~dp0frontend" /min cmd /k "call npm run dev -- --host 127.0.0.1 --port 5173"

:: 7. Poll until Frontend UI is live and responding (up to 20 seconds)
echo [*] Initializing application services and waiting for dashboard...
powershell -NoProfile -Command "$ready = $false; for ($i = 0; $i -lt 40; $i++) { Start-Sleep -Milliseconds 500; try { if ((Invoke-WebRequest -Uri 'http://127.0.0.1:5173' -UseBasicParsing -TimeoutSec 1).StatusCode -eq 200) { $ready = $true; break } } catch {} }; if (-not $ready) { exit 1 }" >nul 2>&1

echo.
echo ===============================================================================
echo  [+] Services successfully started!
echo      - Web Dashboard : http://127.0.0.1:5173
echo      - Backend API   : http://127.0.0.1:5000
echo ===============================================================================
echo.
echo [*] Opening PhishScope SOC Dashboard in your default browser...
start http://127.0.0.1:5173

echo.
echo  -----------------------------------------------------------------------------
echo   The application is running. Leave this window open while using PhishScope.
echo   Press ANY KEY in this window to stop all services.
echo  -----------------------------------------------------------------------------
echo.
pause >nul

echo.
echo [*] Stopping all PhishScope SOC services...
powershell -NoProfile -Command "$p = (Get-NetTCPConnection -LocalPort 5000,5173 -ErrorAction SilentlyContinue).OwningProcess; if ($p) { Stop-Process -Id $p -Force -ErrorAction SilentlyContinue }" >nul 2>&1
for /f "tokens=5" %%p in ('netstat -ano 2^>nul ^| findstr ":5000 "') do taskkill /F /PID %%p >nul 2>&1
for /f "tokens=5" %%p in ('netstat -ano 2^>nul ^| findstr ":5173 "') do taskkill /F /PID %%p >nul 2>&1

echo [+] All services stopped cleanly.
powershell -NoProfile -Command "Start-Sleep -Seconds 2" >nul 2>&1
exit /b 0
