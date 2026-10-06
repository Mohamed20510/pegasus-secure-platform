@echo off
title PEGASUS Desktop Launcher
color 0B

echo ====================================================================
echo          PEGASUS - Secure Software Intelligence Platform           
echo ====================================================================
echo.

:: 1. Pre-Flight Cleanup: Ensure ports 8000 and 3000 are not locked
echo [*] Cleaning up old background processes...
taskkill /F /IM python.exe >nul 2>&1
taskkill /F /IM node.exe >nul 2>&1
taskkill /F /IM electron.exe >nul 2>&1

:: 2. Start Backend safely without hardcoded credentials
echo [1/3] Starting Python Backend (Port 8000)...
start "PEGASUS Backend" /D "D:\Final project\secure-platform\backend" /min cmd /c "set DATABASE_URL=sqlite:///./ssp.db && uvicorn app.main:app --reload --port 8000"

:: 3. Start Frontend using /D to prevent nested-quote syntax errors
echo [2/3] Starting Next.js UI Server (Port 3000)...
start "PEGASUS Frontend" /D "D:\Final project\secure-platform\frontend" /min cmd /c "npm run dev"

:: 4. Wait 7 seconds for Next.js to compile (it takes ~5.1s to report Ready)
echo [3/3] Waiting for servers to initialize (7 seconds)...
timeout /t 7 /nobreak >nul

:: 5. Launch the Native Desktop Window via Electron binary
echo.
echo [*] Launching Native Desktop Window...
cd /d "D:\Final project\secure-platform\frontend"
"node_modules\electron\dist\electron.exe" desktop.js

:: 6. Clean Exit: Shut down background servers when the desktop window is closed
echo.
echo [*] Desktop window closed. Terminating background services...
taskkill /F /IM python.exe >nul 2>&1
taskkill /F /IM node.exe >nul 2>&1
taskkill /F /IM electron.exe >nul 2>&1

exit