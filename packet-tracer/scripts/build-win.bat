@echo off
setlocal
cd /d "%~dp0.."

where npm >nul 2>nul
if errorlevel 1 (
  echo npm not found. Install Node.js 20+ from https://nodejs.org/
  exit /b 1
)

call npm install
if errorlevel 1 exit /b 1

call npm run dist:win
if errorlevel 1 exit /b 1

echo.
echo Built artifacts in dist\
endlocal
