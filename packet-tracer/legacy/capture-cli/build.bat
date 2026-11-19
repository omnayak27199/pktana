@echo off
setlocal enabledelayedexpansion

cd /d "%~dp0"

for /f "usebackq delims=" %%v in ("VERSION") do set VERSION=%%v
set VERSION=!VERSION: =!

where cmake >nul 2>&1
if errorlevel 1 (
    echo error: cmake not found
    exit /b 1
)

cmake -S . -B build -A x64 -DCMAKE_BUILD_TYPE=Release
if errorlevel 1 exit /b 1

cmake --build build --config Release --parallel
if errorlevel 1 exit /b 1

echo.
echo Built build\Release\pktana-tracer.exe (v!VERSION!)
