@echo off
REM Build pktana Windows installer (.exe / portable). Same as build-window.sh.
setlocal EnableExtensions
cd /d "%~dp0..\.."

where cargo >nul 2>nul
if errorlevel 1 (
  echo cargo not found. Install Rust from https://rustup.rs/
  exit /b 1
)
where npm >nul 2>nul
if errorlevel 1 (
  echo npm not found. Install Node.js 20+ from https://nodejs.org/
  exit /b 1
)

if defined NPCAP_SDK (
  echo Using NPCAP_SDK=%NPCAP_SDK%
) else if exist "C:\Npc_SDK" (
  set "NPCAP_SDK=C:\Npc_SDK"
  echo Using NPCAP_SDK=%NPCAP_SDK%
) else (
  echo Note: if cargo fails on pcap, install Npcap SDK from https://npcap.com/#download
  echo       and set NPCAP_SDK=C:\Npc_SDK
)

echo ==^> Building native pktana.exe ^(pcap + TUI^)...
cargo build --release --features pcap,tui -p pktana-cli
if errorlevel 1 exit /b 1

if not exist "target\release\pktana.exe" (
  echo Build failed: target\release\pktana.exe not found
  exit /b 1
)

if not exist "pktana-desktop\resources\bin" mkdir "pktana-desktop\resources\bin"
copy /Y "target\release\pktana.exe" "pktana-desktop\resources\bin\pktana.exe" >nul
pktana-desktop\resources\bin\pktana.exe --version
if errorlevel 1 (
  echo Warning: could not run pktana.exe --version ^(Npcap runtime may be missing^). Continuing...
)

echo ==^> Packaging Electron Windows installer...
cd pktana-desktop
call npm install
if errorlevel 1 exit /b 1
call npm run dist:win
if errorlevel 1 exit /b 1

echo.
echo Artifacts in pktana-desktop\dist\
dir /b dist
echo.
echo Live capture tip: install Npcap from https://npcap.com/ then run as Administrator if needed.
endlocal
