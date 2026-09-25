@echo off
taskkill /F /IM clash-verge-service.exe >nul 2>&1
taskkill /F /IM verge-mihomo.exe >nul 2>&1
taskkill /F /IM "Clash Verge.exe" >nul 2>&1
timeout /t 4 /nobreak >nul
del /F /Q "%APPDATA%\io.github.clash-verge-rev.clash-verge-rev\clash-verge-check.yaml" >nul 2>&1
start "" /MIN "D:\program files\Clash Verge\resources\clash-verge-service.exe"
timeout /t 3 /nobreak >nul
echo DONE
