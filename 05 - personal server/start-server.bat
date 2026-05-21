@echo off
title Personal File Server
echo ==================================================
echo   🚀 STARTING YOUR SECURE PERSONAL FILE SERVER 🚀
echo ==================================================
echo.

:: Check if Node.js is installed
where node >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Node.js was not found on your system!
    echo Please download and install Node.js from: https://nodejs.org/
    echo.
    pause
    exit /b 1
)

echo [INFO] Starting Node.js backend...
echo [INFO] Close this window when you want to stop the server.
echo.

node server.js

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Server crashed or closed with errors.
    pause
)
