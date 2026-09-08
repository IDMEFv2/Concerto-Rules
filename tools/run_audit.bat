@echo off
setlocal enabledelayedexpansion
title Concerto-SIEM - IDMEFv2 rules audit

REM ============================================================
REM  Runs concerto_audit.py against a Concerto-SIEM "logstash" folder.
REM  Place this file next to concerto_audit.py and IDMEFv2.schema.
REM  Usage:
REM    - double-click: the script will ask for the logstash folder path
REM    - or drag the "logstash" folder onto this .bat file
REM ============================================================

REM --- move to this .bat folder (script + schema live here) ---
cd /d "%~dp0"

echo ==================================================
echo   Concerto-SIEM  -  IDMEFv2 rules audit
echo ==================================================
echo.

REM --- 1) is Python available? ---
where python >NUL 2>&1
if errorlevel 1 (
  echo [ERROR] Python not found.
  echo Install it from https://www.python.org/downloads/
  echo with "Add python.exe to PATH" ticked, then run this file again.
  echo.
  pause
  exit /b 1
)

REM --- 2) script and schema present? ---
if not exist "concerto_audit.py" (
  echo [ERROR] concerto_audit.py not found in this folder.
  echo Place this .bat next to concerto_audit.py and IDMEFv2.schema.
  echo.
  pause
  exit /b 1
)
if not exist "IDMEFv2.schema" (
  echo [WARNING] IDMEFv2.schema missing: conformance checking will be disabled.
  echo.
)

REM --- 3) dependencies (installed once) ---
python -c "import yaml, openpyxl, regex" 2>NUL
if errorlevel 1 (
  echo Installing dependencies ^(once, requires internet^)...
  python -m pip install --quiet pyyaml openpyxl regex
  if errorlevel 1 (
    echo [ERROR] Dependency installation failed.
    echo.
    pause
    exit /b 1
  )
)

REM --- 4) logstash folder to analyse ---
set "LOGSTASH=%~1"
if "%LOGSTASH%"=="" (
  echo Drag the "logstash" folder onto this .bat, or paste its path below.
  set /p "LOGSTASH=Path to the logstash folder: "
)
REM strip any surrounding quotes
set "LOGSTASH=%LOGSTASH:"=%"

if "%LOGSTASH%"=="" (
  echo [ERROR] No path provided.
  echo.
  pause
  exit /b 1
)

REM --- if pointed at the repository root, descend into \logstash ---
if not exist "%LOGSTASH%\rulesets" (
  if exist "%LOGSTASH%\logstash\rulesets" set "LOGSTASH=%LOGSTASH%\logstash"
)
if not exist "%LOGSTASH%\rulesets" (
  echo [ERROR] This folder contains no "rulesets" directory.
  echo Point at the "logstash" folder of Concerto-SIEM.
  echo Path given: %LOGSTASH%
  echo.
  pause
  exit /b 1
)

REM --- 5) timestamped output name (locale-proof, via PowerShell) ---
for /f %%i in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd_HHmmss"') do set "STAMP=%%i"
if "%STAMP%"=="" set "STAMP=out"
set "OUT=Concerto_Rules_Audit_%STAMP%.xlsx"

echo.
echo Folder analysed : %LOGSTASH%
echo Report written  : %OUT%
echo.

python concerto_audit.py "%LOGSTASH%" "%OUT%"
if errorlevel 1 (
  echo.
  echo [ERROR] The audit failed. Read the message above.
  echo.
  pause
  exit /b 1
)

echo.
echo Done. Opening the report...
start "" "%OUT%"
echo.
pause
