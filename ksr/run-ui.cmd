@echo off
rem ===========================================================================
rem  KSR launcher
rem
rem  Two things this file must get right on Windows:
rem
rem  1) Never call bare "python". On most machines PATH resolves it to
rem     %LOCALAPPDATA%\Microsoft\WindowsApps\python.exe, which is a 0-byte
rem     Microsoft Store placeholder. It starts nothing and exits at once,
rem     so the window just flashes and disappears.
rem     Every candidate below is therefore *executed* (-c "import sys"),
rem     not merely checked for existence.
rem
rem  2) Use CRLF line endings and plain ASCII. cmd.exe fails to resolve
rem     ":labels" and multi-line "if (...)" blocks in LF-only files, and
rem     non-ASCII bytes get mangled by the OEM codepage.
rem
rem  Diagnose:  run-ui.cmd --check     (prints the chosen interpreter)
rem ===========================================================================
setlocal enabledelayedexpansion
cd /d "%~dp0.."

set "PYEXE="
set "PYARGS="

rem ---- 1) Windows Python Launcher ----
py -3 -c "import sys;sys.exit(0 if sys.version_info>=(3,10) else 1)" >nul 2>nul
if not errorlevel 1 (
  set "PYEXE=py"
  set "PYARGS=-3"
  goto found
)

rem ---- 2) Common install locations; anything that cannot run is skipped ----
for %%C in (
  "%LOCALAPPDATA%\Programs\Python\Python314\python.exe"
  "%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
  "%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
  "%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
  "%LOCALAPPDATA%\Programs\Python\Python310\python.exe"
  "%LOCALAPPDATA%\Python\bin\python.exe"
  "%ProgramFiles%\Python314\python.exe"
  "%ProgramFiles%\Python313\python.exe"
  "C:\Python314\python.exe"
  "C:\Python313\python.exe"
  "C:\Python312\python.exe"
  "%USERPROFILE%\.workbuddy\binaries\python\versions\3.13.12\python.exe"
) do (
  if not defined PYEXE (
    if exist "%%~C" (
      "%%~C" -c "import sys;sys.exit(0 if sys.version_info>=(3,10) else 1)" >nul 2>nul
      if not errorlevel 1 set "PYEXE=%%~C"
    )
  )
)

:found
if not defined PYEXE goto nopython

if /i "%~1"=="--check" (
  echo KSR interpreter: !PYEXE! !PYARGS!
  "!PYEXE!" !PYARGS! -c "import sys;print('python',sys.version.split()[0])"
  exit /b 0
)

echo Starting KSR...
echo   interpreter : !PYEXE! !PYARGS!
echo   working dir : %CD%
echo.

"!PYEXE!" !PYARGS! -m ksr ui %*
set "RC=%ERRORLEVEL%"

if not "%RC%"=="0" (
  echo.
  echo [ERROR] KSR exited with code %RC% .
  echo Run this to check the Python setup:
  echo     "%~f0" --check
  echo Stack traces are appended to: %CD%\ksr\ksr-ui-error.log
  echo.
  pause
)
exit /b %RC%

:nopython
echo.
echo [ERROR] No usable Python 3.10+ interpreter found.
echo.
echo Note: "python" on PATH is usually the Microsoft Store placeholder
echo at %%LOCALAPPDATA%%\Microsoft\WindowsApps\python.exe - a 0-byte stub
echo that does nothing. It does not count as a working Python.
echo.
echo Install Python 3.10+ from https://www.python.org/downloads/
echo and tick "Add python.exe to PATH", then run this file again.
echo.
pause
exit /b 9009
