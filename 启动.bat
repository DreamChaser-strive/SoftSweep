@echo off
setlocal EnableExtensions
chcp 936 >nul
title SoftSweep 净软
cd /d "%~dp0"

set "SOFTSWEEP_HOME=%~dp0"
set "SOFTSWEEP_LAUNCHER=%~f0"
set "SOFTSWEEP_APP_ARGS="
if defined SOFTSWEEP_NO_BROWSER set "SOFTSWEEP_APP_ARGS=--no-browser"

rem 普通权限会漏掉部分系统软件和注册表信息。默认自动请求 UAC。
if defined SOFTSWEEP_NO_ELEVATE goto :find_python
fltmc >nul 2>&1
if not errorlevel 1 goto :find_python

echo.
echo  SoftSweep 需要管理员权限才能完整扫描系统软件。
echo  正在请求管理员权限，请在 UAC 窗口中点击“是”...
echo.
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { Start-Process -FilePath $env:SOFTSWEEP_LAUNCHER -Verb RunAs -ErrorAction Stop; exit 0 } catch { exit 2 }"
if not errorlevel 1 exit /b 0
echo.
echo  未获得管理员权限，将以普通权限启动。
echo  部分系统级软件、HKLM 注册表和 Program Files 目录可能无法读取或清理。
echo.

:find_python
set "PYW="
set "PY_EXTRA="
if defined SOFTSWEEP_PYTHON call :try_python "%SOFTSWEEP_PYTHON%"
if defined PYW goto :launch
call :try_python "%SOFTSWEEP_HOME%.venv\Scripts\pythonw.exe"
if defined PYW goto :launch
call :try_python "%SOFTSWEEP_HOME%.runtime\pythonw.exe"
if defined PYW goto :launch
for /f "delims=" %%I in ('where pythonw.exe 2^>nul') do call :try_python "%%I"
if defined PYW goto :launch
for /f "delims=" %%I in ('where python.exe 2^>nul') do call :try_python "%%~dpIpythonw.exe"
if defined PYW goto :launch
for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python3*") do call :try_python "%%~fD\pythonw.exe"
if defined PYW goto :launch
for /d %%D in ("%ProgramFiles%\Python3*") do call :try_python "%%~fD\pythonw.exe"
if defined PYW goto :launch
for /d %%D in ("C:\Python3*") do call :try_python "%%~fD\pythonw.exe"
if defined PYW goto :launch
for /d %%D in ("D:\Python*") do call :try_python "%%~fD\pythonw.exe"
if defined PYW goto :launch
for /f "delims=" %%I in ('where pyw.exe 2^>nul') do (
  py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)" >nul 2>&1
  if not errorlevel 1 (
    set "PYW=%%I"
    set "PY_EXTRA=-3"
  )
)
if defined PYW goto :launch

echo.
echo  [错误] 没有找到 Python 3.10 或更高版本。
echo.
echo  请先安装 64 位 Python 3.10+：
echo    https://www.python.org/downloads/windows/
echo  安装时请勾选“Add python.exe to PATH”，然后重新双击 启动.bat。
echo.
echo  如果已经安装，可以设置环境变量 SOFTSWEEP_PYTHON，指向 pythonw.exe。
echo.
pause
exit /b 1

:try_python
if defined PYW exit /b 0
set "CANDIDATE=%~1"
if not exist "%CANDIDATE%" exit /b 0
"%CANDIDATE%" -c "import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)" >nul 2>&1
if errorlevel 1 exit /b 0
set "PYW=%CANDIDATE%"
exit /b 0

:launch
echo.
echo  正在启动 SoftSweep...
start "" "%PYW%" %PY_EXTRA% "%SOFTSWEEP_HOME%app.py" %SOFTSWEEP_APP_ARGS% >nul 2>&1
exit /b 0
