@echo off
setlocal enabledelayedexpansion

set DIR_ARCH=ARM64
set DIR_BUILD=build
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"

if not exist "%VSWHERE%" (
    echo [ERROR] vswhere.exe not found at "%VSWHERE%"
    echo Visual Studio Installer does not appear to be installed.
    exit /b 1
)

for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationVersion`) do set "VSFULLVER=%%i"
for /f "tokens=1 delims=." %%v in ("%VSFULLVER%") do set "VSMAJOR=%%v"

set "VSYEAR="
if "%VSMAJOR%"=="15" set "VSYEAR=2017"
if "%VSMAJOR%"=="16" set "VSYEAR=2019"
if "%VSMAJOR%"=="17" set "VSYEAR=2022"
if "%VSMAJOR%"=="18" set "VSYEAR=2026"
 
if not defined VSYEAR (
    echo [ERROR] Unknown Visual Studio major version: %VSMAJOR%
    echo Please add a mapping for this version in build.bat, or pass -G manually.
    exit /b 1
)

set "GENERATOR=Visual Studio %VSMAJOR% %VSYEAR%"

echo Detected: %GENERATOR%

mkdir %DIR_BUILD%
cd %DIR_BUILD%
del /f /s /q *
mkdir out
cd ..

cmake -G "%GENERATOR%" -A %DIR_ARCH% -S . -B %DIR_BUILD%
cmake --build %DIR_BUILD% --config Release
pause
