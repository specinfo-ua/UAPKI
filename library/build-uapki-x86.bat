set DIR_ARCH=Win32
set DIR_BUILD=build

mkdir %DIR_BUILD%
cd %DIR_BUILD%
del /f /s /q *
mkdir out
cd ..

cmake -G "Visual Studio 16 2019" -A %DIR_ARCH% -S . -B %DIR_BUILD%
@rem cmake -G "Visual Studio 17 2022" -A %DIR_ARCH% -S . -B %DIR_BUILD%
@rem cmake -G "Visual Studio 18 2026" -A %DIR_ARCH% -S . -B %DIR_BUILD%
pause

cmake --build %DIR_BUILD% --config Release
pause
