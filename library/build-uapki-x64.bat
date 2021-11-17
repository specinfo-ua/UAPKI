set DIR_ARCH=x64
set DIR_BUILD=build

mkdir %DIR_BUILD%
cd %DIR_BUILD%
del /f /s /q *
mkdir out
cd ..

cmake -G "Visual Studio 16 2019" -A %DIR_ARCH% -S . -B %DIR_BUILD%
pause

cmake --build %DIR_BUILD% --config Release
pause