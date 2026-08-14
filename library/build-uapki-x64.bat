set DIR_ARCH=x64
set DIR_BUILD=build

mkdir %DIR_BUILD%
cd %DIR_BUILD%
del /f /s /q *
mkdir out
cd ..

cmake -A %DIR_ARCH% -S . -B %DIR_BUILD%
cmake --build %DIR_BUILD% --config Release
pause
