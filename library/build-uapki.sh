#!/bin/bash

MAX_JOBS=4
DEFINE_PARAMS=

if test -z "$1"
then
  echo Used default settings
else
  case "$1" in
  "linux-x64" | "freebsd-x64")
          DEFINE_PARAMS="-DUAPKI_CMAKE_ARCH=x64"
          ;;
  "linux-x64-clang" | "freebsd-x64-clang")
          export CC=clang
          export CXX=clang++
          DEFINE_PARAMS="-DUAPKI_CMAKE_ARCH=x64"
          ;;
  "linux-x64-clang12" | "freebsd-x64-clang12")
          export CC=clang-12
          export CXX=clang++-12
          DEFINE_PARAMS="-DUAPKI_CMAKE_ARCH=x64"
          ;;
  "linux-x64-gnu" | "freebsd-x64-gnu")
          export CC=gcc
          export CXX=g++
          DEFINE_PARAMS="-DUAPKI_CMAKE_ARCH=x64"
          ;;
  "linux-arm64" | "freebsd-arm64")
          DEFINE_PARAMS="-DUAPKI_CMAKE_ARCH=arm64"
          ;;
  "linux-arm64-clang" | "freebsd-arm64-clang")
          export CC=clang
          export CXX=clang++
          DEFINE_PARAMS="-DUAPKI_CMAKE_ARCH=arm64"
          ;;
  "linux-arm64-gnu" | "freebsd-arm64-gnu")
          export CC=gcc
          export CXX=g++
          DEFINE_PARAMS="-DUAPKI_CMAKE_ARCH=arm64"
          ;;
  "linux-arm64-cross-gnu" | "freebsd-arm64-cross-gnu")
          export CC=aarch64-linux-gnu-gcc
          export CXX=aarch64-linux-gnu-g++
          DEFINE_PARAMS="-DUAPKI_CMAKE_ARCH=arm64 -DUAPKI_CMAKE_CROSS=1"
          ;;
  "linux-armv7" | "freebsd-armv7")
          DEFINE_PARAMS="-DUAPKI_CMAKE_ARCH=armv7"
          ;;
  "linux-armv7-clang" | "freebsd-armv7-clang")
          export CC=clang
          export CXX=clang++
          DEFINE_PARAMS="-DUAPKI_CMAKE_ARCH=armv7"
          ;;
  "linux-armv7-gnu" | "freebsd-armv7-gnu")
          export CC=gcc
          export CXX=g++
          DEFINE_PARAMS="-DUAPKI_CMAKE_ARCH=armv7"
          ;;
  "linux-armv7-cross-gnu" | "freebsd-armv7-cross-gnu")
          export CC=arm-linux-gnueabihf-gcc
          export CXX=arm-linux-gnueabihf-g++
          DEFINE_PARAMS="-DUAPKI_CMAKE_ARCH=armv7 -DUAPKI_CMAKE_CROSS=1"
          ;;
  "macos-arm64")
          DEFINE_PARAMS="-DCMAKE_OSX_ARCHITECTURES=arm64"
          ;;
  "macos-x64")
          DEFINE_PARAMS="-DCMAKE_OSX_ARCHITECTURES=x86_64"
          ;;
  "iOS")
          DEFINE_PARAMS="-DCMAKE_OSX_ARCHITECTURES=arm64 -DCMAKE_SYSTEM_NAME=iOS"
          ;;
  *)
          echo "Undefined OS_ARCH: '$1'. Stop script"
          exit 1
          ;;
  esac
fi

echo "Build uapki-libs used define:"
echo "DEFINE_PARAMS: '$DEFINE_PARAMS'"
echo "CC: '$CC'"
echo "CXX: '$CXX'"

mkdir -p build
cd build
cmake .. $DEFINE_PARAMS
cmake --build . --config Release -j $MAX_JOBS
