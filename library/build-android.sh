#!/bin/sh
# Builds UAPKI shared libraries for Android with CMake + Android NDK (no Gradle).
#
# Usage:
#   ./build-android.sh                 # all default ABIs, Release
#   ABIS="arm64-v8a" ./build-android.sh
#
# Requirements: ANDROID_NDK_ROOT set (or SDK at $HOME/Android/Sdk with ndk/),
# cmake and ninja in PATH.
#
# Output: library/out/android-<abi>/*.so

set -e

LIBRARY_DIR="$(cd "$(dirname "$0")" && pwd)"
ABIS="${ABIS:-arm64-v8a armeabi-v7a x86_64}"
BUILD_TYPE="${BUILD_TYPE:-Release}"
PLATFORM="${PLATFORM:-android-21}"

if [ -z "$ANDROID_NDK_ROOT" ]; then
    SDK_ROOT="${ANDROID_HOME:-$HOME/Android/Sdk}"
    if [ -d "$SDK_ROOT/ndk" ]; then
        ANDROID_NDK_ROOT="$SDK_ROOT/ndk/$(ls "$SDK_ROOT/ndk" | sort -V | tail -1)"
    fi
fi
if [ ! -f "$ANDROID_NDK_ROOT/build/cmake/android.toolchain.cmake" ]; then
    echo "Android NDK not found. Set ANDROID_NDK_ROOT." >&2
    exit 1
fi

echo "NDK: $ANDROID_NDK_ROOT"

for ABI in $ABIS; do
    BUILD_DIR="$LIBRARY_DIR/../build-android/$ABI"
    echo ""
    echo "=== $ABI ($BUILD_TYPE, $PLATFORM) ==="

    cmake -G Ninja -S "$LIBRARY_DIR" -B "$BUILD_DIR" \
        -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK_ROOT/build/cmake/android.toolchain.cmake" \
        -DANDROID_ABI="$ABI" \
        -DANDROID_PLATFORM="$PLATFORM" \
        -DCMAKE_BUILD_TYPE="$BUILD_TYPE"

    cmake --build "$BUILD_DIR"
done

echo ""
echo "Done. Artifacts in library/out/android-<abi>/"
