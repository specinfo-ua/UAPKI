# Builds UAPKI shared libraries for Android with CMake + Android NDK (no Gradle).
#
# Usage:
#   .\build-android.ps1                       # all default ABIs, Release
#   .\build-android.ps1 -Abi arm64-v8a        # single ABI
#   .\build-android.ps1 -BuildType Debug
#
# Requirements: Android SDK with "ndk;*" and "cmake;*" packages installed
# (locations are auto-detected from ANDROID_NDK_ROOT / ANDROID_HOME /
#  %LOCALAPPDATA%\Android\Sdk).
#
# Output: library/out/android-<abi>/*.so

param(
    [string[]]$Abi = @("arm64-v8a", "armeabi-v7a", "x86_64", "x86"),
    [string]$BuildType = "Release",
    [string]$Platform = "android-28",
    [string]$NdkRoot = $null
)

$ErrorActionPreference = "Stop"
$libraryDir = $PSScriptRoot

# --- locate SDK/NDK ---
$sdkRoot = $env:ANDROID_HOME
if (-not $sdkRoot) { $sdkRoot = Join-Path $env:LOCALAPPDATA "Android\Sdk" }

if (-not $NdkRoot) { $NdkRoot = $env:ANDROID_NDK_ROOT }
if (-not $NdkRoot -and (Test-Path (Join-Path $sdkRoot "ndk"))) {
    $NdkRoot = Get-ChildItem (Join-Path $sdkRoot "ndk") -Directory |
        Sort-Object Name -Descending | Select-Object -First 1 -ExpandProperty FullName
}
if (-not $NdkRoot -or -not (Test-Path "$NdkRoot\build\cmake\android.toolchain.cmake")) {
    throw "Android NDK not found. Set ANDROID_NDK_ROOT or install via sdkmanager 'ndk;<version>'."
}

# --- locate cmake/ninja: prefer SDK-bundled, fall back to PATH ---
$cmake = "cmake"; $ninja = "ninja"
$sdkCmakeDir = Join-Path $sdkRoot "cmake"
if (Test-Path $sdkCmakeDir) {
    $latest = Get-ChildItem $sdkCmakeDir -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if ($latest) {
        $cmake = Join-Path $latest.FullName "bin\cmake.exe"
        $ninja = Join-Path $latest.FullName "bin\ninja.exe"
    }
}

Write-Host "NDK:   $NdkRoot"
Write-Host "CMake: $cmake"

foreach ($a in $Abi) {
    $buildDir = Join-Path $libraryDir "..\build-android\$a"
    Write-Host "`n=== $a ($BuildType, $Platform) ===" -ForegroundColor Cyan

    & $cmake -G Ninja -S $libraryDir -B $buildDir `
        -DCMAKE_TOOLCHAIN_FILE="$NdkRoot\build\cmake\android.toolchain.cmake" `
        -DANDROID_ABI="$a" `
        -DANDROID_PLATFORM="$Platform" `
        -DCMAKE_BUILD_TYPE="$BuildType" `
        -DCMAKE_MAKE_PROGRAM="$ninja"
    if ($LASTEXITCODE -ne 0) { throw "CMake configure failed for $a" }

    & $cmake --build $buildDir
    if ($LASTEXITCODE -ne 0) { throw "Build failed for $a" }
}

Write-Host "`nDone. Artifacts in library/out/android-<abi>/" -ForegroundColor Green
