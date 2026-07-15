# Builds the browser WASM bundle (uapki.js + uapki.wasm) via Docker + Emscripten.
# Requires Docker Desktop. Run from anywhere:
#   powershell -File library\wasm\build-wasm.ps1
#
# Output: build-wasm\wasm\uapki.js|uapki.wasm
# (also copied to library\out\wasm\ and integration\WebAssembly\)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Image = "emscripten/emsdk:3.1.61"

Write-Host "Repo root: $RepoRoot"
Write-Host "Docker image: $Image"

docker run --rm -v "${RepoRoot}:/src" -w /src $Image bash -c @'
set -e
emcmake cmake -S library -B build-wasm \
    -DCMAKE_BUILD_TYPE=MinSizeRel \
    -DUAPKI_LIBS_TYPE=STATIC \
    -DUAPKI_CM_PKCS12_LIB_TYPE=STATIC \
    -DUAPKI_DISABLE_COPY=ON
cmake --build build-wasm -j"$(nproc)"
'@

if ($LASTEXITCODE -ne 0) {
    throw "WASM build failed (exit code $LASTEXITCODE)"
}

Write-Host ""
Write-Host "Done. JSON console: integration\WebAssembly\console.html (serve over HTTP, e.g.:"
Write-Host "  python -m http.server 8000 --directory integration\WebAssembly"
Write-Host "then open http://localhost:8000/console.html )"
