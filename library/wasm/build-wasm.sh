#!/bin/sh
# Builds the browser WASM bundle (uapki.js + uapki.wasm) via Docker + Emscripten.
# Output: build-wasm/wasm/uapki.js|uapki.wasm
# (also copied to library/out/wasm/ and integration/WebAssembly/)
set -e

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
IMAGE="emscripten/emsdk:3.1.61"

docker run --rm -v "$REPO_ROOT:/src" -w /src "$IMAGE" bash -c '
set -e
emcmake cmake -S library -B build-wasm \
    -DCMAKE_BUILD_TYPE=MinSizeRel \
    -DUAPKI_LIBS_TYPE=STATIC \
    -DUAPKI_CM_PKCS12_LIB_TYPE=STATIC \
    -DUAPKI_DISABLE_COPY=ON
cmake --build build-wasm -j"$(nproc)"
'

echo
echo "Done. Serve the JSON console over HTTP, e.g.:"
echo "  python3 -m http.server 8000 --directory integration/WebAssembly"
echo "then open http://localhost:8000/console.html"
