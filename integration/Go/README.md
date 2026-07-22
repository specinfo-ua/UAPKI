# UAPKI Go bindings

Go bindings for the [UAPKI](https://github.com/specinfo-ua/UAPKI) library.

The native library exposes a single JSON-based entry point
(`char* process(const char* request)` / `void json_free(char*)`). This package
loads the shared library at runtime and provides:

* `Library.Process` / `Library.Call` — generic access to every UAPKI method;
* typed helpers for the most common methods: `Version`, `Init`, `Deinit`,
  `Providers`, `Open`, `CloseStorage`, `Keys`, `SelectKey`, `Sign`, `Verify`,
  `Digest`, `RandomBytes`.

Binary fields (`bytes`, certificates, …) are declared as `[]byte` in Go and
are marshalled to/from base64 automatically, matching the UAPKI JSON API.

## Platform support

| Platform | Mechanism | cgo required |
|----------|-----------|--------------|
| Windows  | `LoadLibrary`/`GetProcAddress` via `syscall` | no |
| Linux, macOS and other unixes | `dlopen`/`dlsym` | yes (only for `dlopen`) |

The shared libraries themselves (`uapki`, `uapkic`, `uapkif` and the CM
providers such as `cm-pkcs12`) are built from this repository with CMake, with
any compiler — MSVC-built DLLs work fine, since no compile-time linking against
the library is performed.

## Building the native libraries

Windows (MSVC; the bundled `libcurl.lib` import library is MSVC-only):

```powershell
cmake -S library -B build-native
cmake --build build-native --config Release --target uapki cm-pkcs12
# -> build-native\Release\{uapki,uapkic,uapkif,cm-pkcs12}.dll
```

Linux (needs `cmake`, `g++`, `make` and `libcurl4-openssl-dev` or the distro
equivalent):

```sh
cmake -S library -B build-native
cmake --build build-native --target uapki cm-pkcs12 -j"$(nproc)"
# -> build-native/uapki/libuapki.so, build-native/cm-pkcs12/libcm-pkcs12.so, ...
```

At runtime `libuapki.so` must be able to find `libuapkic.so.2`/`libuapkif.so.2`
(install them, or point `LD_LIBRARY_PATH` at `build-native/uapkic` and
`build-native/uapkif`).

Both platforms are exercised by the
[go-test.yml](../../.github/workflows/go-test.yml) CI workflow.

## Quick start

```go
package main

import (
    "fmt"
    "log"

    uapki "github.com/specinfo-ua/UAPKI/integration/Go"
)

func main() {
    lib, err := uapki.Load("uapki") // or an absolute path to uapki.dll / libuapki.so
    if err != nil {
        log.Fatal(err)
    }
    defer lib.Close()

    version, err := lib.Version()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(version.Name, version.Version)
}
```

Any method that has no typed helper is available through `Call`:

```go
var result struct {
    Certificates []struct {
        CertID string `json:"certId"`
    } `json:"certificates"`
}
err := lib.Call("LIST_CERTS", nil, &result)
```

Errors reported by the library are returned as `*uapki.Error` with the
`errorCode` and message:

```go
var uapkiErr *uapki.Error
if errors.As(err, &uapkiErr) {
    fmt.Println(uapkiErr.Code, uapkiErr.Message)
}
```

## Signing with a PKCS#12 key

See [example/main.go](example/main.go) for a complete program:

```sh
go run ./example -lib /path/to/uapki.dll -providers /path/to/providers-dir \
    -p12 key.p12 -password secret -in document.pdf
```

## Running the tests

The tests need the built native libraries:

```sh
# Windows (PowerShell)
$env:UAPKI_LIBRARY = "C:\path\to\uapki.dll"
$env:UAPKI_CM_PROVIDERS = "C:\path\to\dir-with-cm-pkcs12"   # optional, enables the signing test
go test ./...

# Linux/macOS
UAPKI_LIBRARY=/path/to/libuapki.so UAPKI_CM_PROVIDERS=/path/to/providers go test ./...
```

Tests are skipped when `UAPKI_LIBRARY` is not set and the library is not found
in the system search path.
