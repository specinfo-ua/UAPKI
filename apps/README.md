# UAPKI Apps

Applications built on the UAPKI libraries.

| App | Purpose |
|---|---|
| `tsp-checker` | Sends a TSP request to a time-stamping service and checks the response: status, TSTInfo against the request, signature of the time-stamp token. |
| `ocsp-checker` | Sends an OCSP request for a certificate and checks the response: status, nonce, signature of the response. |
| `gost34311`, `kupyna256` | Hash files with GOST 34.311-95 or DSTU 7564:2014 (Kupyna-256); output is compatible with `md5sum`. |

The checkers verify the response signature with the certificate from the response, or with the one given by `--responder-cert <FILE>` (PEM or DER) when the response does not contain it. The validity of the responder certificate itself is not checked.

## Build

Standalone (the `uapkic` and `uapkif` libraries are built from `../library`):

```sh
cmake -S apps -B build/apps
cmake --build build/apps --config Release
```

Binaries are copied to `apps/out` next to the libraries. As part of another CMake project that already has the `uapkic` and `uapkif` targets, add `add_subdirectory(<path>/apps apps)`; binaries then go to `${OUT_DIR}` of that project.

`tsp-checker` and `ocsp-checker` need libcurl: on Windows the prebuilt one from `library/common/curl` is used, on other platforms the system one.

## Examples

```sh
tsp-checker --url http://acskidd.gov.ua/services/tsp/ --cert-req
tsp-checker --url http://timestamp.digicert.com --digest-algo sha256 --cert-req --save-pem tsa.pem
ocsp-checker --cert user.cer --nonce-len 20
ocsp-checker --cert user.cer --responder-cert ca.pem
kupyna256 file1.bin file2.bin
gost34311 --base64 file.bin
```

Run any app with `--help` for the full list of options. Exit code is 0 on success.
