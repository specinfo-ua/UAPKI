# UAPKI

The UAPKI is crypto library for using in PKI with support of Ukrainian and internationlal cryptographic standards.
Fork of [Cryptonite](https://github.com/privat-it/cryptonite).

[Expert conclusion on the results of the Ukrainian state expertise in the field of cryptographic protection of information No 04/05/02-2096 from 21.07.2021](https://data.gov.ua/dataset/7b0d45fe-75eb-4d14-9792-59e440305678).

## Branches

+ main. Development of version 3.x (work in progress, API may change).
+ v2. Stable version 2.x, bug fixes only.

## Project structure

+ library. Directory contains c/cpp libraries and applications of The UAPKI Project
  + uapkic. Library of cryptoprimitives (symmetric and strem ciphers, hashes, MACs, signatures etc.)
  + uapkif. Library provides ASN.1 encoder/decoder, implements parsing and constructing most of ASN.1 encoded cryptographic data.
  + cm-*. Libraries that provides work with secure storages of private keys. This is private key isolation level.
  + uapki. Main library with JSON that implements interface for message signing and verification, private key and CSR generation, crtificate verification and other.
  + test. Application for testing library and use as examples of library calls.
  + hostapp. Native messaging host for communicate library with web pages in modern browsers.
+ apps. Directory contains applications built on the library (see [apps/README.md](apps/README.md)).
+ integration. Directory contains components for embedding library into applications developed with other programming languages.
+ doc. Directory contains manual for developers.

## Supported cryptographic algorithms

+ Digital signatures: DSTU 4145-2002, ECDSA, RSA, EC-GDSA, EC-RDSA, SM2-DSA
+ Hashes: DSTU 7564:2014 (Kupyna), GOST 34.311-95, MD5, SHA1, SHA2, SHA3, WHIRLPOOL, RIPEMD, GOST R 34.11-2012, SM3
+ HMACs based at all hashes
+ Symmetric ciphers: DSTU 7624:2014 (Kalyna), DSTU 8845:2019 (Strumok), GOST 28147-89 (Magma), AES, DES, TDES
+ Asymmetric ciphers: RSA
+ Key agreement: ECDH

## Supported platforms

+ Microsoft Windows x86 and x86-64 (Windows Vista / Server 2008 or later)
+ Linux x86-64, armv7 (32 bit), armv8 (64 bit) (kernel 3.17 or later)
+ FreeBSD x86-64, armv8 (FreeBSD 12 or later)
+ Apple macOS x86-64, armv8 (Apple M1) (macOS 10.12 or later)
+ Apple iOS, iPadOS armv8 (iOS 10 or later)
+ Google Android armv8, x86-64 (Android 9, API level 28 or later)
+ WebAssembly: browsers and Node.js with Web Crypto API (built with Emscripten 2.0.5 or later)

The minimum versions are determined by the operating system entropy source used by the library: BCryptGenRandom (Windows), getrandom (Linux, Android), getentropy (macOS, iOS, FreeBSD, WebAssembly). There is no fallback to /dev/urandom.

## Telegram group for developers
https://t.me/joinchat/UTjOABGHYxEqUYDp

# License
See [LICENSE](LICENSE) file.

# Authors
See [AUTHORS](AUTHORS) file.
