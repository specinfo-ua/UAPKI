# UAPKI

UAPKI is a cryptographic library for use in PKI with support of Ukrainian and international cryptographic standards.
Fork of [Cryptonite](https://github.com/privat-it/cryptonite).

[Expert conclusion on the results of the Ukrainian state expertise in the field of cryptographic protection of information No 04/05/02-2096 from 21.07.2021](https://data.gov.ua/dataset/7b0d45fe-75eb-4d14-9792-59e440305678).

## Project structure

+ library. This directory contains c/cpp libraries and applications of the UAPKI project.
  + uapkic. The library of cryptographic primitives (block and stream ciphers, hashes, MACs, signatures, etc.)
  + uapkif. A library which provides ASN.1 encoder/decoder, implements parsing and constructing most of ASN.1 encoded cryptographic data.
  + cm-*. Libraries which provide work with secure storages of private keys. This is a private key isolation level.
  + uapki. The main library with JSON which implements the interface for message signing and verification, private key and CSR generation, certificate verification, and more.
  + test. An application for testing the library and use as examples of library calls.
  + hostapp. A native messaging host to communicate library with web pages in modern browsers.
+ integration. This directory contains components for embedding the library into applications developed in other programming languages.
+ doc. This directory contains the manual for developers.

## Supported cryptographic algorithms

+ Digital signatures: DSTU 4145-2002, ECDSA, RSA, ECGDSA, EC-RDSA, SM2-DSA
+ Hashes: DSTU 7564:2014 (Kupyna), GOST 34.311-95, MD5, SHA-1, SHA-2, SHA-3, Whirlpool, RIPEMD, GOST R 34.11-2012, SM3
+ HMACs based on all hashes
+ Symmetric ciphers: DSTU 7624:2014 (Kalyna), DSTU 8845:2019 (Strumok), GOST 28147-89 (Magma), AES, DES, TDES
+ Asymmetric ciphers: RSA
+ Key agreement: ECDH

## Supported platforms

+ Microsoft Windows x86 and x86-64
  + Windows 7 or later
  + Windows Server 2008 R2 or later
+ Linux x86-64, armv7 (32 bit), armv8 (64 bit)
+ FreeBSD x86-64, armv8
+ Apple macOS x86-64, armv8 (Apple M1)
+ Apple iOS, iPadOS armv8
+ Google Android armv8, x86-64

## Telegram group for developers
https://t.me/joinchat/UTjOABGHYxEqUYDp

# License
See [LICENSE](LICENSE) file.

# Authors
See [AUTHORS](AUTHORS) file.
