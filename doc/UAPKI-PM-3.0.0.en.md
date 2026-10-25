# UAPKI. Programmer's Manual

Languages: [Українська](UAPKI-PM-3.0.0.md) | **English**

| | |
| ------------------- | ---------- |
| Library version     | 3.0.0      |
| Document revision   | 3          |
| Revision date       | 2026-09-30 |

The version number in the document title corresponds to the version of the uapki library it describes (`project(uapki VERSION ...)` in `library/uapki/CMakeLists.txt`; returned by the VERSION method). The document revision is incremented when the description is edited without a change of the library version.

## Change history

| Revision | Date       | Changes                                                                                                                                                          |
| ------- | ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1       | —          | Initial version of the document (PDF)                                                                                                                               |
| 2       | 2026-07-16 | Conversion to Markdown. Verification against the library code v2.0.16: documented missing request/response fields and error codes, corrected field names and types, extended Appendices B, C, D. English version of the document added |
| 3       | 2026-09-30 | Library v3.0.0: sessions API (uapki_session_create, uapki_session_free, uapki_session_process) for independent library instances in one process and shared memory (uapki_session_shared_memory_create, uapki_session_shared_memory_free, uapki_session_shared_memory_process) for certificate and CRL caches shared by sessions; error codes INVALID_SESSION, INVALID_SHARED_MEMORY; the VERSION method returns the versions of the loaded uapkic and uapkif libraries; the cmProviders field in the INIT response |
| 4       | 2026-10-12 | Trusted lists (ETSI TS 119 612): the ADD_TRUST_LIST method, the trustListCache parameter of the INIT method, the fields trusted, trustListSigner, trustServices of the CERT_INFO method, the fields of the signature quality and of a time-stamp in the FULL-ETSI report by a trusted list. The field requireRevocationSignerStatus is removed from the validation policies: the status of the certificate of an OCSP responder is always required. The trust in a certificate of a trusted list is decided at a time (the sub-indication NO_CERTIFICATE_CHAIN_FOUND_NO_POE of the FULL-ETSI report). A repeated INIT returns, with the error ALREADY_INITIALIZED, the parameters the library was initialized with |
| 5       | 2026-10-24 | Signature validation: an OCSP responder given by name is the certificate with this name whose key verifies the signature of the response (the certificate of a responder is issued again with the same name); certificateRefs / revocationRefs that cannot be decoded do not stop the validation of the signature, they are not used (warnings "THE CERTIFICATE REFERENCES ARE NOT DECODED AND ARE NOT USED", "THE REVOCATION REFERENCES ARE NOT DECODED AND ARE NOT USED"); the timeStampOrderTolerance parameter of the INIT method - the accuracy of a time-stamp token without the accuracy field when the order of the time-stamps is checked. HTTP: redirects are followed (up to 5, http and https only); libcurl for Windows - 8.21.0 with TLS (Schannel). Trusted lists are recommended for signature validation (see "Trusted lists and the speed of validation"). Signature validation: an OCSP responder whose certificate is not issued by the key of the CA of the certificate being checked is recognized if it is an OCSP service of a trusted list of the same provider as the CA service and its certificate is issued by a CA service of this provider (RFC 6960, 4.2.2.2, item 1; ETSI TS 119 612, 5.5.1.1) - the field responderByTrustList of the VALIDATE_BY_OCSP_INFO structure, the warning "THE OCSP RESPONDER IS AUTHORIZED BY A TRUSTED LIST, NOT BY THE KEY OF THE CA". The field tspId of the TRUST_SERVICE structure - the registration identifier of the provider from TSPTradeName |

# General information

This document is intended for use by application developers who need to integrate electronic signature and data encryption mechanisms using public key certificates.

The UAPKI library is a component of the cryptographic information protection tool "3DA CA Client" and directly implements the functionality related to creating and verifying electronic signatures, encrypting and decrypting data using public key certificates, and other auxiliary functions. It consists of the binary files listed in Table 1 (prefixes and extensions depend on the operating system).

The library supports working with various key storage media (hereinafter — storage) that contain private keys for electronic signature and key agreement protocol, including: PKCS#12 format files, hardware and hardware-software devices for creating qualified electronic signatures, etc.

Table 1. List of binary files

| **№** | **Base file name** | **Description**                                                                                                                                                                                                                                   |
| ----- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1     | uapki                 | Main library implementing the core logic                                                                                                                                                                                      |
| 2     | uapkic                | Library of cryptographic primitives, mandatory                                                                                                                                                                                         |
| 3     | uapkif                | Library of data formats and ASN.1 syntax handling,<br>mandatory                                                                                                                                                                    |
| 4     | cm-<storage-name>     | Libraries for working with storages (hereinafter — storage providers). For example,<br>for a storage in the form of a PKCS#12 file this would be "cm-pkcs12".<br>Required when using functions that depend on<br>private keys (for example, data signing) |

The minimum operating system versions are determined by the system entropy source the library uses to seed its DRBG (there is no fallback source such as /dev/urandom):

- Microsoft Windows Vista / Windows Server 2008 or later – BCryptGenRandom (system RNG);
- Linux with kernel 3.17 or later – the getrandom system call (waits until the kernel entropy pool is initialized);
- Android 9 (API 28) or later – the getrandom system call;
- macOS 10.12, iOS/iPadOS 10 or later – getentropy;
- FreeBSD 12 or later – getentropy;
- WebAssembly (browsers and Node.js with Web Crypto API) – getentropy (crypto.getRandomValues), built with Emscripten 2.0.5 or later.

In addition to the system source, a CPU jitter based entropy source (jitterentropy) is used.

Interaction with the library is performed by calling the methods listed in Table 2. Methods are invoked via the exported library functions process and json_free (the global library instance) or uapki_session_process (an explicitly created session, see "Sessions" below); their interface is described in Table 3. All interaction with the library methods is based on the use of a text string composed according to JSON rules (hereinafter — JSON string).

The library supports multithreading, i.e. the ability to call methods simultaneously in parallel from different threads. Due to implementation specifics of the library, methods are divided into three types of multithreading support (the multithreading support type is specified in Table 2). The types describe how methods interact within one library instance (the global instance or one session); methods of different sessions are synchronized only while they use a shared process-wide resource (loading and unloading of a provider library, OPEN/CLOSE through the same provider, network requests to the same URL):

- independent (IND), do not change the internal state of the library, do not block other methods and are not blocked by other methods;

- single-threaded (ST), change the internal state of the library, can be executed only in one thread, and when called block all other single-threaded and multi-threaded methods;

- multi-threaded (MT), change the internal state of the library and, when called, may block other threads while accessing shared resources.

Table 2. List of library methods

| **№** | **Method name**    | **Short description**                                  | **Type** |
| ----- | ------------------- | -------------------------------------------------- | ------- |
| 1     | VERSION             | Library version                                  | IND      |
| 2     | INIT                | Library initialization                           | ST      |
| 3     | DEINIT              | Library shutdown (de-initialization)    | ST      |
| 4     | PROVIDERS           | List of storage providers                            | ST      |
| 5     | STORAGES            | List of storages available through the selected provider      | ST      |
| 6     | STORAGE_INFO        | Storage information                                 | ST      |
| 7     | OPEN                | Open a storage                                       | ST      |
| 8     | CLOSE               | Close a storage                                      | ST      |
| 9     | KEYS                | List of keys in the opened storage                    | ST      |
| 10    | SELECT_KEY          | Select a key                                       | ST      |
| 11    | CREATE_KEY          | Create a key                                      | ST      |
| 12    | DELETE_KEY          | Delete a key                                      | ST      |
| 13    | GET_CSR             | Get a certificate request for the current key   | ST      |
| 14    | BUILD_CSR_2PASS     | Generate a certificate request from data           | IND      |
| 15    | VERIFY_CSR          | Validate a certificate request                     | IND      |
| 16    | CHANGE_PASSWORD     | Change the password (PIN code) of a storage                     | ST      |
| 17    | INIT_KEY_USAGE      | Initialize key usage                   | ST      |
| 18    | SIGN                | Sign data using the current key      | MT      |
| 19    | BUILD_CMS_2PASS     | Generate a PKCS#7 signature from data                 | MT      |
| 20    | MODIFY_CMS          | Modify a PKCS#7 signature                         | IND      |
| 21    | AUGMENT_CMS         | Augment a CAdES signature (T, B-LT, B-LTA)        | MT      |
| 22    | VERIFY              | Verify signed data                          | MT      |
| 23    | ENCRYPT             | Encrypt data                                   | MT      |
| 24    | DECRYPT             | Decrypt data                                 | MT      |
| 25    | ADD_CERT            | Add a certificate to the certificate cache             | MT      |
| 26    | CERT_INFO           | Certificate information                          | MT      |
| 27    | GET_CERT            | Get a certificate from the certificate cache           | MT      |
| 28    | LIST_CERTS          | List of certificates in the certificate cache           | MT      |
| 29    | REMOVE_CERT         | Remove a certificate from the certificate cache          | ST      |
| 30    | VERIFY_CERT         | Certificate validation                              | MT      |
| 31    | GENERATE_CERTBUNDLE | Generate a certificate bundle                      | IND      |
| 32    | CERT_STATUS_BY_OCSP | Create an OCSP request and get an OCSP response | MT      |
| 33    | ADD_CRL             | Add a CRL to the CRL cache                             | MT      |
| 34    | CRL_INFO            | CRL information                                | MT      |
| 35    | LIST_CRLS           | List of CRLs in the CRL cache                          | MT      |
| 36    | REMOVE_CRL          | Remove outdated CRLs from the CRL cache                 | ST      |
| 37    | RANDOM_BYTES        | Generate a pseudorandom sequence           | MT      |
| 38    | DIGEST              | Data hashing                                    | IND      |
| 39    | ASN1_DECODE         | Decode DER-encoded ASN.1 data              | IND      |
| 40    | ASN1_ENCODE         | Encode data according to ASN.1 DER encoding         | IND      |
| 41    | ADD_TRUST_LIST      | Add a trusted list | MT      |
| 42    | LIST_TRUST_LISTS    | The list of the accepted trusted lists | MT      |

Table 3. List of exported library functions

| **№** | **Function name**     | **Short description**                                                        |
| ----- | --------------------- | ---------------------------------------------------------------------------- |
| 1     | process               | char* process(const char* request);                                          |
| 2     | json_free             | void json_free(char\* buf);                                                  |
| 3     | uapki_session_create  | UAPKI_SESSION* uapki_session_create(void);                                   |
| 4     | uapki_session_free    | void uapki_session_free(UAPKI_SESSION* session);                             |
| 5     | uapki_session_process | char* uapki_session_process(UAPKI_SESSION* session, UAPKI_SESSION_SHARED_MEMORY* memory, const char* request); |
| 6     | uapki_session_shared_memory_create  | UAPKI_SESSION_SHARED_MEMORY* uapki_session_shared_memory_create(void);         |
| 7     | uapki_session_shared_memory_free    | void uapki_session_shared_memory_free(UAPKI_SESSION_SHARED_MEMORY* memory);    |
| 8     | uapki_session_shared_memory_process | char* uapki_session_shared_memory_process(UAPKI_SESSION_SHARED_MEMORY* memory, const char* request); |

Functions 1–2 are declared in the header uapki-export.h, functions 3–8 in uapki-sessions-export.h.

### Function process

The function is intended for calling a library method, passing parameters to it, and obtaining the result of its execution.

### Input parameters

request — a pointer to a null-terminated JSON string in UTF8 encoding that defines the method being called and its parameters (method name, method parameters).

### Output parameters

returns a pointer to a null-terminated JSON string in UTF8 encoding containing the result of the method execution. The memory referenced by this pointer must always be released after processing using the json_free function.

### Function json_free

The function is intended for releasing the memory allocated by the process or uapki_session_process function for returning the result of a library method execution.

### Input parameters

the buf parameter is a pointer to a null-terminated JSON string in UTF8 encoding that was returned by the process or uapki_session_process function;

Output parameters:

none.

## Sessions

A session is an independent instance of the library inside one process: it has its own configuration (INIT parameters, including offline mode and proxy), its own certificate and CRL caches, its own opened storage and selected key. The function process works with the global session that is created automatically on its first call; applications that use only process and json_free need no changes.

Sessions are intended for applications that work with several storages at the same time (for example, a server that signs documents on behalf of many users): every storage is opened in its own session, and the sessions are used in parallel from different threads without waiting for each other. Within one session the methods are synchronized according to the types in Table 2, exactly as for the global session. The storage provider libraries (cm-*) are loaded once per process and shared by all sessions; the provider parameters (CMPROVIDER_PARAMS.config) are applied by the session that loads the provider first, later sessions reuse the loaded provider as it is; a provider is unloaded when the last session that uses it executes DEINIT or is freed. Several sessions may use the same certCache/crlCache directories: scanning of a directory during INIT is serialized between sessions, permanent additions and removals are ordinary file operations of each session.

Every session goes through the same method sequence as the global library: INIT, then the required methods (OPEN, SELECT_KEY, SIGN, …), then CLOSE and DEINIT. Freeing a session with uapki_session_free performs CLOSE and DEINIT automatically if they were not called.

### Function uapki_session_create

The function creates a new session.

### Input parameters

none.

### Output parameters

returns a session handle, or NULL if the session could not be created. The handle is passed to uapki_session_process and uapki_session_free.

### Function uapki_session_free

The function frees a session and all resources that belong to it (closes the opened storage, releases the caches and the provider references). The handle becomes invalid; a subsequent uapki_session_process with this handle returns the INVALID_SESSION error. If another thread is executing uapki_session_process for this session at the moment of the call, that call is completed normally and the session is freed afterwards.

### Input parameters

session — the session handle returned by uapki_session_create. NULL and already freed handles are ignored.

### Output parameters

none.

### Function uapki_session_process

The function is intended for calling a library method in the given session; the request and response formats are identical to the process function.

### Input parameters

session — the session handle returned by uapki_session_create;

memory — the shared memory handle returned by uapki_session_shared_memory_create, or NULL (see "Shared memory" below);

request — a pointer to a null-terminated JSON string in UTF8 encoding that defines the method being called and its parameters.

### Output parameters

returns a pointer to a null-terminated JSON string in UTF8 encoding containing the result of the method execution; for an invalid handle the response contains the INVALID_SESSION (or INVALID_SHARED_MEMORY) error code. The memory referenced by this pointer must always be released after processing using the json_free function.

### Example

```c
#include "uapki-sessions-export.h"

UAPKI_SESSION* session = uapki_session_create();
char* response = uapki_session_process(session, NULL, "{\"method\":\"INIT\",\"parameters\":{...}}");
json_free(response);
response = uapki_session_process(session, NULL, "{\"method\":\"OPEN\",\"parameters\":{...}}");
json_free(response);
response = uapki_session_process(session, NULL, "{\"method\":\"SIGN\",\"parameters\":{...}}");
json_free(response);
uapki_session_free(session);
```

## Shared memory

Every session keeps its own certificate and CRL caches; with many sessions and large caches (thousands of CRLs) this multiplies the same data in RAM. A shared memory is an object that holds one copy of the certificate and CRL caches and is used by any number of sessions: a session passes the shared memory handle together with each request. When the handle is NULL the session works exactly as described above.

With a shared memory given in a request:

- certificates are looked up first in the session's own cache (certificates from the opened storage, ADD_CERT) and then in the shared memory, so a certificate of the session takes precedence over one with the same key in the shared memory; a certificate that the shared memory already holds is not copied into the session; the certificates of the session stay private to it, permanent additions (ADD_CERT with permanent = true) go to the shared memory;
- CRLs are taken from the shared memory only (LIST_CRLS, CRL_INFO, ADD_CRL, REMOVE_CRL and certificate validation by CRL work with the shared memory); the session's own CRL cache is not used;
- a session that did not execute INIT uses the configuration of the shared memory (offline mode, OCSP/TSP parameters, validationByCrl), so cache and verification methods work without initializing the session; storage methods still require INIT and OPEN in the session;
- an initialized session keeps its own configuration.

The shared memory is filled and maintained with the function uapki_session_shared_memory_process, which accepts only the methods listed in Table 4; any other method of Table 2 returns the NOT_ALLOWED error, an unknown method returns INVALID_METHOD. The request and response formats of these methods are the ones described in "Library methods description". Requests of sessions that use the shared memory are synchronized with it: the methods marked ST in Table 4 (from the shared memory itself, and REMOVE_CERT/REMOVE_CRL also from any session that passes the shared memory) wait until every request that is using the shared memory has finished, including requests that are waiting for a network response, and new requests wait for them; the methods marked MT and IND run in parallel with the requests of all sessions. The ST methods are therefore meant to be rare maintenance operations.

Table 4. Methods of the shared memory (uapki_session_shared_memory_process)

| **№** | **Method name** | **Short description**                                                                       | **Type** |
| ----- | --------------- | ------------------------------------------------------------------------------------------- | ------- |
| 1     | VERSION         | Library version                                                                             | IND     |
| 2     | INIT            | Loading of the caches (certCache, crlCache) and the configuration; cmProviders is ignored   | ST      |
| 3     | DEINIT          | Release of the caches                                                                       | ST      |
| 4     | ADD_CERT        | Add a certificate to the shared certificate cache                                           | MT      |
| 5     | CERT_INFO       | Certificate information                                                                     | MT      |
| 6     | GET_CERT        | Get a certificate from the shared certificate cache                                         | MT      |
| 7     | LIST_CERTS      | List of certificates in the shared certificate cache                                        | MT      |
| 8     | REMOVE_CERT     | Remove a certificate from the shared certificate cache                                      | ST      |
| 9     | ADD_CRL         | Add a CRL to the shared CRL cache                                                           | MT      |
| 10    | CRL_INFO        | CRL information                                                                             | MT      |
| 11    | LIST_CRLS       | List of CRLs in the shared CRL cache                                                        | MT      |
| 12    | REMOVE_CRL      | Remove outdated CRLs from the shared CRL cache                                              | ST      |
| 13    | ADD_TRUST_LIST   | Add a trusted list: in effect for all sessions of the shared memory | MT      |
| 14    | LIST_TRUST_LISTS | The list of the accepted trusted lists of the shared memory | MT      |

### Function uapki_session_shared_memory_create

The function creates a new, empty shared memory.

### Input parameters

none.

### Output parameters

returns a shared memory handle, or NULL if it could not be created.

### Function uapki_session_shared_memory_free

The function frees the shared memory and its caches. The handle becomes invalid; requests of sessions that pass this handle afterwards return the INVALID_SHARED_MEMORY error. If another thread is executing a request with this shared memory at the moment of the call, that request is completed normally and the shared memory is freed afterwards.

### Input parameters

memory — the shared memory handle returned by uapki_session_shared_memory_create. NULL and already freed handles are ignored.

### Output parameters

none.

### Function uapki_session_shared_memory_process

The function is intended for calling a cache management method on the shared memory; the request and response formats are identical to the process function.

### Input parameters

memory — the shared memory handle returned by uapki_session_shared_memory_create;

request — a pointer to a null-terminated JSON string in UTF8 encoding that defines the method being called and its parameters.

### Output parameters

returns a pointer to a null-terminated JSON string in UTF8 encoding containing the result of the method execution; for an invalid handle the response contains the INVALID_SHARED_MEMORY error code. The memory referenced by this pointer must always be released after processing using the json_free function.

### Example

```c
UAPKI_SESSION_SHARED_MEMORY* memory = uapki_session_shared_memory_create();
char* response = uapki_session_shared_memory_process(memory,
    "{\"method\":\"INIT\",\"parameters\":{\"certCache\":{\"path\":\"/var/uapki/certs/\"},\"crlCache\":{\"path\":\"/var/uapki/crls/\"}}}");
json_free(response);

UAPKI_SESSION* session = uapki_session_create();
response = uapki_session_process(session, memory, "{\"method\":\"VERIFY\",\"parameters\":{...}}");
json_free(response);
uapki_session_free(session);
uapki_session_shared_memory_free(memory);
```

# Library methods description

All method requests and responses have a unified format.

### Request format

| **Field name** | **Type** | **Description**                                                                |
| -------------- | ------- | ----------------------------------------------------------------------- |
| method         | String  | Method name. Mandatory parameter                                     |
| parameters     | Object  | Optional parameter. Structure containing<br>the method input parameters |

### Response format

| **Field name** | **Type** | **Description**                                       |
| -------------- | ------- | ---------------------------------------------- |
| errorCode      | Integer | Error code. Error codes are listed in Appendix A  |
| method         | String  | Method name                                   |
| result         | Object  | Structure containing the method output parameters |
| error          | String  | Short textual description of the error. Optional  |

## VERSION method

The method is intended for determining the library version. Input parameters: none.

### Structure of the result field in the response

| **Field name** | **Type** | **Description**                                    |
| -------------- | ------- | ------------------------------------------- |
| name           | String  | Library name                             |
| version        | String  | Library version number                     |
| uapkicVersion  | String  | Version number of the uapkic library              |
| uapkifVersion  | String  | Version number of the uapkif library              |

### Request example

```
{
  "method": "VERSION"
}
```

### Response example

```
{
  "errorCode": 0,
  "method": "VERSION",
  "result": {
    "name": "UAPKI",
    "version": "3.0.0-dev",
    "uapkicVersion": "3.0.0-dev",
    "uapkifVersion": "3.0.0-dev"
  }
}
```

## INIT method

The method is intended for initializing the library. Input parameters are optional. The output parameters return the current status/parameter values of the library subsystems. If the library has been initialized, the DEINIT method must be executed before finishing work with it.

If methods that change the internal state of the library (i.e. of type ST and MT) are used, library initialization is mandatory. Methods that do not change the internal state of the library are of type IND, for example: VERSION and DIGEST.

Library parameters can be set in two ways: via parameters or via a configuration file. The parameters and the configuration file have the same structure. If a configuration file is used, its path must be specified in the "configFile" field (recommended name "uapki-config.json").

If the library parameters are not set, the default parameters will be used. To work with storages, the storage provider parameters must be set.

A repeated call of the method for a library (a session, a shared memory) that is already initialized changes nothing and returns the error ALREADY_INITIALIZED; the result field of the response then has the field "parameters" (Object) — the parameters the library was initialized with: in the structure of the parameters field of the request, for a configuration file — its content with the "configFile" field, without the "proxy.credentials" field.

Starting from version 2.0.16, the INIT method (by default) performs a self-test. The self-test can be canceled by setting the skipSelfTest parameter to true. The duration of the self-test depends on system performance. It is enough to run the self-test once per process: later INIT calls, including those in other sessions, can pass skipSelfTest = true.

### Structure of the parameters field in the request using a configuration file

| **Field name** | **Type** | **Description**             |
| -------------- | ------- | -------------------- |
| configFile     | String  | Full path to the file |

### Request example using a configuration file

```
{
  "method": "INIT",
  "parameters": {
    "configFile": "C:/uapki/uapki-config.json"
  }
}
```

### Structure of the parameters field in the request

| **Field name**  | **Type**                      | **Description**                                                |
| --------------- | ---------------------------- | ------------------------------------------------------- |
| cmProviders     | Object<br>CMPROVIDERS_PARAMS | Storage provider parameters. Optional                 |
| certCache       | Object<br>CERT_CACHE_PARAMS  | Certificate cache parameters. Optional.              |
| crlCache        | Object<br>CRL_CACHE_PARAMS   | CRL cache parameters. Optional                        |
| trustListCache  | Object<br>TRUST_LIST_CACHE_PARAMS | Trusted lists parameters. Optional |
| offline         | Boolean                      | "Offline" operation mode. Optional                     |
| ocsp            | Object<br>OCSP_PARAMS        | OCSP service parameters. Optional                    |
| proxy           | Object<br>PROXY_PARAMS       | PROXY service parameters. Optional                   |
| skipSelfTest    | Boolean                      | Skip the self-test. Optional                 |
| tsp             | Object<br>TSP_PARAMS         | TSP service parameters. Optional                     |
| validationByCrl | Boolean                      | Certificate status verification by CRL.<br>Optional |
| timeStampOrderTolerance | Integer | The accuracy (seconds) of a time-stamp token without the accuracy<br>field when the order of the time-stamps of a signature is checked<br>(RFC 3161, 2.4.2). Optional, default 0 |

### Structure CERT_CACHE_PARAMS

| **Field name** | **Type**  | **Description**                                                                                                                                    |
| -------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| path           | String   | Full path to the directory. Optional. If the path<br>to the directory is not set, only the<br>temporary in-memory certificate cache is used |
| trustedCerts   | Base64[] | Array of trusted certificates. Optional. A certificate chain is built up to the first trusted certificate |

### Structure CRL_CACHE_PARAMS

| **Field name** | **Type** | **Description**                                                                                                                           |
| -------------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| path           | String  | Full path to the directory. Optional. If the path<br>to the directory is not set, only the<br>temporary in-memory CRL cache is used |
| useDeltaCrl    | Boolean | Use delta CRL. Optional,<br>default true                                                                |

### Structure TRUST_LIST_CACHE_PARAMS

| **Field name** | **Type** | **Description** |
| -------------- | -------- | --------------- |
| path           | String   | Full path to the directory of trusted lists. Optional. The directory<br>keeps the last accepted version of every trusted list (the<br>ADD_TRUST_LIST method); at initialization the kept lists are<br>verified and applied again. If the path is not set, trusted lists<br>are in effect until the library is deinitialized |
| trustListSignerCerts | Base64[] | The certificates that sign trusted lists. Optional. A trusted list<br>is accepted only if it is signed by one of these certificates. Such<br>a certificate is not a trusted certificate of a certificate chain;<br>a certificate of certCache.trustedCerts is not a certificate for<br>signing trusted lists |

### Structure OCSP_PARAMS

| **Field name** | **Type** | **Description**                                                                                                                                                                                                                                               |
| -------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| nonceLen       | Integer | Length of the one-time random number in the OCSP<br>request. Value range: 0, 8..64. If the value<br>equals 0 or is out of range, the<br>random number in the OCSP request is not used.<br>Optional, default is 20 |
| cacheTime      | Integer | Time (minutes) an OCSP response without nextUpdate is taken<br>from the cache: up to thisUpdate + cacheTime; a response<br>with nextUpdate is taken from the cache up to nextUpdate. A<br>response older than that is not cached.<br>Optional, default is 30 |
| maxFreshness   | Integer | Maximum freshness (minutes) of an OCSP response without<br>nextUpdate when verifying a signature (ETSI EN 319 102-1, 5.2.5):<br>the response is used if thisUpdate > validation time - maxFreshness;<br>a response with nextUpdate - if nextUpdate > validation time.<br>It should be greater than cacheTime for the signatures of the<br>library to pass the verification. A response obtained from<br>the server is rejected if it is not fresh at the current time.<br>Optional, default is 120 |
| responderCrlEmbedMaxSize | Integer | The largest size (bytes) of a CRL of an OCSP responder without<br>id-pkix-ocsp-nocheck embedded into a CAdES-B-LT/B-LTA signature<br>(a limit of the size of the signature). A bigger CRL is used for<br>the validation but not embedded, and such a signature is not a<br>complete B-LT (ETSI EN 319 122-1, table 1, requirement o).<br>Optional, default is 10240 |

### Structure PROXY_PARAMS

| **Field name** | **Type** | **Description**                                                                                                                         |
| -------------- | ------- | -------------------------------------------------------------------------------------------------------------------------------- |
| url            | String  | URL of the PROXY service. If the value is absent<br>or is an empty string, the PROXY service is not<br>used. Optional. |
| credentials    | String  | Authentication parameters for the PROXY service.<br>Optional                                                                       |

### Structure TSP_PARAMS

| **Field name** | **Type** | **Description**                                                                                                                                                                                                                                            |
| -------------- | ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| certReq        | Boolean | Requirement to return the service certificate in the TSP response.<br>Optional, default is false                                                                                                                                                 |
| forced         | Boolean | Requirement to use the TSP service URLs<br>specified in the "url" field, ignoring the addresses specified in the<br>signer's certificate. Without it all the TSP services of the signer's<br>certificate are tried first (in random order), then, if they are absent,<br>do not respond or refuse, all the addresses of "url" in their order.<br>Optional, default is false                                                               |
| nonceLen       | Integer | Length of the one-time random number in the TSP<br>request. Value range: 0, 4..32. If the value<br>equals 0 or is out of range, the<br>random number in the TSP request is not used.<br>Optional, default is 8 |
| policyId       | OID     | Identifier of the TSP service policy. If the field<br>is absent or its value is an empty string, the TSP service<br>policy parameter in the request is not used.<br>Optional                                                                            |

| url | String[] | array of TSP service URLs.                      |
| --- | -------- | -------------------------------------------------- |
|     | or       | In the case of a single address, it can be set as a string. |
|     | String   | Optional                                       |

### Structure CMPROVIDERS_PARAMS

| **Field name**   | **Type**                       | **Description**                                                  |
| ---------------- | ----------------------------- | --------------------------------------------------------- |
| dir              | String                        | Full path to the directory with the storage<br>provider libraries |
| allowedProviders | Object[]<br>CMPROVIDER_PARAMS | Array of storage provider parameters                       |

### Structure CMPROVIDER_PARAMS

| **Field name** | **Type** | **Description**                                                        |
| -------------- | ------- | --------------------------------------------------------------- |
| lib            | String  | File name of the storage provider library                           |
| config         | Object  | Parameters specific to this storage provider.<br>Optional |

### Configuration file example

```
{
  "cmProviders": {
    "allowedProviders": [
      {
        "lib": "cm-pkcs11",
        "config": {
          "modules": [{
            "name": "sisp11",
            "ekuDevice": true,
            "pka": true
          }, {
            "name": "Av337CryptokiD",
            "ekuDevice": true
          }, {
            "name": "avcryptokinxt",
            "ekuDevice": true
          }]
        }
      }, {
        "lib": "cm-pkcs12"
      }, {
        "lib": "cm-almaz1c"
      }
    ]
  },
  "certCache": {
    "path": "C:/uapki/certs/",
    "trustedCerts": ["MIIE...a2s=", ... ]
  },
  "crlCache": {
    "path": "C:/uapki/certs/crls/"
  },
  "offline": false
}
```

### Structure of the result field in the response

| **Field name**   | **Type**                   | **Description**                               |
| ---------------- | ------------------------- | -------------------------------------- |
| certCache        | Object<br>CERT_CACHE_INFO | Information about the certificate cache state  |
| crlCache         | Object<br>CRL_CACHE_INFO  | Information about the CRL cache state           |
| trustListCache   | Object<br>TRUST_LIST_CACHE_INFO | Information about trusted lists. Optional — present if<br>trustListCache.path is set |
| countCmProviders | Integer                   | Number of loaded storage providers |
| cmProviders      | Object<br>CM_PROVIDERS_INFO | Outcome of loading the storage providers from the cmProviders.allowedProviders parameter. Absent for the shared memory of sessions |
| offline          | Boolean                   | "Offline" operation mode                  |
| ocsp             | Object<br>OCSP_INFO       | Information about the OCSP service parameters  |
| proxy            | Object<br>PROXY_INFO      | Information about the PROXY service parameters |
| tsp              | Object<br>TSP_INFO        | Information about the TSP service parameters   |
| validationByCrl  | Boolean                   | Certificate status verification by CRL |
| timeStampOrderTolerance | Integer | The accuracy (seconds) of a time-stamp token without the accuracy field |

### Structure CERT_CACHE_INFO

| **Field name**    | **Type** | **Description**                                            |
| ----------------- | ------- | --------------------------------------------------- |
| countTrustedCerts | Integer | Number of trusted certificates in the certificate cache |
| countCerts        | Integer | Total number of certificates in the certificate cache |

### Structure TRUST_LIST_CACHE_INFO

| **Field name**    | **Type** | **Description** |
| ----------------- | -------- | --------------- |
| countLists        | Integer  | Number of trusted lists applied from the directory |
| countRefusedLists | Integer  | Number of trusted lists of the directory that are not accepted |
| countListsNextUpdatePassed | Integer | Number of the accepted trusted lists whose next update time<br>is passed (the list is to be obtained again) |

### Structure CM_PROVIDERS_INFO

| **Field name** | **Type**                       | **Description**                                              |
| -------------- | ------------------------------ | ------------------------------------------------------------ |
| requested      | Integer                        | Number of providers in allowedProviders                       |
| loaded         | Integer                        | Number of successfully loaded providers                       |
| failed         | Array<br>CM_PROVIDER_FAILURE   | Providers that failed to load (empty array if none). A provider load failure is not an error of the INIT method |

### Structure CM_PROVIDER_FAILURE

| **Field name** | **Type** | **Description**            |
| -------------- | -------- | -------------------------- |
| lib            | String   | Provider library name      |
| errorCode      | Integer  | Load error code            |
| error          | String   | Error name                 |

### Structure CRL_CACHE_INFO

| **Field name** | **Type** | **Description**                          |
| -------------- | ------- | --------------------------------- |
| countCrls      | Integer | Number of CRLs in the CRL cache          |
| useDeltaCrl    | Boolean | Delta CRL is used    |

### Structure OCSP_INFO

| **Field name** | **Type** | **Description**                                                                                                                                     |
| -------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| nonceLen       | Integer | Length of the one-time random nonce in the OCSP<br>request. If the value equals 0, the random<br>nonce in the OCSP request is not used |
| cacheTime      | Integer | Cache time of an OCSP response without nextUpdate (minutes) |
| maxFreshness   | Integer | Maximum freshness of an OCSP response without nextUpdate (minutes) |
| responderCrlEmbedMaxSize | Integer | The largest size of a CRL of an OCSP responder embedded into a signature (bytes) |

### Structure PROXY_INFO

| **Field name** | **Type** | **Description**                                      |
| -------------- | ------- | --------------------------------------------- |
| url            | String  | URL of the PROXY service. If it contains an empty<br>string, the PROXY service is not used. |

### Structure TSP_INFO

| **Field name** | **Type** | **Description**                                                                                                                              |
| -------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| certReq        | Boolean | Requirement to return the service certificate in the TSP response                                                                                   |
| forced         | Boolean | Requirement to use the TSP service URLs<br>specified in the "url" field, ignoring the addresses specified in the<br>signer's certificate |
| nonceLen       | Integer | Length of the one-time random number in the TSP<br>request. If the value equals 0, the random<br>number in the request is not used |
| policyId       | OID     | Identifier of the TSP service policy                                                                                                    |
| url            | String  | URL of the TSP service. An array of URLs<br>is returned as a string with ";" as separator                                            |

### Request example with input parameters set directly

```
{
  "method": "INIT",
  "parameters": {
    "cmProviders": {
      "allowedProviders": [
        {
          "lib": "cm-pkcs11",
          "config": {
            "modules": [
              { "name": "sisp11", "ekuDevice": true, "pka": true },
              { "name": "Av337CryptokiD", "ekuDevice": true },
              { "name": "avcryptokinxt", "ekuDevice": true }
            ]
          }
        },
        { "lib": "cm-pkcs12" },
        { "lib": "cm-almaz1c" }
      ]
    },
    "certCache": {
      "path": "C:/uapki/certs/",
      "trustedCerts": ["MIIE...a2s=", ... ]
    },
    "crlCache": { "path": "C:/uapki/certs/crls/" },
    "offline": false,
    "ocsp": { "nonceLen": 20 },
    "tsp": {
      "certReq": true,
      "forced": true,
      "nonceLen": 8,
      "policyId": "1.2.804.2.1.1.1.2.3.1",
      "url": "http://url_ca/services/tsp/"
    }
  }
}
```

### Response example

```
{
  "errorCode": 0,
  "method": "INIT",
  "result": {
    "certCache": { "countCerts": 29, "countTrustedCerts": 5 },
    "crlCache": { "countCrls": 4, "useDeltaCrl": true },
    "countCmProviders": 3,
    "cmProviders": { "requested": 3, "loaded": 3, "failed": [] },
    "offline": false,
    "ocsp": { "nonceLen": 20 },
    "proxy": { "url": "" },
    "tsp": {
      "certReq": true,
      "forced": true,
      "nonceLen": 8,
      "policyId": "1.2.804.2.1.1.1.2.3.1",
      "url": "http://url_ca/services/tsp/"
    },
    "validationByCrl": false
  }
}
```

## DEINIT method

The method is intended for releasing the library resources that were allocated during initialization. Input parameters: none.

DEINIT releases the resources of the session it is called in (the global one or one created with uapki_session_create). When DEINIT is executed in the last initialized session (counting the global session and the shared memory; freeing a session with uapki_session_free is equivalent to DEINIT), the global state of the crypto library is released as well: the DRBG state is wiped, the elliptic curve parameter cache and error stacks are freed. The application must guarantee that no other thread uses the library at that moment, including methods that do not require INIT (DIGEST, ASN1_DECODE, etc.). After that the library can be initialized again with INIT.

If the library is linked statically into a module (DLL, shared library) that can be unloaded while the process keeps running, DEINIT must be executed in all initialized sessions before the module is unloaded.

Output parameters: none.

### Request example

```
{
  "method": "DEINIT"
}
```

### Response example

```
{
  "errorCode": 0,
  "method": "DEINIT",
  "result": {}
}
```

## PROVIDERS method

The method is intended for obtaining the list of loaded storage providers and information about them. Input parameters: none.

### Structure of the result field in the response

| **Field name** | **Type**                     | **Description**                                        |
| -------------- | --------------------------- | ----------------------------------------------- |
| providers      | Object[]<br>PROVIDER_INFO[] | Array of information about the loaded storage providers |

### Structure PROVIDER_INFO

| **Field name**      | **Type** | **Description**                                                                      |
| ------------------- | ------- | ----------------------------------------------------------------------------- |
| id                  | String  | Provider identifier. A unique value,<br>for example: "PKCS12", "TOKEN" |
| apiVersion          | String  | Provider API version in the major.minor.build format                             |
| libVersion          | String  | Provider library version in the<br>major.minor.build format                   |
| description         | String  | Short description of the provider                                                      |
| manufacturer        | String  | Name of the provider manufacturer                                                    |
| supportListStorages | Boolean | Flag indicating support of the "STORAGES" method                                          |
| flags               | Integer | Provider capability flags. Optional                                 |

### Request example

```
{
  "method": "PROVIDERS"
}
```

### Response example

```
{
    "errorCode": 0,
    "method": "PROVIDERS",
    "result": {
        "providers": [
            {
                "id": "PKCS12",
                "apiVersion": "1.0.0",
                "libVersion": "1.0.20",
                "description": "PKCS#12 (PFX) file key storage",
                "manufacturer": "SPECINFOSYSTEMS LLC",
                "supportListStorages": false,
                "flags": 0
            },
            {
                "id": "PKCS11",
                "apiVersion": "1.0.0",
                "libVersion": "1.0.10",
                "description": "CM-provider for PKCS11",
                "manufacturer": "SPECINFOSYSTEMS LLC",
                "supportListStorages": true,
                "flags": 0
            }
        ]
    }
}
```

## STORAGES method

The method is intended for obtaining the list of storages of a specific provider. Providers may not support this method, for example, the PKCS12 provider.

### Structure of the parameters field in the request

| **Field name** | **Type** | **Description**                 |
| -------------- | ------- | ------------------------ |
| provider       | String  | Provider identifier |

### Structure of the result field in the response

| **Field name** | **Type**                    | **Description**                        |
| -------------- | -------------------------- | ------------------------------- |
| storages       | Object[]<br>STORAGE_INFO[] | Array of information about the available storages |

### Structure of the STORAGE_INFO field

| **Field name**       | **Type** | **Description**                                                                                           |
| -------------------- | ------- | -------------------------------------------------------------------------------------------------- |
| id                   | String  | Storage identifier                                                                                  |
| description          | String  | Storage description                                                                                           |
| manufacturer         | String  | Storage manufacturer                                                                                       |
| model                | String  | Storage model                                                                                          |
| serial               | String  | Storage serial number                                                                                 |
| label                | String  | Storage text label                                                                            |
| passwordCountLow     | Boolean | The previous password entry attempt was<br>incorrect, the number of password entry attempts<br>has been reduced |
| passwordFinalTry     | Boolean | Last password entry attempt                                                                        |
| passwordLocked       | Boolean | Password is locked                                                                                 |
| passwordToBeChanged  | Boolean | Flag indicating that the password must be changed                                                                 |
| passwordAttemptsLeft | Integer | Number of attempts remaining before the password<br>is locked                                             |
| passwordMinLen       | Integer | Minimum password length                                                                          |
| passwordMaxLen       | Integer | Maximum password length                                                                         |
| flags                | String  | Storage state flags. Depends on the provider                                                        |
| maxSessionCount      | Integer | Maximum number of sessions. Depends on the provider                                               |
| sessionCount         | Integer | Current number of sessions. Depends on the provider                                                   |
| maxRwSessionCount    | Integer | Maximum number of read-write sessions.<br>Depends on the provider                             |
| rwSessionCount       | Integer | Current number of read-write sessions.<br>Depends on the provider                                 |
| totalPublicMemory    | Integer | Total amount of public memory.<br>Depends on the provider                                      |
| freePublicMemory     | Integer | Free amount of public memory.<br>Depends on the provider                                        |
| totalPrivateMemory   | Integer | Total amount of private memory.<br>Depends on the provider                                      |
| freePrivateMemory    | Integer | Free amount of private memory.<br>Depends on the provider                                        |
| hardwareVersion      | String  | Hardware version.<br>Depends on the provider                                         |
| firmwareVersion      | String  | Firmware version. Depends on the provider                                                      |
| utcTime              | String  | Current storage time (UTC). Depends on the provider                                                    |

### Request example

```
{
  "method": "STORAGES",
  "parameters": {
    "provider": "TOKEN"
  }
}
```

### Response example, if the method is supported

```
{
  "errorCode": 0,
  "method": "STORAGES",
  "result": {
    "storages": [
      {
        "id": "1099999",
        "description": "DIAMOND token",
        "manufacturer": "SPECINFOSYSTEMS LLC",
        "model": "DIAMOND 1000",
        "serial": "1099999",
        "label": "",
        "passwordCountLow": false,
        "passwordFinalTry": false,
        "passwordLocked": false,
        "passwordToBeChanged": false,
        "passwordAttemptsLeft": 10,
        "passwordMinLen": 4,
        "passwordMaxLen": 64
      },
      { ... }
    ]
  }
}
```

### Response example, if the method is not supported

```
{
  "errorCode": 4123,
  "method": "STORAGES",
  "result": {},
  "error": "UNSUPPORTED_CM_API"
}
```

## STORAGE_INFO method

The method is intended for obtaining information about a storage. Providers may not support this method, for example, the PKCS12 provider.

If the provider supports this method, the STORAGE_INFO structure will be returned as the output parameters (see the STORAGES method).

### Structure of the parameters field in the request

| **Field name** | **Type** | **Description**                                                               |
| -------------- | ------- | ---------------------------------------------------------------------- |
| provider       | String  | Provider identifier                                               |
| storage        | String  | Storage identifier. For example, this can be a file<br>name or a URL |

### Request example

```
{
  "method": "STORAGE_INFO",
  "parameters": {
    "provider": "PKCS12",
    "storage": "storage-id"
  }
}
```

### Response example, if the method is supported

```
{
  "errorCode": 0,
  "method": "STORAGE_INFO",
  "result": {
    "id": "1099999",
    "description": "DIAMOND token",
    "manufacturer": "SPECINFOSYSTEMS LLC",
    "model": "DIAMOND 1000",
    "serial": "1099999",
    "label": "",
    "passwordCountLow": true,
    "passwordFinalTry": false,
    "passwordLocked": false,
    "passwordToBeChanged": false,
    "passwordAttemptsLeft": 9,
    "passwordMinLen": 4,
    "passwordMaxLen": 64
  }
}
```

### Response example, if the method is not supported

```
{
  "errorCode": 4123,
  "method": "STORAGE_INFO",
  "result": {},
  "error": "UNSUPPORTED_CM_API"
}
```

## OPEN method

The method is intended for user authorization and opening a storage.

Attention! Only one storage can be open at a time in a session (or in the global library instance), and it is available to all threads that use this session. Different sessions open their storages independently.

If certificates are found on the storage when it is opened, they automatically become available for use in other library methods.

The method has three mandatory input parameters ("provider", "storage" and "password"), optional parameters "mode" and "username", and may also have specific parameters that depend on the particular storage provider.

### Storage access modes ("mode")

| **Value** | **Type**                                                                                                            |
| ------------ | ------------------------------------------------------------------------------------------------------------------ |
| "RW"         | All key operation methods are available. Default mode                                                     |
| "RO"         | Methods for working with keys that do not modify the storage are available (analogous to the<br>"read-only" mode for regular files) |
| "CREATE"     | Creation of a new PKCS#12 file, all key operation methods are<br>available (PKCS12 provider only)         |

The PKCS12 provider has a specific parameter — "openParams", which is optional. It can be used when creating a file container or when working with keys stored not in a file but in RAM. The special "in memory" mode allows using the content of a PKCS12-format file located in RAM instead of working with a file on disk. To use the "in memory" mode, specify the keyword "file://memory" in the "storage" parameter, set the "mode" parameter to "RO" (other modes are not supported), and provide the file content in base64 encoding in the "bytes" field of the "openParams" parameter.

When creating new PKCS#12 file containers, the values of the "bagCipher", "bagKdf", "macAlgo" and "iterations" parameters can be set in the "createPfx" field of the "openParams" parameter. If the "createPfx" field is not set, the provider will use the default parameter values. If the "createPfx" field is set, all four parameters are mandatory: a missing or unsupported value of any of them results in an error.

### Default "createPfx" parameters

| **Parameter** | **Value**                | **Description**       |
| ------------ | --------------------------- | -------------- |
| bagCipher    | `"2.16.840.1.101.3.4.1.42"` | AES256-CBC-PAD |
| bagKdf       | `"1.2.840.113549.2.11"`     | HMAC-SHA-512   |
| macAlgo      | `"2.16.840.1.101.3.4.2.3"`  | SHA-512        |
| iterations   | `10000`                     |                |

### Structure of the parameters field in a request to the PKCS12 provider

| **Field name** | **Type** | **Description**                         |
| -------------- | ------- | -------------------------------- |
| provider       | String  | Identifier of the PKCS12 provider                   |
| storage        | String  | File name                                        |
| mode           | String  | Storage access mode. Optional                  |
| password       | String  | Password                                            |
| username       | String  | User name. Optional, depends on the<br>provider |
| openParams     | Object  | Additional parameters. Optional                 |

### Structure of the result field in the response

| **Field name** | **Type**  | **Description**                                                              |
| -------------- | -------- | --------------------------------------------------------------------- |
| id             | String   | Storage identifier                                                     |
| description    | String   | Storage description                                                          |
| manufacturer   | String   | Storage manufacturer                                                    |
| model          | String   | Storage model                                                        |
| serial         | String   | Storage serial number                                                    |
| label          | String   | User-defined text description of the storage                         |
| mechanisms     | Object[] | Array of structures describing the mechanisms available<br>for use |

On successful file opening, the PKCS12 provider returns empty strings for the "model", "serial" and "label" parameters.

### Request example to the PKCS12 provider for creating a new key file

```
{
  "method": "OPEN",
  "parameters": {
    "provider": "PKCS12",
    "storage": "file.p12",
    "mode": "CREATE",
    "password": "password",
    "openParams": {
      "createPfx": {
        "bagCipher": "2.16.840.1.101.3.4.1.2",
        "bagKdf": "1.2.840.113549.2.9",
        "macAlgo": "2.16.840.1.101.3.4.2.1",
        "iterations": 10000
      }
    }
  }
}
```

### Request example to the PKCS12 provider for working with a key file

```
{
  "method": "OPEN",
  "parameters": {
    "provider": "PKCS12",
    "storage": "file.p12",
    "mode": "RW",
    "password": "password"
  }
}
```

### Request example to the PKCS12 provider for working with keys "in memory"

```
{
  "method": "OPEN",
  "parameters": {
    "provider": "PKCS12",
    "storage": "file://memory",
    "password": "password",
    "mode": "RO",
    "openParams": {
      "bytes": "MIIE4wIBAzCCBIAGCSqG...U+soAgInEA=="
    }
  }
}
```

### Response example

```
{
  "errorCode": 0,
  "method": "OPEN",
  "result": {
    "id": "file.p12",
    "description": "PKCS#12",
    "manufacturer": "SPECINFOSYSTEMS LLC",
    "model": "",
    "serial": "",
    "label": "",
    "mechanisms": [
      {
        "id": "1.2.804.2.1.1.1.1.3.6",
        "name": "DSTU-4145",
        "keyParam": ["1.2.804.2.1.1.1.1.3.1.1.2.5", ... ],
        "signAlgo": ["1.2.804.2.1.1.1.1.3.6.1", ... ]
      },
      {
        "id": "1.2.840.10045.2.1",
        "name": "ECDSA",
        "keyParam": ["1.2.840.10045.3.1.7", ... ],
        "signAlgo": ["1.2.840.10045.4.3.2", ... ]
      },
      { ... }
    ]
  }
}
```

## CLOSE method

Closes the currently open storage. Input parameters: none. Output parameters: none.

### Request example

```
{
  "method": "CLOSE"
}
```

### Response example

```
{
  "errorCode": 0,
  "method": "CLOSE",
  "result": {}
}
```

## KEYS method

The method is intended for obtaining the list of keys on the open storage.

### Structure of the parameters field in the request

| **Field name**  | **Type** | **Description**                                                                    |
| --------------- | ------- | --------------------------------------------------------------------------- |
| returnPublicKey | Boolean | Return the public key value.<br>Optional, default false |

### Structure of the result field in the response

| **Field name** | **Type**                | **Description**                   |
| -------------- | ---------------------- | -------------------------- |
| keys           | Object[]<br>KEY_INFO[] | Array of key information |

### Structure KEY_INFO

| **Field name** | **Type**              | **Description**                                                                                                       |
| -------------- | -------------------- | -------------------------------------------------------------------------------------------------------------------- |
| id             | String               | Key identifier. Unique value                                                                        |
| mechanismId    | OID                  | Key algorithm identifier                                                                                  |
| parameterId    | OID<br>or<br>String | Key parameter identifier:<br>OID – EC curve identifier;<br>String – RSA key length in bits (number) |
| signAlgo       | OID[]                | Array of signature algorithm identifiers<br>supported by the key                            |
| label          | String               | Text label of the key                                                                      |
| application    | String               | Text label of the application                                                                 |
| publicKey      | Base64               | Public key value. Optional —<br>present if the returnPublicKey parameter is<br>set to true    |
| keyId2         | Hex                  | Key identifier keyId2 (based on Kupyna-256).<br>Optional, present only for DSTU keys             |

### Request example

```
{
  "method": "KEYS"
}
```

### Response example

```
{
  "errorCode": 0,
  "method": "KEYS",
  "result": {
    "keys": [
      {
        "id": "112233445566...DDEEFF00",
        "mechanismId": "1.2.804.2.1.1.1.1.3.1.1",
        "parameterId": "1.2.804.2.1.1.1.1.3.1.1.2.6",
        "signAlgo": ["1.2.804.2.1.1.1.1.3.1.1", ... ],
        "label": "DSTU-4145, M257_PB",
        "application": ""
      }, {
        "id": "CAFE8A8E1234...00000001",
        "mechanismId": "1.2.840.10045.2.1",
        "parameterId": "1.2.840.10045.3.1.7",
        "signAlgo": ["1.2.840.10045.4.3.2", ... ],
        "label": "ECDSA, prime256v1",
        "application": ""
      }
    ]
  }
}
```

## SELECT_KEY method

The method is intended for selecting the current key on the open storage by the key identifier on the storage (the id parameter) or by the certificate identifier in the certificate cache (the certId parameter). Exactly one of the two parameters must be specified: either id or certId.

Attention! Only one key can be selected at a time in a session (or in the global library instance), and it is available to all threads that use this session. When another key is selected, it changes for all threads that use this session.

### Structure of the parameters field in the request

| **Field name** | **Type** | **Description**                                                       |
| -------------- | ------- | -------------------------------------------------------------- |
| id             | Hex     | Key identifier on the storage. Optional                       |
| certId         | Base64  | Certificate identifier in the certificate cache.<br>Optional |

### Structure of the result field in the response

| **Field name** | **Type**              | **Description**                                                                                                       |
| -------------- | -------------------- | -------------------------------------------------------------------------------------------------------------------- |
| id             | String               | Key identifier                                                                                            |
| mechanismId    | OID                  | Key algorithm identifier                                                                                  |
| parameterId    | OID<br>or<br>String | Key parameter identifier:<br>OID – EC curve identifier;<br>String – RSA key length in bits (number) |
| signAlgo       | OID[]                | Array of signature algorithm identifiers<br>supported by the key                            |
| label          | String               | Text label of the key                                                                      |
| application    | String               | Text label of the application                                                                 |
| keyId2         | Hex                  | Key identifier keyId2 (based on Kupyna-256).<br>Optional, present only for DSTU keys              |
| certId         | Base64               | Certificate identifier in the certificate cache.<br>Optional                                                 |
| certificate    | Base64               | Key certificate (per the x.509 standard) in<br>base64 format. Optional                       |

### Request example

```
{
  "method": "SELECT_KEY",
  "parameters": {
    "id": "112233445566...DDEEFF00"
  }
}
```

### Response example when there is no matching certificate in the certificate cache

```
{
  "errorCode": 0,
  "method": "SELECT_KEY",
  "result": {
    "id": "112233445566...DDEEFF00",
    "mechanismId": "1.2.804.2.1.1.1.1.3.1.1",
    "parameterId": "1.2.804.2.1.1.1.1.3.1.1.2.6",
    "signAlgo": ["1.2.804.2.1.1.1.1.3.1.1", ... ],
    "label": "DSTU-4145, M257_PB",
    "application": ""
  }
}
```

### Response example when there is a matching certificate in the certificate cache

```
{
  "errorCode": 0,
  "method": "SELECT_KEY",
  "result": {
    "id": "112233445566...DDEEFF00",
    "mechanismId": "1.2.804.2.1.1.1.1.3.1.1",
    "parameterId": "1.2.804.2.1.1.1.1.3.1.1.2.6",
    "signAlgo": ["1.2.804.2.1.1.1.1.3.1.1", ... ],
    "label": "DSTU-4145, M257_PB",
    "application": "",
    "certId": "MIH+MIHlMQsw...NQAAAFwAAAA=",
    "certificate": "MIIErjCCBFagAwIBAgIUFXe...NcYCFp23iPeya2s="
  }
}
```

## CREATE_KEY method

The method is intended for creating a new key on the open storage. The parameters with which a key can be created are determined when the storage is opened. If the method completes successfully, the new key becomes the currently selected key on the storage.

### Structure of the parameters field in the request

| **Field name** | **Type**              | **Description**                                                                                                                       |
| -------------- | -------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| mechanismId    | OID                  | Key algorithm identifier                                                                                                  |
| parameterId    | OID<br>or<br>String | Key parameter identifier:<br>OID – EC curve identifier;<br>String – RSA key length in bits (number)<br>Optional |
| label          | String               | Text label of the key. Optional                                                                                        |
| application    | String               | Text label of the application. Optional                                                                                   |

### Structure of the result field in the response

| **Field name** | **Type** | **Description**                        |
| -------------- | ------- | ------------------------------- |
| id             | Hex     | Key identifier. Unique |

### Request example

```
{
  "method": "CREATE_KEY",
  "parameters": {
    "mechanismId": "1.2.804.2.1.1.1.1.3.1.1",
    "parameterId": "1.2.804.2.1.1.1.1.3.1.1.2.6",
    "label": "new DSTU4145-key, M257_PB"
  }
}
```

### Response example

```
{
  "errorCode": 0,
  "method": "CREATE_KEY",
  "result": {
    "id": "112233445566...DDEEFF00"
  }
}
```

## DELETE_KEY method

The method is intended for destroying a key on the open storage. Output parameters: none.

### Structure of the parameters field in the request

| **Field name** | **Type** | **Description**                        |
| -------------- | ------- | ------------------------------- |
| id             | Hex     | Key identifier. Unique |

### Request example
```
{
  "method": "DELETE_KEY",
  "parameters": {
    "id": "112233445566...DDEEFF00"
  }
}
```

### Response example

```
{
  "errorCode": 0,
  "method": "DELETE_KEY",
  "result": {}
}
```

## GET_CSR method

The method is intended for obtaining a certificate request (CSR) for the currently selected key. If the signature algorithm is not specified, the first signature algorithm from the key's signAlgo list is used.

If the CM provider implements a certificate request generation function, that function will be used; otherwise, the certificate request will be generated by the method's internal code.

### Structure of the parameters field in the request

| **Field name**       | **Type** | **Description**                                                                                                                            |
| -------------------- | ------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| signAlgo             | String  | Signature algorithm. Optional                                                                                                      |
| signAlgoParams       | Base64  | Signature algorithm parameters (DER encoding).<br>Optional                                                                        |
| subject              | Base64  | Key owner description (DER encoding of the Name<br>structure). Optional                                                                 |
| attributes           | Base64  | Request attributes (DER encoding). Optional                                                                                       |
| ignoreProviderGetCsr | Boolean | Ignore the GetCsr function in the CM provider,<br>use the method's internal code to generate the<br>certificate request. Optional |

### Structure of the result field in the response

| **Field name** | **Type** | **Description**                                                 |
| -------------- | ------- | -------------------------------------------------------- |
| bytes          | Base64  | Certificate request<br>(per the x.509 standard) |

### Request example
```
{
  "method": "GET_CSR",
  "parameters": {
    "signAlgo": "1.2.804.2.1.1.1.1.3.1.1"
  }
}
```

### Response example

```
{
  "errorCode": 0,
  "method": "GET_CSR",
  "result": {
    "bytes": "MIIBJTCBzgIBADAAMIGIMGA...xV235n6GixwS"
  }
}
```

## BUILD_CSR_2PASS method

The method is intended for two-pass generation of a certificate request according to PKCS#10 (CSR):

1. on the first pass, the data to be signed is generated;

2. on the second pass - the certificate request.

The input and output parameters for the first pass are named step1, for the second - step2. The step1 and step2 parameters are optional, but at least one of them must be specified in the request.

### Structure of the parameters field in the request

| **Field name** | **Type**                   | **Description**                        |
| -------------- | -------------------------- | -------------------------------------- |
| step1          | Object<br>STEP1_CSR_PARAMS | Data for the first pass. Optional      |
| step2          | Object<br>STEP2_CSR_PARAMS | Data for the second pass. Optional     |

### Structure STEP1_CSR_PARAMS

| **Field name**       | **Type**                         | **Description**                                 |
| -------------------- | -------------------------------- | ----------------------------------------------- |
| subject              | Base64                           | Description of the key owner. Optional          |
| subjectPublicKeyInfo | Object<br>SUBJECT_PUBLICKEY_INFO | Public key parameters                           |
| extensionRequest     | Object<br>EXTNREQUEST_INFO       | Request extension parameters. Optional          |
| digestAlgo           | OID                              | Digest algorithm identifier. Optional           |

### Structure STEP2_CSR_PARAMS

| **Field name** | **Type** | **Description**                                                          |
| -------------- | ------- | ------------------------------------------------------------------------ |
| bytes          | Base64  | The data that was signed (corresponds to the<br>CertificationRequestInfo structure) |
| signAlgo       | OID     | Signature algorithm identifier                                           |
| signAlgoParams | Base64  | Signature algorithm parameters. Optional                                 |
| signBytes      | Base64  | Signature value                                                          |

### Structure of the result field in the response

| **Field name** | **Type**                   | **Description**                         |
| -------------- | -------------------------- | --------------------------------------- |
| step1          | Object<br>STEP1_CSR_RESULT | Result of the first pass. Optional      |
| step2          | Object<br>STEP2_CSR_RESULT | Result of the second pass. Optional     |

### Structure STEP1_CSR_RESULT

| **Field name** | **Type** | **Description**                                                         |
| -------------- | ------- | ----------------------------------------------------------------------- |
| bytes          | Base64  | Generated data corresponding to the<br>CertificationRequestInfo structure |
| digestBytes    | Base64  | Digest value of the bytes field. Optional                               |

### Structure STEP2_CSR_RESULT

| **Field name** | **Type** | **Description**                        |
| -------------- | ------- | -------------------------------------- |
| bytes          | Base64  | Generated data (certificate request)   |

### Request example (first pass)

```
{
  "method": "BUILD_CSR_2PASS",
  "parameters": {
    "step1": {
      "subjectPublicKeyInfo": {
        "algorithm": "1.2.840.10045.2.1",
        "parameters": "BggqhkjOPQMBBw==",
        "publicKey": "BAhBtGOvW1zu...u3mwMTP8Sww="
      },
      "extensionRequest": {
        "subjectKeyIdentifier": "7680377DDCD6...B896100E0081"
      },
      "digestAlgo": "2.16.840.1.101.3.4.2.1"
    }
  }
}
```

### Response example (first pass)

```
{
  "errorCode": 0,
  "method": "BUILD_CSR_2PASS",
  "result": {
    "step1": {
      "bytes": "MIGSAgEAMAAw...mtq4lhAOAIE=",
      "digestBytes": "2i/pfJXv9CTz7an9S4RB2z+ioI+W2uu90GL0sv7PN4E="
    }
  }
}
```

### Request example (second pass)

```
{
  "method": "BUILD_CSR_2PASS",
  "parameters": {
    "step2": {
      "bytes": "MIGSAgEAMAAw...mtq4lhAOAIE=",
      "signAlgo": "1.2.840.10045.4.3.2",
      "signBytes": "MEUCIBqTf+1q...hEzMe/fPosI="
    }
  }
}
```

### Response example (second pass)

```
{
  "errorCode": 0,
  "method": "BUILD_CSR_2PASS",
  "result": {
    "step2": {
      "bytes": "MIHrMIGSAgEA...TMx798+iwg=="
    }
  }
}
```

## VERIFY_CSR method

The method is intended for validating the signature and obtaining information from a certificate request generated according to the PKCS#10 format.

### Structure of the parameters field in the request

| **Field name** | **Type** | **Description**     |
| -------------- | ------- | ------------------- |
| bytes          | Base64  | Certificate request |

### Structure of the result field in the response

| **Field name**       | **Type**                         | **Description**                                                                                            |
| -------------------- | -------------------------------- | --------------------------------------------------------------------------------------------------------- |
| signatureInfo        | Object<br>SIGNATURE_INFO         | Electronic signature of the certificate                                                                   |
| version              | Integer                          | Certificate request version                                                                                |
| subject              | Object                           | Description of the key owner. Optional                                                                     |
| subjectPublicKeyInfo | Object<br>SUBJECT_PUBLICKEY_INFO | Public key parameters                                                                                      |
| keyId                | Hex                              | Key identifier, calculated on the public key<br>value with the corresponding digest<br>algorithm           |
| keyId2               | Hex                              | Key identifier keyId2 (based on Kupyna-256).<br>Optional, present only for DSTU keys                       |
| attributes           | Object[]<br>ATTRIBUTE_PARAMS[]   | Array of attributes stored in the attributes field.<br>Optional                                            |
| extensionRequest     | Object<br>EXTNREQUEST_INFO       | Certificate request extensions. Optional                                                                   |
| statusSignature      | String                           | Electronic signature status:<br>"VALID", "INVALID", "FAILED"                                               |

### Structure SIGNATURE_INFO

| **Field name** | **Type** | **Description**                           |
| -------------- | ------- | ----------------------------------------- |
| algorithm      | OID     | Signature algorithm identifier            |
| parameters     | Base64  | Signature algorithm parameters. Optional  |
| signature      | Base64  | Signature value                           |

### Structure EXTNREQUEST_INFO

| **Field name**       | **Type**                      | **Description**                        |
| -------------------- | ----------------------------- | -------------------------------------- |
| extensions           | Object[],<br>EXTENSION_INFO[] | Array of extensions                    |
| subjectKeyIdentifier | Hex                           | Key identifier. Optional               |
| extendedKeyUsage     | OID[]                         | Array of identifiers. Optional         |
| pkaBytes             | Base64                        | Private key attestation. Optional      |

### Request example

```
{
  "method": "VERIFY_CSR",
  "parameters": {
    "bytes": "MIIBXDCCAQEC...63/lpcHviw=="
  }
}
```

### Response example
```
{
  "errorCode": 0,
  "method": "VERIFY_CSR",
  "result": {
    "signatureInfo": {
      "algorithm": "1.2.840.10045.4.3.2",
      "signature": "MEYCIQDDNLPc...MFjrf+Wlwe+L"
    },
    "version": 0,
    "subject": { "CN": "Приклад запиту" },
    "subjectPublicKeyInfo": {
      "algorithm": "1.2.840.10045.2.1",
      "parameters": "BggqhkjOPQMBBw==",
      "publicKey": "BIa8LPLIfFJt...Qjd0gjvYJXw=",
      "bytes": "MFkwEwYHKoZI...N3SCO9glfA=="
    },
    "keyId": "643F80BA40B03FB45F0F6249D4AFA79E2EF63143",
    "attributes": [
      {
        "type": "1.2.840.113549.1.9.14",
        "bytes": "MGgwHQYDVR0O...BgQAjkYBBA=="
      }
    ],
    "extensionRequest": {
      "extensions": [
        { "extnId": "2.5.29.14", "extnValue": "BBRkP4C6QLA/tF8PYknUr6eeLvYxQw==" },
        { "extnId": "2.5.29.37", "critical": true, "extnValue": "MAoGCCsGAQUFBwMI" },
        ...
      ],
      "subjectKeyIdentifier": "643F80BA40B0...A79E2EF63143",
      "extendedKeyUsage": ["1.3.6.1.5.5.7.3.8"]
    },
    "statusSignature": "VALID"
  }
}
```

## CHANGE_PASSWORD method

The method is intended for changing the access password of an opened storage. Output parameters: none.

### Structure of the parameters field in the request

| **Field name** | **Type** | **Description** |
| -------------- | ------- | ------------ |
| newPassword    | String  | New password |

### Request example
```
{
  "method": "CHANGE_PASSWORD",
  "parameters": {
    "newPassword": "newpass"
  }
}
```

### Response example

```
{
  "errorCode": 0,
  "method": "CHANGE_PASSWORD",
  "result": {}
}
```

## INIT_KEY_USAGE method

The method is intended for initializing key usage. The request and result parameters depend on the storage. Most storages do not require calling this method.

### Request example

```
{
  "method": "INIT_KEY_USAGE",
  "parameters": {
    ...
  }
}
```

### Response example

```
{
  "errorCode": 0,
  "method": "INIT_KEY_USAGE",
  "result": {}
}
```

## SIGN method

The method is intended for signing data.

In the offline state, the library can create a signature in the CAdES-BES format - verification of the owner's certificate status will be performed using CRLs, without using OCSP.

Additional signature parameters can be specified in the options (the "options" field).

When the "ignoreCertStatus" parameter is set to true, the status of the key owner's certificate will not be checked during signing. This option is available only for the CAdES-BES and CAdES-T signature formats; for other signature formats it will be ignored.

When the "checkTrustedRoot" parameter is set to true, the status check of the key owner's certificate (and of the time-stamp certificate) requires the certificate chain to end in a trusted root certificate, otherwise the error CERT_NOT_TRUSTED is returned. Default false: whether to trust is decided by the one who verifies the signature. If the status is not checked ("ignoreCertStatus"), the parameter has no effect.

Signature formats are described in Appendix B. In the formats "CAdES-B-LT" and "CAdES-B-LTA" (ETSI EN 319 122-1) the signature is made as CAdES-T with the signingTime attribute, then it is validated and augmented with the validation data (and the archive time-stamp) by the code of the AUGMENT_CMS method; the revocation data obtained when signing is used. If the validation does not give "TOTAL-VALID", the error NOT_ALLOWED is returned. For compatibility the SIGN and BUILD_CMS_2PASS methods accept the names "CAdES-LT" and "CAdES-LTA" as synonyms of "CAdES-XL" and "CAdES-A" respectively. These are not the B-LT and B-LTA levels of the baseline signatures of ETSI EN 319 122-1: those keep the validation data in SignedData and have no reference and value attributes.

### Structure of the parameters field in the request

| **Field name** | **Type**                       | **Description**                             |
| -------------- | ------------------------------ | ------------------------------------------- |
| signParams     | Object,<br>SIGN_PARAMS         | Set of signature parameters                 |
| dataTbs        | Object[],<br>DATA_TBS_PARAMS[] | Array of structures containing the data to be signed |
| options        | Object,<br>OPTION_PARAMS       | Set of additional parameters. Optional      |

### Structure SIGN_PARAMS

| **Field name**   | **Type** | **Description**                                                                                                         |
| ---------------- | ------- | ----------------------------------------------------------------------------------------------------------------------- |
| signatureFormat  | String  | Signature format:<br>"RAW", "CMS", "CAdES-BES", "CAdES-T", "CAdES-C",<br>"CAdES-XL", "CAdES-A", "CAdES-B-LT", "CAdES-B-LTA" |
| signAlgo         | OID     | Signature algorithm identifier. Optional                                                                                |
| digestAlgo       | OID     | Digest algorithm identifier. Optional.<br>For the RSASSA-PSS signature algorithm ("1.2.840.113549.1.1.10") —<br>also the hash of the signature, SHA-256 by default |
| detachedData     | Boolean | Detached signature (data is not encapsulated).<br>Optional, default true                                                |
| includeCert      | Boolean | Add the key owner's certificate to the signature.<br>Optional, default false                                            |
| includeTime      | Boolean | Add the host time (untrusted) to the signature.<br>Optional, default false                                              |
| includeContentTS | Boolean | Add a content timestamp to the signature<br>(for any signature format).<br>Optional, default false                      |
| signaturePolicy  | Object  | Signature policy, contains the sigPolicyId field (OID —<br>signature policy identifier). Optional                       |

### Structure DATA_TBS_PARAMS

| **Field name**     | **Type**                        | **Description**                                                                                                                |
| ------------------ | ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| id                 | String                          | Data identifier                                                                                                                |
| bytes              | Base64                          | Data to be signed                                                                                                              |
| file               | String                          | File that stores the data to be signed                                                                                         |
| ptr                | Hex                             | Pointer to the memory where the data to be signed<br>is stored. The pointer size depends on the hardware<br>and software platform |
| size               | Integer                         | Number of bytes of data to be signed                                                                                           |
| type               | OID                             | Data type identifier. Optional, default<br>"1.2.840.113549.1.7.1" (data)                                                       |
| isDigest           | Boolean                         | Type of data to be signed. If true, the bytes field<br>contains a digest, otherwise the original data. Optional,<br>default false |
| signedAttributes   | Object[],<br>ATTRIBUTE_PARAMS[] | Array of structures containing attribute data for the<br>signed part of the signature. Optional                                |
| unsignedAttributes | Object[],<br>ATTRIBUTE_PARAMS[] | Array of structures containing attribute data for the<br>unsigned part of the signature. Optional                              |

### Structure ATTRIBUTE_PARAMS

| **Field name** | **Type** | **Description**             |
| -------------- | ------- | --------------------------- |
| type           | OID     | Attribute type identifier   |
| bytes          | Base64  | Attribute data              |

### Structure OPTION_PARAMS

| **Field name**   | **Type** | **Description**                                                                        |
| ---------------- | ------- | ------------------------------------------------------------------------------------- |
| ignoreCertStatus | Boolean | Do not check the status of the key owner's certificate.<br>Optional, default false     |
| checkTrustedRoot | Boolean | The chain of the key owner's certificate must end in<br>a trusted root certificate.<br>Optional, default false |

### Structure of the result field in the response

| **Field name** | **Type**                         | **Description**                                                                                      |
| -------------- | -------------------------------- | --------------------------------------------------------------------------------------------------- |
| digestAlgo     | OID                              | Identifier of the digest algorithm that was<br>used                                                 |
| signerCertId   | Base64                           | Signer certificate identifier.<br>Optional — absent for the "RAW" format and for<br>signing by keyId (if includeCert is not set) |
| signatures     | Object[],<br>SIGNATURE_PARAMS[]  | Array of SIGNATURE_PARAMS structures containing<br>the signed data                                  |
| expectedCerts  | Object[]<br>EXPECTED_CERT_INFO[] | Array of information about a certificate required<br>for creating the signature. Optional — present<br>only on error (see the VERIFY method)  |
| expectedCrls   | Object[]<br>EXPECTED_CRL_INFO[]  | Array of information about a CRL file required<br>for creating the signature. Optional — present<br>only on error (see the VERIFY method)    |

### Structure SIGNATURE_PARAMS

| **Field name**     | **Type** | **Description**                                                              |
| ------------------ | ------- | ----------------------------------------------------------------------------- |
| id                 | String  | Data identifier                                                              |
| bytes              | Base64  | Signature data                                                               |
| contentType        | OID     | Content type identifier. Optional                                            |
| messageDigest      | Base64  | Message digest value                                                         |
| signingTime        | Time    | Host time (untrusted). Optional                                              |
| contentTimeStamp   | Time    | Content timestamp value. Optional                                            |
| signatureTimeStamp | Time    | Signature timestamp value. Optional                                          |
| archiveTimeStamp   | Time    | Archive timestamp value. Optional                                            |
| warnings           | String[] | Remarks on the augmentation of the signature (the formats "CAdES-B-LT"<br>and "CAdES-B-LTA"), as in the AUGMENT_CMS method. Optional |

### Request example

```
{
  "method": "SIGN",
  "parameters": {
    "signParams": {
      "signatureFormat": "CAdES-BES",
      "signAlgo": "1.2.804.2.1.1.1.1.3.1.1",
      "detachedData": true,
      "includeCert": false,
      "includeTime": true
    },
    "dataTbs": [
      { "id": "doc-0", "bytes": "VGhlIHF1aWNrIGJyb...p5IGRvZw==" },
      { "id": "doc-1", "bytes": "VHJpcGxlIENyb3duIG9mIE1vdG9yc3BvcnQ=" }
    ]
  }
}
```

### Response example

```
{
  "errorCode": 0,
  "method": "SIGN",
  "result": {
    "signatures": [
      { "id": "doc-0", "bytes": "MIISxQYJKoZIhvcNAQcCo...y26i8X+13kQ/l6" },
      { "id": "doc-1", "bytes": "MIIHcgYJKoZIhvcNAQcCo...C719o6rNlQUrTOsBx8=" }
    ]
  }
}
```

## BUILD_CMS_2PASS method

The method is intended for two-pass generation of a signature according to PKCS#7 (CMS):

1. on the first pass, the data to be signed (the signedAttributes field) is generated;

2. on the second pass - the signature.

The input and output parameters for the first pass are named step1, for the second - step2. The step1 and step2 parameters are optional, but at least one of them must be specified in the request.

The method supports generation of PKCS#7 signatures of the following formats: "CMS", "CAdES-BES", "CAdES-T", "CAdES-XL", "CAdES-A", "CAdES-B-LT" and "CAdES-B-LTA". For "CAdES-B-LT" and "CAdES-B-LTA" the signed attributes of the first pass must contain signingTime (the includeTime or signingTime parameter), otherwise the second pass returns the error ATTRIBUTE_NOT_PRESENT; on the second pass the signature is validated and augmented in the same way as by the SIGN method.

On the first pass, data corresponding to the signedAttributes structure is generated. Additionally, the hash value of this data can be obtained: the digestAlgo parameter must be specified - the result will be in the digestBytes field.

On the second pass, all parameters required for the final generation of the PKCS#7 signature are specified.

To generate a CAdES signature, on the first pass the certId and includeSigningCert (value true) parameters must be specified, and on the second pass the certId and signatureFormat parameters with the corresponding CAdES format value. When a CAdES signature is created with a timestamp, the signatureFormat parameter with one of the values "CAdES-T", "CAdES-XL", "CAdES-A", "CAdES-B-LT" and "CAdES-B-LTA" must be specified on the second pass. A content timestamp is added on the first pass with the includeContentTS parameter (value true), for any signature format.

### Structure of the parameters field in the request

| **Field name** | **Type**                   | **Description**                        |
| -------------- | -------------------------- | -------------------------------------- |
| step1          | Object<br>STEP1_CMS_PARAMS | Data for the first pass. Optional      |
| step2          | Object<br>STEP2_CMS_PARAMS | Data for the second pass. Optional     |

### Structure of STEP1_CMS_PARAMS

| **Field name**     | **Type**                        | **Description**                                                                                                    |
| ------------------ | ------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| digestAlgo         | OID                             | Hash algorithm identifier. Optional                                                                               |
| digestAlgoParams   | Base64                          | Hash algorithm parameters (DER encoding).<br>Optional                                                             |
| contentType        | OID                             | Content type identifier. Optional, defaults<br>to "1.2.840.113549.1.7.1" (data)                                   |
| messageDigest      | Base64                          | Message digest value                                                                                              |
| includeTime        | Boolean                         | Add the current host time (untrusted).<br>Optional, defaults to false                                             |
| signingTime        | Time                            | Add a specified host time (untrusted).<br>Optional                                                                |
| certId             | Base64                          | Certificate identifier in the certificate cache.<br>Optional                                                      |
| includeSigningCert | Boolean                         | Add the signingCertificateV2 attribute (mandatory<br>for a CAdES signature).<br>Optional, defaults to false       |
| includeContentTS   | Boolean                         | Add a content timestamp<br>(for any signature format).<br>Optional, defaults to false                             |
| signedAttributes   | Object[],<br>ATTRIBUTE_PARAMS[] | Add an array of attributes to be signed.<br>Optional                                                              |

### Structure of STEP2_CMS_PARAMS

| **Field name**     | **Type**                        | **Description**                                                                                        |
| ------------------ | ------------------------------- | ----------------------------------------------------------------------------------------------------- |
| bytes              | Base64                          | Signed attributes (the signedAttributes field)                                                         |
| signatureFormat    | String                          | Signature format:<br>"CMS", "CAdES-BES", "CAdES-T",<br>"CAdES-XL", "CAdES-A", "CAdES-B-LT", "CAdES-B-LTA" |
| signAlgo           | OID                             | Signature algorithm identifier                                                                         |
| signAlgoParams     | Base64                          | Signature algorithm parameters. Optional                                                               |
| signBytes          | Base64                          | Signature value of the signed attributes                                                               |
| digestAlgo         | OID                             | Hash algorithm identifier                                                                              |
| digestAlgoParams   | Base64                          | Hash algorithm parameters (DER encoding).<br>Optional                                                  |
| certId             | Base64                          | Certificate identifier in the certificate cache.<br>Mandatory for a CAdES signature; optional for a CMS<br>signature (the certificate for includeCert) |
| keyId              | Hex                             | Key identifier (the value of the id field of the KEYS<br>method).<br>Only for a CMS signature          |
| contentBytes       | Base64                          | Content data. Optional                                                                                 |
| includeCert        | Boolean                         | Add the key owner's certificate. For a CMS signature<br>without certId the certificate is found in the cache<br>by keyId; if it is absent - the error CERT_NOT_FOUND.<br>Optional, defaults to false |
| unsignedAttributes | Object[],<br>ATTRIBUTE_PARAMS[] | Add an array of unsigned attributes.<br>Optional                                                       |
| options            | Object,<br>OPTION_PARAMS        | Set of additional parameters. Optional                                                                 |

### Structure of the result field in the response

| **Field name** | **Type**                   | **Description**                         |
| -------------- | -------------------------- | --------------------------------------- |
| step1          | Object<br>STEP1_CMS_RESULT | Result of the first pass. Optional      |
| step2          | Object<br>STEP2_CMS_RESULT | Result of the second pass. Optional     |

### Structure of STEP1_CMS_RESULT

| **Field name**                    | **Type**             | **Description**                                              |
| --------------------------------- | -------------------- | ------------------------------------------------------------ |
| bytes                             | Base64               | Generated data to be signed (the<br>signedAttributes field)  |
| contentType                       | OID                  | Content type identifier                                      |
| digestBytes                       | Base64               | Hash value of the bytes field. Optional                      |
| signingTime                       | Time                 | Host time. Optional                                          |

### Structure of STEP2_CMS_RESULT

| **Field name** | **Type** | **Description**                  |
| -------------- | ------- | ------------------------------- |
| bytes          | Base64  | Generated data (PKCS#7 signature) |

### Request example (first pass)

```
{
  "method": "BUILD_CMS_2PASS",
  "parameters": {
    "step1": {
      "digestAlgo": "1.2.804.2.1.1.1.1.2.2.1",
      "contentType": "1.2.840.113549.1.7.1",
      "messageDigest": "mWiZ8tdCLOr1UkdQNrLcEgYH7/U4q/K43/RxqYpHQMY=",
      "signingTime": "2026-05-11 11:53:00",
      "certId": "MIHNMIG0MSEw...OgAA174CAA==",
      "includeSigningCert": true,
      "includeContentTS": true
    }
  }
}
```

### Response example (first pass)

```
{
  "errorCode": 0,
  "method": "BUILD_CMS_2PASS",
  "result": {
    "step1": {
      "bytes": "MYIBkTAYBgkq...AFY6AADXvgIA",
      "digestBytes": "NwkHivRMiML5IClu5hXlgmBeDk4dpAxgWWaYhnTL6qs=",
      "contentType": "1.2.840.113549.1.7.1",
      "signingTime": "2026-05-11 11:53:00"
    }
  }
}
```

### Request example (second pass)

```
{
  "method": "BUILD_CMS_2PASS",
  "parameters": {
    "step2": {
      "bytes": "MYIBkTAYBgkq...AFY6AADXvgIA",
      "signatureFormat": "CAdES-T",
      "signAlgo": "1.2.804.2.1.1.1.1.3.6.1.1",
      "signBytes": "vKX9KpnUKB/C...tQ+Se4vhTg==",
      "digestAlgo": "1.2.804.2.1.1.1.1.2.2.1",
      "certId": "MIHNMIG0MSEw...OgAA174CAA==",
      "contentBytes": "VGhlIHF1aWNr...YXp5IGRvZw==",
      "includeCert": true
    }
  }
}
```

### Response example (second pass)

```
{
  "errorCode": 0,
  "method": "BUILD_CMS_2PASS",
  "result": {
    "step2": {
      "bytes": "MIIIiQYJKoZI...XbUPknuL4U4="
    }
  }
}
```

## MODIFY_CMS method

The method is intended for manipulations with a PKCS#7 signature that do not change the value of the electronic signature: add/remove content, add/remove a certificate, add/remove a CRL, add/remove a signature (SignerInfo structure).

When generating a new PKCS#7 signature, the removal operations (the remove field) are performed first, and then the additions (the add field).

### Structure of the parameters field in the request

| **Field name** | **Type**                 | **Description**                     |
| -------------- | ------------------------ | ----------------------------------- |
| bytes          | Base64                   | PKCS#7 signature                    |
| add            | Object<br>MODCMS_ADD     | Add to the signature. Optional      |
| options        | Object<br>MODCMS_OPTIONS | Options. Optional                   |
| remove         | Object<br>MODCMS_REMOVE  | Remove from the signature. Optional |

### Structure of MODCMS_ADD

| **Field name** | **Type**  | **Description**                                                        |
| -------------- | -------- | -------------------------------------------------------------------- |
| bytes          | Base64   | Add a PKCS#7 signature or a signature (SignerInfo<br>structure)       |
| isSignerInfo   | Boolean  | Flag indicating that the bytes field contains a signature<br>(SignerInfo structure) |
| signIndex      | Integer  | Set the order for the signature                                       |
| content        | Base64   | Add content                                                           |
| certificates   | Base64[] | Add certificates                                                      |
| crls           | Base64[] | Add CRLs                                                              |

### Structure of MODCMS_OPTIONS

| **Field name**          | **Type** | **Description**                                              |
| ----------------------- | ------- | ------------------------------------------------------------ |
| returnContent           | Boolean | Return the content value. Optional                           |
| returnCerts             | Boolean | Return the certificate values. Optional                      |
| returnCrls              | Boolean | Return the CRL values. Optional                              |
| returnEncodedSignerInfo | Boolean | Return the DER-encoded SignerInfo structure.<br>Optional     |

### Structure of MODCMS_REMOVE

| **Field name** | **Type** | **Description**             |
| -------------- | ------- | ------------------------ |
| content        | Boolean | Remove the content       |
| signIndex      | Integer | Remove a signature part  |
| certificates   | Boolean | Remove all certificates  |
| crls           | Boolean | Remove all CRLs          |

### Structure of the result field in the response

| **Field name**   | **Type**                      | **Description**                              |
| ---------------- | ----------------------------- | ------------------------------------------- |
| version          | Integer                       | SignedData version                           |
| digestAlgorithms | OID[]                         | Array of hash algorithm identifiers          |
| content          | Object<br>CONTENT_INFO        | CONTENT_INFO structure                       |
| signatureInfos   | Object[]<br>MODCMS_SIGNINFO[] | Array of basic information for each signature |
| certificates     | Base64[]                      | Array of certificates. Optional —<br>present if the returnCerts option is set       |
| crls             | Base64[]                      | Array of CRLs. Optional — present<br>if the returnCrls option is set                 |
| bytes            | Base64                        | Generated data                               |

### Structure of MODCMS_SIGNINFO

| **Field name** | **Type** | **Description**                                                                                 |
| -------------- | ------- | --------------------------------------------------------------------------------------------- |
| version        | Integer | SignatureInfo version                                                                          |
| serialNumber   | Hex     | Serial number of the signature owner's certificate.<br>Optional                                |
| issuerBytes    | Base64  | Issuer of the signature owner's certificate.<br>Optional, in DER-encoded form.<br>Optional     |
| issuer         | Object  | Issuer of the signature owner's certificate.<br>Optional                                       |
| keyId          | Hex     | Key identifier of the signature owner.<br>Optional                                             |
| signAlgo       | OID     | Signature algorithm identifier                                                                 |
| digestAlgo     | OID     | Hash algorithm identifier                                                                      |
| contentType    | OID     | Content type identifier                                                                        |
| messageDigest  | Base64  | Message (content) digest value                                                                 |
| bytes          | Base64  | DER-encoded SignerInfo structure.<br>Optional — present if the<br>returnEncodedSignerInfo option is set |

### Request example “adding Bob's PKCS#7 signature and certificate to Alice's PKCS#7 signature”

```
{
  "method": "MODIFY_CMS",
  "parameters": {
    "bytes": "MIIIiQYJKoZI...t7BYR9fjvW4=",
    "add": {
      "bytes": "MIIIgAYJKoZI...E7uXVgWidTE=",
      "certificates": [ "MIIFRDCCBOug...5AsbTvm6d2s=" ]
    }
  }
}
```

### Response example “adding Bob's PKCS#7 signature and certificate to Alice's PKCS#7 signature”

```
{
  "errorCode": 0,
  "method": "MODIFY_CMS",
  "result": {
    "version": 1,
    "digestAlgorithms": [
      "1.2.804.2.1.1.1.1.2.2.1"
    ],
    "content": {
      "type": "1.2.840.113549.1.7.1"
    },
    "signatureInfos": [
      {
        "version": 1,
        "serialNumber": "29DA764793476CCC04000000563A0000D7BE0200",
        "issuerBytes": "MIG0MSEwHwYD...LTQzMzk1MDMz",
        "issuer": {
          "C": "UA",
          ...
        },
        "signAlgo": "1.2.804.2.1.1.1.1.3.6.1.1",
        "digestAlgo": "1.2.804.2.1.1.1.1.2.2.1",
        "contentType": "1.2.840.113549.1.7.1",
        "messageDigest": "mWiZ8tdCLOr1UkdQNrLcEgYH7/U4q/K43/RxqYpHQMY="
      }
    ],
    "bytes": "MIIQngYJKoZI...sFhH1+O9bg=="
  }
}
```

### Request example “do not modify the PKCS#7 signature, get the content and certificates”

```
{
  "method": "MODIFY_CMS",
  "parameters": {
    "bytes": "MIIIiQYJKoZI...t7BYR9fjvW4=",
    "options": {
      "returnContent": true,
      "returnCerts": true,
      "returnCrls": true
    }
  }
}
```

### Response example “do not modify the PKCS#7 signature, get the content and certificates”

```
{
  "errorCode": 0,
  "method": "MODIFY_CMS",
  "result": {
    "version": 1,
    "digestAlgorithms": [
      "1.2.804.2.1.1.1.1.2.2.1"
    ],
    "content": {
      "type": "1.2.840.113549.1.7.1",
      "bytes": "VGhlIHF1aWNr...YXp5IGRvZw=="
    },
    "signatureInfos": [
      {
        "version": 1,
        "serialNumber": "29DA764793476CCC04000000563A0000D7BE0200",
        "issuerBytes": "MIG0MSEwHwYD...LTQzMzk1MDMz",
        "issuer": {
          "C": "UA",
          ...
        },
        "signAlgo": "1.2.804.2.1.1.1.1.3.6.1.1",
        "digestAlgo": "1.2.804.2.1.1.1.1.2.2.1",
        "contentType": "1.2.840.113549.1.7.1",
        "messageDigest": "mWiZ8tdCLOr1UkdQNrLcEgYH7/U4q/K43/RxqYpHQMY="
      }
    ],
    "certificates": [
      "MIIFTTCCBPSg...7rZDBCa9wkY="
    ],
    "crls": []
  }
}
```

### Request example “get the content and remove the content from the PKCS#7 signature”

```
{
  "method": "MODIFY_CMS",
  "parameters": {
    "bytes": "MIIIiQYJKoZI...t7BYR9fjvW4=",
    "remove": { "content": true },
    "options": { "returnContent": true }
  }
}
```

### Request example “add content to the PKCS#7 signature”

```
{
  "method": "MODIFY_CMS",
  "parameters": {
    "bytes": "MIIIiQYJKoZI...t7BYR9fjvW4=",
    "add": { "content": "VGhlIHF1aWNr...YXp5IGRvZw==" }
  }
}
```

## AUGMENT_CMS method

The method is intended for the augmentation of a CAdES signature (ETSI EN 319 102-1, 4.3.3-4.3.5; ETSI EN 319 122-1): CAdES-BES -> CAdES-T, CAdES-BES or CAdES-T -> CAdES-B-LT or CAdES-B-LTA, CAdES-B-LT -> CAdES-B-LTA. No key is needed.

Signatures with the attributes of the CAdES-C, CAdES-XL and CAdES-A formats (certificateRefs, revocationRefs, certValues, revocationValues, CAdES-C-timestamp, time-stamped-certs-crls-references) are not augmented - the error NOT_SUPPORTED: the B-LT and B-LTA levels do not have these attributes.

If the signature already has the CAdES-B-LTA format, the format "CAdES-B-LTA" adds the next archive time-stamp (re-archiving, ETSI EN 319 102-1, 4.3.5): first the validation data of the earlier time-stamps (the TSA certificates and their revocation data) is added to SignedData, then a new archive-time-stamp-v3 whose index covers the earlier archive time-stamps too. Re-archiving is done before the TSA certificate of the earlier archive time-stamp expires or before its algorithms stop being considered strong. No data is added to SignedData if the signature has an archive time-stamp without an index in its token (CAdES-A of earlier versions of the library) - the error NOT_SUPPORTED.

The format "CAdES-A" is for a signature with the attributes of ETSI TS 101 733 (CAdES-C, CAdES-XL, CAdES-A): a new archive-time-stamp-v3 with ats-hash-index-v3 is added. For a signature without such attributes ("CAdES-B-LTA" is used) and for a signature with an archive-time-stamp of the earlier version (id-aa-ets-archiveTimestampV2) - the error NOT_SUPPORTED.

A detached signature (the data is not encapsulated) needs the data: the "content", "file" or "ptr" and "size" field of the SIGNATURE_DATA structure, as in the VERIFY method; with "isDigest" true the "content" field contains the hash of the data by the digest algorithm of the signature. Without the data the validation gives INDETERMINATE, and the signature is not augmented.

The freshness of the revocation data is set by the "options.revocationFreshness" parameter (minutes, from 0 to 120, default 120): if the signature has no revocation data yet, the OCSP responses from the cache and the CRLs from the CRL cache issued (thisUpdate) earlier than the given number of minutes before the call of the method are obtained again; 0 - always new data. An OCSP responder working by CRLs returns thisUpdate of that CRL. The data the signature already has is used as it is.

### Structure of the parameters field in the request

| **Field name**  | **Type**                 | **Description**                                                                                              |
| --------------- | ------------------------ | ------------------------------------------------------------------------------------------------------------ |
| signature       | Object<br>SIGNATURE_DATA | SIGNATURE_DATA structure (as in the VERIFY method): the signature and, for a detached signature, the data     |
| signatureFormat | String                   | The format the signature is augmented to:<br>"CAdES-T", "CAdES-B-LT", "CAdES-B-LTA", "CAdES-A"               |
| signerInfoIndex | Integer                  | Index of the signature (SignerInfo structure), the first is 0.<br>Optional, by default all the signatures are augmented |
| options         | Object<br>AUGMENT_OPTIONS | Validation parameters. Optional                                                                             |

### Structure of AUGMENT_OPTIONS

| **Field name**          | **Type** | **Description**                                                                                                               |
| ----------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------ |
| revocationFreshness     | Integer | Freshness of the revocation data (minutes, 0-120).<br>Optional, defaults to 120                                                |
| onlyCrl                 | Boolean | Use CRLs exclusively. Optional, defaults to<br>"validationByCrl" of the initialization                                         |
| checkCriticalExtensions | Boolean | As in the VERIFY method. Optional, defaults to false                                                                           |
| caRemovesExpiredCerts   | Boolean | As in the VERIFY method. Optional, defaults to false                                                                           |

### Structure of the result field in the response

| **Field name** | **Type**                     | **Description**                                                                                                           |
| -------------- | ---------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| bytes          | Base64                       | The augmented signature                                                                                                   |
| signatureInfos | Object[]<br>SIGNATURE_INFO[] | The result of the validation of the augmented signatures, as in the VERIFY method.<br>Present for the formats "CAdES-B-LT" and "CAdES-B-LTA", also on the error NOT_ALLOWED |
| warnings       | String[]                     | Remarks on the augmentation, e.g. "THE CRL OF THE OCSP RESPONDER<br>IS NOT EMBEDDED (SIZE LIMIT)" - the CRL of an OCSP responder is bigger<br>than "ocsp.responderCrlEmbedMaxSize" of INIT and not embedded. Optional |

### Example request

```
{
  "method": "AUGMENT_CMS",
  "parameters": {
    "signature": {
      "bytes": "MIIIiQYJKoZI...t7BYR9fjvW4=",
      "file": "C:/docs/contract.pdf"
    },
    "signatureFormat": "CAdES-B-LTA",
    "options": { "revocationFreshness": 0 }
  }
}
```

### Example response

```
{
  "errorCode": 0,
  "method": "AUGMENT_CMS",
  "result": {
    "signatureInfos": [
      {
        "signerCertId": "MIIBXzCCAQag...",
        "status": "TOTAL-VALID",
        "signatureFormat": "CAdES-T",
        ...
      }
    ],
    "bytes": "MIIUsgYJKoZI...9fjvW4=="
  }
}
```

## VERIFY method

The method is intended for validation of a signature in CMS/CAdES format or in the output format of cryptographic primitives ("RAW"). The description of signature formats is given in Appendix B. The "signature" field is mandatory — the signed data is stored in the "signature.bytes" field

To validate a CMS/CAdES-format signature as a detached signature, the original data is additionally specified in the "signature.content" field. If the CMS/CAdES-format signature has encapsulated data, the "signature.content" field is not used.

The method supports four types of validation of a CMS/CAdES-format signature (the "options.validationType" field): 1) "STRUCT" — validation of the signature structure (default), the signature data structure, the electronic signature of the signed attributes and timestamps (if present) are verified;

2. "CHAIN" — validation of the signature structure and the certificate chain, includes item 1 and building the certificate chain of the signer and of the timestamps (if present), by which the validity of the certificate chain can be verified;

3. "FULL" — full validation of the signature, includes item 2 and validation of the validity of all certificates in the chain at the moment the signature was created.

4. "FULL-ETSI" — full validation of the signature with the report of ETSI EN 319 102-1 and ETSI TS 119 102-2 and a validation policy (see the section «The validation type "FULL-ETSI"»).

For the "CHAIN" and "FULL" types the certificate chain must end in a trusted root certificate (the "trustedCerts" field at initialization or certificates marked as trusted in the certificate cache). If the root certificate is not trusted, or a certificate needed to build the chain is missing (the "expectedCerts" field), the status of the signature is "INDETERMINATE".

Certificate status data (the same rules for VERIFY, VERIFY_CERT and the certificate check before signing):

- An OCSP response counts only if it is about this certificate of this issuer (CertID: hashes of the issuer name and key, the serial number), its signature is valid and the responder is authorized (RFC 6960, 4.2.2.2): the issuer of the certificate itself or a delegated responder with the extended key usage id-kp-OCSPSigning whose certificate is issued by the same key that signed the certificate being checked. A response from a responder issued by another key (even of the same CA) does not count.
- A CRL counts if its issuer (name) is the issuer of the certificate and its signer has a certificate with that name, the cRLSign bit of keyUsage and a path to the same root certificate (RFC 5280, 6.3.3 f). Delegated CRL signers (another key of the same CA) are supported.
- Segmented CRLs (the issuingDistributionPoint extension): a CRL counts only if it covers the segment of the certificate - the distribution point of the CRL is one of the cRLDistributionPoints of the certificate (freshestCRL for a delta CRL), onlyContainsUserCerts/onlyContainsCACerts match the certificate. Indirect CRLs (indirectCRL) and CRLs for some revocation reasons only (onlySomeReasons) are not supported. The CRL cache keeps the freshest CRL of every segment.
- A downloaded CRL gets into the cache only after its signer is checked (as in the ADD_CRL method).
- A revocation after the best signature time ("bestSignatureTime") does not invalidate the signature: the same for an OCSP response (revocation time "revocationTime") and for a CRL.

The signature format is determined by the attributes present: CAdES is a signature with the signingCertificateV2 or signingCertificate (ESS v1, SHA-1 hash) attribute, whatever the type of the signer identifier (issuerAndSerialNumber or subjectKeyIdentifier), otherwise CMS. Then: "CAdES-T" - a signature time-stamp is present (the content time-stamp is optional); "CAdES-C" - certificateRefs and revocationRefs are present; "CAdES-XL" ("CAdES-LT") - certValues and revocationValues are present (with or without the references); "CAdES-A" ("CAdES-LTA") - an archive time-stamp is present.

The signer certificate in the signingCertificateV2/signingCertificate attribute is identified by the first entry: its hash, and issuerSerial (if present), must match the signer certificate. If the signer is identified by subjectKeyIdentifier and the cache holds several certificates of this key (for example, re-issued by another CA on the same key), the certificate the signingCertificateV2/signingCertificate attribute points to is used, without it the certificate included in the signature. In the same way, among several issuer certificates with the same key identifier the one whose key signed the certificate is used.

To simplify the analysis of the signature validation results, the result fields "validSignatures", "validDigests" and "bestSignatureTime" can be used. The "bestSignatureTime" field contains the best trusted signature time: the time of the signature time-stamp ("signatureTS.genTime"), without it the time of the archive time-stamp ("archiveTS.genTime"), without them the validation time. The "signingTime" attribute is claimed by the signer, so it is only reported and not used as the signature time; the content time-stamp proves the time of the data, not of the signature.

When the "CHAIN" or "FULL" validation type is used, the "certificateChain" field stores information about the certificate chain (an array of CERT_CHAIN_INFO records).

If a certificate is missing for validation, the information for finding it is stored in the "expectedCerts" field (an array of EXPECTED_CERT_INFO records).

If a CRL is missing to determine the certificate status, the information for finding it is stored in the "expectedCrls" field (an array of EXPECTED_CRL_INFO records).

The "warnings" field contains warnings about the signature validation result (an array of text strings). With the validation type "STRUCT" it always has the warning "THE CERTIFICATE CHAIN AND THE REVOCATION STATUS ARE NOT CHECKED (VALIDATION TYPE STRUCT)", with the type "CHAIN" - "THE REVOCATION STATUS OF THE CERTIFICATES IS NOT CHECKED (VALIDATION TYPE CHAIN)": the status of a signature of these types does not take into account what they do not check. If the order of the time-stamps of a signature is not kept (the content, the signature, the archive ones - each not earlier than the previous one given the accuracy and the ordering field, RFC 3161, 2.4.2), the result is INDETERMINATE with the warning "THE ORDER OF THE TIME-STAMPS IS NOT KEPT".

The order of the time-stamps is checked with their accuracy (the accuracy field). A token without this field is taken with the accuracy of the "timeStampOrderTolerance" parameter of the INIT method (seconds, default 0): "the accuracy may be available through other means" (RFC 3161, 2.4.2), "unless stated differently by the signature validation constraints" (ETSI EN 319 102-1, 5.5.4 4) e)). The unsigned attributes complete-certificate-references and complete-revocation-references that cannot be decoded are not used, the signature is validated without them, with the warning "THE CERTIFICATE REFERENCES ARE NOT DECODED AND ARE NOT USED" or "THE REVOCATION REFERENCES ARE NOT DECODED AND ARE NOT USED" in "warnings" (such are, for example, in the IIT signatures of 2019-2020, where IssuerSerial.issuer is a Name instead of GeneralNames).

### Trusted lists and the speed of validation

Trusted lists (the "trustListCache" parameter of the INIT method, the ADD_TRUST_LIST method) are not mandatory, but recommended for signature validation. OCSP responders that are services of a trusted list (for Ukrainian providers - TL-UA-DSTU, the service type National-Certstatus/OCSP) need no status of their own: the library does not look for it and does not download the CRLs of the providers for it. Without trusted lists the status of the certificate of a responder is determined by OCSP or by CRL (RFC 6960, 4.2.2.2.1); the CRL of a provider may be of tens of megabytes, and for old keys of a provider no longer available, and then the result is INDETERMINATE with the warning "THE STATUS OF THE OCSP RESPONDER IS NOT DETERMINED".

A trusted list also recognizes an OCSP responder whose certificate is issued by another key of the CA (for example, by the new key of a provider for the certificates issued by the old one). RFC 6960, 4.2.2.2 requires for a delegated responder the same key as for the certificate being checked, but allows a local configuration of the authority of a responder (item 1); ETSI TS 119 612, 5.5.1.1 requires a responder with no path to the key of the CA to be listed as a service of its own. The library recognizes such a responder if: its certificate is an OCSP service of a list provided at the time producedAt; the CA service of the certificate being checked (or of the first of its issuers that is a service of a list) and the service of the responder belong to the same provider of the same list - by the registration identifier from TSPTradeName, without it - by the name; the certificate of the responder is issued by a CA service of the same provider. The result of the signature does not change, and the warning "THE OCSP RESPONDER IS AUTHORIZED BY A TRUSTED LIST, NOT BY THE KEY OF THE CA" and the field responderByTrustList show that the responder is recognized this way.

During full signature validation, the following logic is used to determine the certificate status:
| Signature formats        | Description                                                     |
| ------------------------ | --------------------------------------------------------------- |
| "CAdES-BES",             | The OCSP service is used first; if the online status cannot be  |
| "CAdES-T"                | determined, the CRL is used                                     |
| "CAdES-C",               | The CRL is used first; if the CRL cannot be obtained, the       |
| "CAdES-XL",<br>"CAdES-A",<br>"CAdES-B-LT",<br>"CAdES-B-LTA" | OCSP service is used                                            |

To forbid the use of the OCSP service, the "options.onlyCrl" parameter must be set to true (default — as "validationByCrl" at initialization) or the library must be initialized with the "validationByCrl" parameter set to true. The "options.onlyCrl" parameter has higher priority than the (global) "validationByCrl".

Validating a RAW-format signature requires more parameters:

1. the "signParams" field contains the signature parameters ("signAlgo" - mandatory);

2. the "signerPubkey" field contains the parameters of the signer's public key;

3. the "signature.content" field contains the original data.

### Structure of the parameters field in the request

| **Field name** | **Type**                 | **Description**                                        |
| -------------- | ------------------------ | ---------------------------------------------------- |
| signature      | Object<br>SIGNATURE_DATA | SIGNATURE_DATA structure containing the signed data  |
| signParams     | Object<br>SIGN_PARAMS    | Set of signature parameters. Conditionally optional  |
| signerPubkey   | Object<br>SIGNER_PUBKEY  | Set of signer parameters.<br>Conditionally optional  |
| options        | Object<br>OPTION_PARAMS  | Set of additional parameters. Optional               |

### Structure of SIGNATURE_DATA

| **Field name** | **Type** | **Description**                                                                                                          |
| -------------- | ------- | --------------------------------------------------------------------------------------------------------------------- |
| bytes          | Base64  | Signed data                                                                                                             |
| content        | Base64  | Original data. Conditionally optional                                                                                   |
| file           | String  | File that stores the signature data                                                                                     |
| ptr            | Hex     | Pointer to the memory where the signature data is stored.<br>The pointer size depends on the hardware-software<br>platform |
| size           | Integer | Number of bytes of signature data                                                                                       |
| isDigest       | Boolean | If set to true, the content field contains the hash<br>of the data. Defaults to false                                   |

### Structure of SIGN_PARAMS

| **Field name** | **Type** | **Description**                 |
| -------------- | ------- | ------------------------------- |
| signAlgo       | OID     | Signature algorithm identifier  |
| digestAlgo     | OID     | Digest algorithm identifier for the RSASSA-PSS signature<br>algorithm ("1.2.840.113549.1.1.10").<br>Optional, SHA-256 by default |

### Structure of SIGNER_PUBKEY

| **Field name** | **Type** | **Description**                                                                                                            |
| -------------- | ------- | ------------------------------------------------------------------------------------------------------------------------ |
| certificate    | Base64  | Signer's certificate. Optional                                                                                            |
| certId         | Base64  | Identifier of the signer's certificate. Optional                                                                          |
| spki           | Base64  | Signer's public key with key parameters,<br>a SubjectPublicKeyInfo structure per the “x.509” standard.<br>Optional        |

### Structure of OPTION_PARAMS

| **Field name**        | **Type** | **Description**                                                                                                                                                   |
| --------------------- | ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| validationType        | String  | Signature validation type:<br>"STRUCT", "CHAIN", "FULL", "FULL-ETSI".<br>Optional, defaults to "STRUCT"                                                                       |
| validationPolicy      | String,<br>Object<br>VALIDATION_POLICY | Validation policy for the type "FULL-ETSI": a name<br>("UkraineDefault", "EtsiStrict") or a VALIDATION_POLICY object.<br>Optional, defaults to "UkraineDefault" |
| verifySignerInfoIndex | Integer | Verify an individual user (the first index<br>equals 0). If the index equals -1, all<br>users are verified.<br>Optional, defaults to -1                          |
| proofOfExistenceTime | String | The type "FULL-ETSI": the time ("YYYY-MM-DD hh:mm:ss", UTC) the<br>application attests the signature with all its objects existed<br>at (a proof of existence given as an input, ETSI EN 319 102-1,<br>5.6.3). Used by the past validation. Optional |
| onlyCrl               | Boolean | Use CRLs exclusively. Optional, defaults to<br>"validationByCrl" of the initialization                                                                           |
| checkCriticalExtensions | Boolean | A certificate with an unknown critical extension is unusable<br>(RFC 5280, 4.2). Optional, defaults to false                                                   |
| caRemovesExpiredCerts | Boolean | The CAs remove the expired certificates from their revocation<br>data (RFC 5280, 3.3): data issued after a certificate expired<br>does not prove it is not revoked. Optional, defaults to false<br>(the CAs keep the status of such certificates)                                       |

Depending on the format of the signed data, the structure of the result field in the response differs.

### Structure of the result field in the response for validation of signed data in “CMS/CAdES” format

| **Field name** | **Type**                     | **Description**                                                        |
| -------------- | ---------------------------- | ---------------------------------------------------------------------- |
| content        | Object<br>CONTENT_INFO       | CONTENT_INFO structure                                                 |
| certIds        | Base64[]                     | Array of identifiers of certificates present in the<br>signed data     |
| signatureInfos | Object[]<br>SIGNATURE_INFO[] | Array of information for each signature                                |

### Structure of the result field in the response for validation of signed data in “RAW” format

| **Field name**  | **Type** | **Description**                                                |
| --------------- | ------- | ------------------------------------------------------------ |
| statusSignature | String  | Electronic signature status:<br>"VALID", "INVALID", "FAILED" |

### Structure of CONTENT_INFO

| **Field name** | **Type** | **Description**                |
| -------------- | ------- | --------------------------------- |
| type           | OID     | Data type identifier              |
| bytes          | Base64  | Encapsulated data. Optional       |

### Structure of SIGNATURE_INFO

| **Field name**      | **Type** | **Description**                                                                                                           |
| ------------------- | ------- | ----------------------------------------------------------------------------------------------------------------------- |
| signerCertId        | Base64  | Identifier of the signer's certificate.<br>Optional                                                                      |
| signatureFormat     | String  | CMS/CAdES signature format:<br>"CMS", "CAdES-BES", "CAdES-T", "CAdES-C",<br>"CAdES-XL", "CAdES-A", "CAdES-B-LT", "CAdES-B-LTA" |
| status              | String  | Signed data status:<br>"UNDEFINED", "INDETERMINATE", "TOTAL-FAILED",<br>"TOTAL-VALID"                                    |
| validSignatures     | Boolean | All cryptographic signatures related to the<br>signature format structure are valid                                      |
| validDigests        | Boolean | All hashes related to the signature format<br>structure are valid                                                        |
| bestSignatureTime   | Time    | Best signature time                                                                                                      |
| signAlgo            | OID     | Signature algorithm identifier                                                                                           |
| statusSignature     | String  | Electronic signature status:<br>"UNDEFINED", "INDETERMINATE", "FAILED",<br>"INVALID", "VALID WITHOUT KEYUSAGE", "VALID"  |
| digestAlgo          | OID     | Data hash algorithm identifier                                                                                           |
| statusMessageDigest | String  | Data digest status:<br>"UNDEFINED", "INDETERMINATE", "FAILED",<br>"INVALID", "VALID"                                     |
| signingTime         | Time    | Local signing time. Optional — present<br>if the signed data has the corresponding attribute                             |
| signaturePolicy       | Object<br>SIGN_POLICY_INFO        | Signature policy. Optional — present if<br>the signed data has the corresponding attribute                                                                                                                            |
| statusEssCert         | String                            | Status of the signer certificate identification<br>(optional):<br>"UNDEFINED", "NOT PRESENT", "INDETERMINATE",<br>"FAILED", "INVALID", "VALID"                                                                        |
| contentTS             | Object<br>TIMESTAMP_INFO          | Content timestamp. Optional —<br>present if the signed data has the corresponding<br>attribute                                                                                                                        |
| signatureTS           | Object<br>TIMESTAMP_INFO          | Signature timestamp. Optional —<br>present if the signed data has the corresponding<br>attribute                                                                                                                      |
| statusCertificateRefs | String                            | Status of the references to all certificates in the<br>certificateRefs attribute (present in the signature formats<br>"CAdES-C", "CAdES-XL" and "CAdES-A"):<br>"UNDEFINED", "NOT PRESENT", "INDETERMINATE",<br>"FAILED", "INVALID", "VALID" |
| certificateRefs       | Object[]<br>CERT_REF_INFO[]       | Array of references to all certificates in the<br>certificateRefs attribute. Optional — present if<br>the signature has the corresponding attribute                                                                  |
| certValues            | Base64[]                          | Array of identifiers of certificates present in the<br>certValues attribute (present in the signature formats<br>"CAdES-XL" and "CAdES-A"). Optional                                                                 |
| revocationRefs        | Object[]<br>REVOCATION_REF_INFO[] | Array of references to all revocation elements in the<br>revocationRefs attribute (present in the signature formats<br>"CAdES-C", "CAdES-XL" and "CAdES-A"). Optional                                                 |
| archiveTS             | Object<br>TIMESTAMP_INFO          | Archive timestamp (the first). Optional — present<br>if the signed data has the corresponding attribute                                                                                                               |
| archiveTimeStamps     | Object[]<br>TIMESTAMP_INFO[]      | All the archive timestamps in the order they were added<br>(re-archiving). Optional — present if there is more than one                                                                                               |
| signedAttributes      | Object[]<br>ATTRIBUTE_PARAMS[]    | Array of attributes stored in the<br>signedAttributes field                                                                                                                                                           |
| unsignedAttributes    | Object[]<br>ATTRIBUTE_PARAMS[]    | Array of attributes stored in the<br>unsignedAttributes field. Optional                                                                                                                                               |
| certificateChain      | Object[]<br>CERT_CHAIN_INFO[]     | Array of certificate chain validation results.<br>Optional — present when the signature validation<br>type is "CHAIN" or "FULL"                                                                                       |
| expectedCerts         | Object[]<br>EXPECTED_CERT_INFO[]  | Array of information about a certificate required<br>for signature validation. Optional                                                                                                                               |
| expectedCrls          | Object[]<br>EXPECTED_CRL_INFO[]   | Array of information about a CRL file required<br>for signature validation. Optional                                                                                                                                  |
| warnings              | String[]                          | Array of warnings about the verification result.<br>Optional                                                                                                                                                          |

### Structure of the SIGN_POLICY_INFO field

| **Field name** | **Type** | **Description**                |
| -------------- | ------- | ------------------------------ |
| sigPolicyId    | OID     | Signature policy identifier    |

### Structure of TIMESTAMP_INFO

| **Field name**  | **Type** | **Description**                                                                                                                     |
| --------------- | ------- | --------------------------------------------------------------------------------------------------------------------------------- |
| genTime         | Time    | Timestamp value                                                                                                                    |
| policyId        | OID     | TSP policy identifier                                                                                                              |
| hashAlgo        | OID     | Hash algorithm identifier                                                                                                          |
| hashedMessage   | Base64  | Hash value                                                                                                                         |
| statusDigest    | String  | Timestamp value status:<br>"UNDEFINED", "NOT PRESENT", "INDETERMINATE",<br>"FAILED", "INVALID", "VALID"                            |
| statusSignature | String  | Timestamp signature verification status:<br>"UNDEFINED", "NOT PRESENT", "INDETERMINATE",<br>"FAILED", "INVALID", "VALID"           |
| signerCertId    | Base64  | Identifier of the timestamp signer's<br>certificate. Optional — present if the certificate<br>is found in the certificate cache    |

### Structure of the CERT_REF_INFO field

| **Field name** | **Type**               | **Description**                                                                             |
| -------------- | --------------------- | ----------------------------------------------------------------------------------------- |
| certHash       | Object<br>HASH_INFO   | Information about the certificate hash                                                    |
| issuer         | Object<br>RDNAME_INFO | Certificate description. Certificate description<br>elements are listed in Appendix E. Optional |
| serialNumber   | Hex                   | Certificate serial number. Optional                                                       |
| status         | String                | Status of the match between the certificate hash and the certificate                      |

### Structure of the HASH_INFO field

| **Field name** | **Type** | **Description**                                                       |
| -------------- | ------- | ------------------------------------------------------------------- |
| hashAlgo       | OID     | Hash algorithm identifier                                            |
| hashAlgoParams | Base64  | Hash algorithm parameters (ASN1 DER<br>encoding). Optional           |
| hashValue      | Base64  | Hash value                                                           |

### Structure of the REVOCATION_REF_INFO field

| **Field name** | **Type**                    | **Description**                                            |
| -------------- | -------------------------- | --------------------------------------------------------- |
| crlIds         | Object<br>CRLID_INFO       | Array of CRL references. Optional                          |
| ocspIds        | Object[]<br>OCSPID_INFO    | Array of references to OCSP responses. Optional            |
| otherRev       | Object<br>ATTRIBUTE_PARAMS | Alternative revocation information.<br>Optional            |

### Structure of the CRLID_INFO field

| **Field name** | **Type**                      | **Description**                   |
| -------------- | ---------------------------- | ------------------------------- |
| crlHash        | Object<br>HASH_INFO          | Information about the CRL hash  |
| crlIdentifier  | Object<br>CRLIDENTIFIER_INFO | CRL identifier. Optional        |

### Structure of the CRLIDENTIFIER_INFO field

| **Field name** | **Type**     | **Description**                                     |
| -------------- | ----------- | ------------------------------------------------ |
| crlIssuer      | Object<br>RDNAME_INFO | CRL description. CRL description elements are listed in<br>Appendix E. Optional |
| crlIssuedTime  | Time        | CRL issue time                                   |
| crlNumber      | Hex         | CRL number. Optional                             |

### Structure of the OCSPID_INFO field

| **Field name** | **Type**                        | **Description**                                     |
| -------------- | ----------------------------- | ----------------------------------------------- |
| ocspIdentifier | Object<br>OCSPIDENTIFIER_INFO | OCSP response identifier                        |
| ocspHash       | Object<br>HASH_INFO           | Information about the OCSP response hash. Optional |

### Structure of the OCSPIDENTIFIER_INFO field

| **Field name** | **Type**                             | **Description**                                                                                                                      |
| -------------- | ----------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| responderId    | Object<br>RDNAME_INFO<br>or<br>Hex  | Certificate description or key identifier of the OCSP<br>service. Optional. Certificate description<br>elements are listed in Appendix E |
| producedAt     | Time                                | OCSP response creation time                                                                                                          |

### Structure of CERT_CHAIN_INFO

| **Field name**  | **Type**                 | **Description**                                                                               |
| --------------- | ----------------------- | -------------------------------------------------------------------------------------------- |
| subjectCertId   | Base64                  | Certificate identifier                                                                       |
| CN              | String                  | Name of the certificate owner (commonName)                                                   |
| entity          | String                  | Purpose:<br>"UNDEFINED", "SIGNER", "INTERMEDIATE",<br>"CRL", "OCSP", "TSP", "CA", "ROOT"     |
| source          | String                  | Source:<br>"UNDEFINED", "SIGNATURE", "STORE"                                                 |
| validity        | Object<br>CERT_VALIDITY | Certificate validity period                                                                  |
| expired         | Boolean                 | Flag indicating that the certificate has expired                                             |
| selfSigned      | Boolean                 | Flag indicating that the certificate is self-signed                                          |
| trusted         | Boolean                 | Flag indicating that the certificate is trusted                                              |
| issuerCertId    | Base64                  | Identifier of the issuer certificate. Optional                                               |
| statusSignature | String                  | Certificate electronic signature status:<br>"UNDEFINED", "INDETERMINATE", "FAILED",<br>"INVALID", "VALID WITHOUT KEYUSAGE", "VALID" |
| validateByCRL    | Object<br>VALIDATE_BY_CRL_INFO  | Result of verifying the user certificate<br>using a CRL. Optional                        |
| validateByOCSP   | Object<br>VALIDATE_BY_OCSP_INFO | Result of verifying the user certificate<br>using OCSP. Optional                         |
| statusValidation | String                          | Certificate validation status:<br>"UNDEFINED", "NONE", "VALID", "INVALID", "EXPIRED"     |

### Structure of the CERT_VALIDITY field

| **Field name** | **Type** | **Description**                                    |
| -------------- | ------- | -------------------------------------------- |
| notBefore      | Time    | Date from which the certificate becomes valid |
| notAfter       | Time    | Date from which the certificate ceases to be valid |

### Structure of VALIDATE_BY_CRL_INFO

| **Field name**    | **Type** | **Description**                                                                                                                                                                                                                                                              |
| ----------------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| crlId             | Base64  | CRL identifier in the CRL cache                                                                                                                                                                                                                                              |
| CN                | String  | Name of the CRL issuer (commonName)                                                                                                                                                                                                                                          |
| thisUpdate        | Time    | Creation time of the current CRL                                                                                                                                                                                                                                             |
| nextUpdate        | Time    | Creation time of the next CRL                                                                                                                                                                                                                                                |
| crlNumber         | Hex     | Sequence number of the CRL issue                                                                                                                                                                                                                                             |
| deltaCrlIndicator | Hex     | Number of the full CRL issue. Optional                                                                                                                                                                                                                                       |
| issuerCertId      | Base64  | Identifier of the issuer certificate. Optional                                                                                                                                                                                                                               |
| statusSignature   | String  | CRL electronic signature status:<br>"UNDEFINED", "INDETERMINATE", "FAILED", "INVALID",<br>"VALID WITHOUT KEYUSAGE", "VALID"                                                                                                                                                  |
| status            | String  | Certificate status:<br>"UNDEFINED", "GOOD", "REVOKED", "UNKNOWN"                                                                                                                                                                                                             |
| revocationReason  | String  | Revocation reason. The following values are possible:<br>"UNSPECIFIED", "KEY_COMPROMISE", "CA_COMPROMISE",<br>"AFFILIATION_CHANGED", "SUPERSEDED",<br>"CESSATION_OF_OPERATION", "CERTIFICATE_HOLD",<br>"REMOVE_FROM_CRL", "PRIVILEGE_WITHDRAWN",<br>"AA_COMPROMISE". Optional |
| revocationTime    | Time    | Revocation time. Optional                                                                                                                                                                                                                                                    |

### Structure of VALIDATE_BY_OCSP_INFO

| **Field name** | **Type** | **Description**                                                                                                                                 |
| -------------- | ------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| source         | String  | Source:<br>"UNDEFINED", "SIGNATURE", "STORE"                                                                                                  |
| responseStatus | String  | OCSP response status:<br>"UNDEFINED", "SUCCESSFUL", "MALFORMED_REQUEST",<br>"INTERNAL_ERROR", "TRY_LATER", "SIG_REQUIRED",<br>"UNAUTHORIZED"  |
| producedAt       | Time   | OCSP response creation time                                                                                                                                                                                                                                                  |
| statusSignature  | String | OCSP response electronic signature status:<br>"UNDEFINED", "NOT PRESENT", "INDETERMINATE",<br>"FAILED", "INVALID", "VALID"                                                                                                                                                   |
| signerCertId     | Base64 | Identifier of the OCSP response signer's certificate.<br>Optional                                                                                                                                                                                                            |
| responderByTrustList | Boolean | The responder is recognized by a trusted list (an OCSP service of the same<br>provider as the CA), not by the key of the CA. Optional — present with the value true |
| status           | String | Certificate status:<br>"UNDEFINED", "GOOD", "REVOKED", "UNKNOWN"                                                                                                                                                                                                             |
| thisUpdate       | Time   | Creation time of the current OCSP record                                                                                                                                                                                                                                     |
| nextUpdate       | Time   | Creation time of the next OCSP record. Optional                                                                                                                                                                                                                              |
| revocationReason | String | Revocation reason. The following values are possible:<br>"UNSPECIFIED", "KEY_COMPROMISE", "CA_COMPROMISE",<br>"AFFILIATION_CHANGED", "SUPERSEDED",<br>"CESSATION_OF_OPERATION", "CERTIFICATE_HOLD",<br>"REMOVE_FROM_CRL", "PRIVILEGE_WITHDRAWN",<br>"AA_COMPROMISE". Optional |
| revocationTime   | Time   | Revocation time. Optional                                                                                                                                                                                                                                                    |

### Structure of EXPECTED_CERT_INFO

| **Field name** | **Type**                             | **Description**                                                                                                                      |
| -------------- | ----------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| entity         | String                              | Purpose:<br>"UNDEFINED", "SIGNER", "INTERMEDIATE",<br>"CRL", "OCSP", "TSP", "CA", "ROOT"                                            |
| issuer         | Object<br>RDNAME_INFO               | Certificate description. Certificate description elements<br>are listed in Appendix E. Optional                                     |
| serialNumber   | Hex                                 | Certificate serial number. Optional                                                                                                 |
| keyId          | Hex                                 | Key identifier. Optional                                                                                                            |
| responderId    | Object<br>RDNAME_INFO<br>or<br>Hex  | Certificate description or key identifier of the OCSP service.<br>Optional. Certificate description elements<br>are listed in Appendix E |

### Structure of EXPECTED_CRL_INFO

| **Field name** | **Type**                 | **Description**                                                              |
| -------------- | ----------------------- | -------------------------------------------------------------------------- |
| authorityKeyId | Hex                     | Issuer key identifier                                                       |
| issuer         | Object<br>RDNAME_INFO   | CRL description. CRL description elements are listed in<br>Appendix E. Optional |
| url            | String                  | CRL storage URL. Optional                                                   |
| full           | Object<br>CRL_FULL_INFO | Information about the full CRL. Optional                                    |

### Structure of the CRL_FULL_INFO field

| **Field name** | **Type** | **Description**                    |
| -------------- | ------- | ---------------------------- |
| thisUpdate     | Time    | Creation time of the current CRL |
| nextUpdate     | Time    | Creation time of the next CRL    |
| crlNumber      | Hex     | Sequence number of the CRL issue |

### The validation type "FULL-ETSI"

The validation type "FULL-ETSI" performs the full validation of a signature and returns a report with the status indications of ETSI EN 319 102-1 (clause 5.1.3, tables 5 and 6) in the structure of ETSI TS 119 102-2 (the field names are those of the XML Schema of that standard, with the first letter in lower case). The structure of the result field for this type is FULL_ETSI_RESULT; it differs from the structure for the types "STRUCT", "CHAIN" and "FULL".

The "errorCode" field of the response of the method is 0 when the report is produced; everything found for a signature is in its report. A non-zero code is returned when the signed data cannot be parsed, the request is not correct or an internal error occurred.

A signature is to be accepted only with the status "TOTAL-PASSED". The status "INDETERMINATE" means that the available data is not enough for a conclusion; its reasons are in the "subIndications" field.

The validation constraints are set by a policy (the "options.validationPolicy" field): the name of a predefined policy, or a VALIDATION_POLICY object with the values that differ from a predefined one. For the type "FULL-ETSI" the fields "options.checkCriticalExtensions" and "options.caRemovesExpiredCerts" are not used: they are defined by the policy. The field "options.onlyCrl" is in effect: the data on the status of a certificate that the signature has (CRL, OCSP) is used as it is, and if there is none or it does not meet the requirements, no request to an OCSP service is made and the status is determined by CRL.

### Structure of VALIDATION_POLICY

| **Field name** | **Type** | **Description** |
| --- | --- | --- |
| basedOn | String | The predefined policy whose values are changed:<br>"UkraineDefault", "EtsiStrict".<br>Optional, defaults to "UkraineDefault" |
| revocationFreshness | Integer | Freshness of the data on the status of a certificate, minutes:<br>the data of the signature without the next update time is<br>usable if issued not earlier than this before the best<br>signature time. 0 - the strict freshness (ETSI EN 319 102-1,<br>5.2.5), the same for every certificate and for OCSP responses<br>and CRLs: the status must be issued after the best signature<br>time. Data issued before it: if its next update time is not<br>reached - "TRY_LATER" (in "reportData" - "tryAfter", that<br>time), it is not asked again; if there is no next update time<br>(an OCSP response) - newer data is asked. Without the strict<br>freshness a CRL is usable up to its next update time. Optional |
| tsaExtendedKeyUsage | String | Extended key usage of a time-stamping service certificate:<br>"allowAdditional" — key purposes besides id-kp-timeStamping<br>are allowed; "strict" — only id-kp-timeStamping. Optional |
| tsaTrust | String | The time a time-stamping service must be trusted at:<br>"timeStampTime" — the time of its time-stamp (RFC 3161, section 4:<br>a time-stamp made before the service was taken out of use is valid<br>unless the key of the service is compromised); "proofOfExistence" —<br>a time proven apart from the time-stamp: of a later time-stamp that<br>covers it, and without one — the validation time (ETSI EN 319 102-1).<br>Optional |
| pastValidation | String | The past validation (ETSI EN 319 102-1, 5.6):<br>"bestSignatureTime" - the certification path is validated at the<br>best signature time; "proofOfExistence" - a signature is accepted<br>if it is proven to have existed at the control time of the path<br>(the trust anchor sunset date, the revocation of a CA certificate,<br>the end of the reliability of an algorithm) and there are proofs of<br>existence of the certificates and revocation data of the path at<br>that time (an archive time-stamp). Optional |
| certificatePathModel | String | The model of the path in the past validation (5.6.2.2):<br>"shell" - the revocation of any certificate of the path moves<br>the control time; "chain" - the revocation of a CA certificate<br>moves it only if the reason is a compromise or is not given.<br>Optional |
| timeStampDelay | Integer | Time-stamp delay, minutes (0-525600): the claimed signing time<br>(signing-time) plus the delay must be after the time of the<br>signature time-stamp, else "SIG_CONSTRAINTS_FAILURE"; the same<br>if a signature with a time-stamp has no signing time<br>(ETSI EN 319 102-1, 5.5.4, step 5). 0 - no delay is specified.<br>Optional |
| cryptographicConstraints | String | Constraints on cryptographic algorithms (ETSI EN 319 102-1,<br>5.2.8.4.1): "off" - not applied; "warning" - a violation is<br>reported and does not change the result; "fail" - a violation<br>gives "CRYPTO_CONSTRAINTS_FAILURE_NO_POE" (INDETERMINATE), and a<br>signature made after the date (by a content time-stamp) -<br>"CRYPTO_CONSTRAINTS_FAILURE" (TOTAL-FAILED). Optional |
| cryptographicAlgorithms | Object[]<br>CRYPTO_ALGORITHM[] | Changes to the constraints of the library: a record replaces<br>the constraint of the same algorithm and key size or adds<br>a new one. Optional |
| signerKeyUsage | String | Key usage of the signing certificate:<br>"digitalSignatureOrNonRepudiation" or "nonRepudiation".<br>Optional |
| caRemovesExpiredCerts | Boolean | The CAs remove the expired certificates from the revocation<br>data. Optional |
| checkCriticalExtensions | Boolean | A certificate with an unknown critical extension is unusable;<br>false — such an extension is a remark. Optional |

An unknown policy name or an unknown field of the VALIDATION_POLICY object is the error INVALID_PARAMETER.

The values of the predefined policies:

| **Constraint** | **UkraineDefault** | **EtsiStrict** |
| --- | --- | --- |
| revocationFreshness | 120 | 120 |
| tsaExtendedKeyUsage | "allowAdditional" | "strict" |
| tsaTrust | "timeStampTime" | "proofOfExistence" |
| pastValidation | "bestSignatureTime" | "proofOfExistence" |
| certificatePathModel | "shell" | "shell" |
| timeStampDelay | 0 | 0 |
| cryptographicConstraints | "warning" | "fail" |
| signerKeyUsage | "digitalSignatureOrNonRepudiation" | "digitalSignatureOrNonRepudiation" |
| caRemovesExpiredCerts | false | true |
| checkCriticalExtensions | false | true |

Structure of the CRYPTO_ALGORITHM record:

| **Field name** | **Type** | **Description** |
| -------------- | -------- | --------------- |
| algorithm      | String  | A hash algorithm ("SHA1", "SHA224", "SHA256", "SHA384", "SHA512",<br>"SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "RIPEMD128",<br>"RIPEMD160", "WHIRLPOOL", "GOST34311", "DSTU7564-256",<br>"DSTU7564-384", "DSTU7564-512") or a family of keys ("RSA", "EC") |
| keySizeBelow   | Integer | For keys: the constraint concerns the keys shorter than this<br>number of bits. Optional |
| reliableUntil  | String  | The date (YYYY-MM-DD) the algorithm is considered reliable until;<br>an empty string - no limit |

The constraints of the library (ETSI TS 119 312; for the algorithms it lists no more - the dates of its earlier versions):

| **Algorithm** | **Reliable until** |
| ------------- | ------------------ |
| SHA1 | 2012-08-01 |
| RIPEMD160 | 2014-08-01 |
| WHIRLPOOL | 2020-12-01 |
| SHA224 | 2029-01-01 |
| RSA, a key shorter than 1024 bits | 2010-08-01 |
| RSA, a key shorter than 1900 bits | 2019-10-01 |
| RSA, a key shorter than 3000 bits | 2029-01-01 |
| EC, a key shorter than 224 bits | 2012-08-01 |
| EC, a key shorter than 256 bits | 2021-10-01 |
| GOST34311 | 2026-09-01, taken out of use |

For an algorithm taken out of use only a certificate issued after the date does not meet the constraint; the certificates issued before meet it, and a signature or a time-stamp made after the date gives the warning "withdrawnAlgorithms". There are no constraints for the keys of DSTU 4145.

### Structure of FULL_ETSI_RESULT (the result field for the validation type "FULL-ETSI")

| **Field name** | **Type** | **Description** |
| --- | --- | --- |
| content | Object<br>CONTENT_INFO | The CONTENT_INFO structure |
| signatureValidationReports | Object[]<br>SIGNATURE_VALIDATION_REPORT[] | The report for every signature that was validated |
| signatureValidationObjects | Object[]<br>VALIDATION_OBJECT[] | The objects used in the validation (certificates,<br>time-stamps); the reports refer to them by the "id" field |

### Structure of SIGNATURE_VALIDATION_REPORT

| **Field name** | **Type** | **Description** |
| --- | --- | --- |
| signerInfoIndex | Integer | Index of the signer (the first one is 0) |
| signatureIdentifier | Object<br>SIGNATURE_IDENTIFIER | Identification of the signature |
| signatureValidationStatus | Object<br>VALIDATION_STATUS | Status of the signature: "mainIndication" is<br>"TOTAL-PASSED", "TOTAL-FAILED" or "INDETERMINATE" |
| signatureValidationProcess | Object | The "signatureValidationProcessId" field — the validation<br>process of ETSI EN 319 102-1: "Basic" (5.3), "LTVM" (5.5),<br>"LTA" (5.6) |
| validationTimeInfo | Object<br>VALIDATION_TIME_INFO | The validation time and the best signature time |
| pastValidation | Object | The past validation (ETSI EN 319 102-1, 5.6.2): the "signature"<br>field and the "timeStamps" array (with the "id" field - the<br>identifier of the time-stamp). The fields of a record: "status" -<br>"PASSED" or "NO_POE"; "reason" - the reason if not "PASSED";<br>"controlTime" - the time the path is validated at;<br>"controlTimeReason" - why it is not the validation time<br>("TRUST_ANCHOR_SUNSET", "CERTIFICATE_REVOKED",<br>"CA_CERTIFICATE_REVOKED", "ALGORITHM_NOT_RELIABLE"); "poe" - the<br>proof of existence of the object ("poeTime", "typeOfProof",<br>"poeObject" - the time-stamp that gives it) |
| signersDocument | Object | The "digestAlgAndValue" field (the DIGEST_ALG_AND_VALUE<br>structure) — the hash of the signed data, as signed. Optional |
| signerInformation | Object | The "signerCertificate" field (Base64) — the identifier of the<br>signing certificate, the "signer" field (String) — the name of<br>its subject. Optional — when the certificate is identified |
| signatureQuality | Object<br>SIGNATURE_QUALITY | Quality of the signature. Optional — present with the<br>status "TOTAL-PASSED" |
| validationConstraintsEvaluationReport | Object<br>CONSTRAINTS_REPORT | The validation policy and the result of every constraint |
| signatureFormat | String | Format of the CMS/CAdES signature (as in the SIGNATURE_INFO<br>structure) |
| signAlgo | OID | Signature algorithm identifier |
| signingTime | Time | Local signing time. Optional |
| timeStamps | String[] | Identifiers of the time-stamps of the signature in the<br>"signatureValidationObjects" field |
| certificates | Object[]<br>CERT_CHAIN_INFO[] | The certificates used, with the data on their status |
| expectedCerts | Object[]<br>EXPECTED_CERT_INFO[] | The certificates missing for the validation. Optional |
| expectedCrls | Object[]<br>EXPECTED_CRL_INFO[] | The CRLs missing for the validation. Optional |
| signedAttributes | Object[]<br>ATTRIBUTE_PARAMS[] | Signed attributes |
| unsignedAttributes | Object[]<br>ATTRIBUTE_PARAMS[] | Unsigned attributes. Optional |

### Structure of SIGNATURE_IDENTIFIER

| **Field name** | **Type** | **Description** |
| --- | --- | --- |
| digestAlgAndValue | Object<br>DIGEST_ALG_AND_VALUE | The hash of the signed attributes |
| signatureValue | Base64 | The signature value |
| hashOnly | Boolean | Only the hash of the data to be signed was processed<br>(always false) |
| docHashOnly | Boolean | The hash of the signed data was given instead of the data |

### Structure of DIGEST_ALG_AND_VALUE

| **Field name** | **Type** | **Description** |
| --- | --- | --- |
| digestMethod | OID | Hash algorithm identifier |
| digestValue | Base64 | Hash value. Optional |

### Structure of VALIDATION_STATUS

| **Field name** | **Type** | **Description** |
| --- | --- | --- |
| mainIndication | String | Status. For a signature: "TOTAL-PASSED", "TOTAL-FAILED",<br>"INDETERMINATE"; for a constraint and a validation object:<br>"PASSED", "FAILED", "INDETERMINATE" |
| subIndications | String[] | The reasons of a status that is not a success (ETSI EN 319 102-1,<br>table 6):<br>"FORMAT_FAILURE", "HASH_FAILURE", "SIG_CRYPTO_FAILURE",<br>"REVOKED", "EXPIRED", "NOT_YET_VALID",<br>"CHAIN_CONSTRAINTS_FAILURE", "CERTIFICATE_CHAIN_GENERAL_FAILURE", "NO_SIGNING_CERTIFICATE_FOUND",<br>"NO_CERTIFICATE_CHAIN_FOUND", "NO_CERTIFICATE_CHAIN_FOUND_NO_POE",<br>"REVOKED_NO_POE", "REVOKED_CA_NO_POE",<br>"OUT_OF_BOUNDS_NO_POE", "REVOCATION_OUT_OF_BOUNDS_NO_POE",<br>"TRY_LATER", "TIMESTAMP_ORDER_FAILURE",<br>"SIG_CONSTRAINTS_FAILURE", "CRYPTO_CONSTRAINTS_FAILURE",<br>"CRYPTO_CONSTRAINTS_FAILURE_NO_POE", "SIGNED_DATA_NOT_FOUND",<br>"CUSTOM".<br>Optional |
| associatedValidationReportData | Object[]<br>VALIDATION_REPORT_DATA[] | The data of the status. Optional |

### Structure of VALIDATION_REPORT_DATA

An entry holds either the certificate chain (the fields "trustAnchor", "certificateChain") or the data of one reason of the status (the other fields).

| **Field name** | **Type** | **Description** |
| --- | --- | --- |
| trustAnchor | Base64 | Identifier of the trusted root certificate. Optional |
| certificateChain | Object | The chain of the signing certificate: "signingCertificate"<br>(Base64), "intermediateCertificates" (Base64[]), "trustAnchor"<br>(Base64, optional). Optional |
| relatedValidationObject | Base64 | Identifier of the certificate the reason is about. Optional |
| revocationStatusInformation | Object | The revocation: "validationObjectId" (Base64) — the<br>certificate, "revocationTime" (Time), "revocationReason"<br>(String, optional): "unspecified", "keyCompromise",<br>"cACompromise", "affiliationChanged", "superseded",<br>"cessationOfOperation", "certificateHold", "removeFromCRL",<br>"privilegeWithdrawn", "aACompromise". Optional |
| additionalValidationReportData | Object | The "reportData" field — an array of "type"/"value" pairs<br>(String): "mainIndication", "subIndication" — the status and<br>the reason the entry is about; "info" — a detail of the reason.<br>Optional |

### Structure of VALIDATION_TIME_INFO

| **Field name** | **Type** | **Description** |
| --- | --- | --- |
| validationTime | Time | The validation time |
| bestSignatureTime | Object | The best signature time: "poeTime" (Time), "typeOfProof"<br>(String, "validation"), "poeObject" (String, optional) — the<br>identifier of the time-stamp that proves it. Optional |

### Structure of SIGNATURE_QUALITY

If the certificate of the issuer of the signing certificate is in a trusted list (the ADD_TRUST_LIST method), the "basis" field is "trustedList": the quality is confirmed when the service issuing qualified certificates of the kind (for signatures or for seals) was provided both when the certificate was issued and at the best signature time; if it is not confirmed, the value is "AdESig" or "AdESeal". Otherwise the "basis" field is "certificate": the quality is determined by the data of the signing certificate, these are statements of its issuer.

| **Field name** | **Type** | **Description** |
| --- | --- | --- |
| signatureQualityInformation | String[] | Quality of the signature, one value (see the table below) |
| basis | String | The basis of the conclusion: "trustedList" or "certificate" |
| confirmedByTrustedList | Boolean | Flag indicating that the trusted list confirms what the certificate<br>states. Optional — present for "basis" equal to "trustedList" |
| trustService | Object | The service of the trusted list: "listId", "type", "tspName",<br>"serviceName" (String) — as in the TRUST_SERVICE structure of the<br>CERT_INFO method. Optional |
| qcStatements | String[] | Identifiers of the statements of the qcStatements extension<br>of the signing certificate |

| **Value** | **Description** |
| --- | --- |
| "QESig", "QESeal" | The certificate is stated to be qualified (id-etsi-qcs-QcCompliance), the key is in a qualified device (id-etsi-qcs-QcSSCD) |
| "AdESig-QC", "AdESeal-QC" | The certificate is stated to be qualified |
| "AdESig-QC-old", "AdESeal-QC-old" | A qualified ("посилений") certificate under the former law of Ukraine on the electronic digital signature (the certificate policy 1.2.804.2.1.1.1.2.2), without the id-etsi-qcs-QcCompliance statement |
| "AdESig", "AdESeal" | Other certificates |

The values with "Seal" are for a certificate of an electronic seal: the id-etsi-qcs-QcType statement with the value id-etsi-qct-eseal, or the extended key usage 1.2.804.2.1.1.1.3.9.

### Structure of CONSTRAINTS_REPORT

| **Field name** | **Type** | **Description** |
| --- | --- | --- |
| signatureValidationPolicy | Object | The validation policy: "policyName" (String) — "UkraineDefault",<br>"EtsiStrict" or "custom"; "basedOn" (String) — for "custom" |
| validationConstraints | Object[]<br>VALIDATION_CONSTRAINT[] | The result of every constraint |

### Structure of VALIDATION_CONSTRAINT

| **Field name** | **Type** | **Description** |
| --- | --- | --- |
| validationConstraintIdentifier | String | Identifier of the constraint (see the table below) |
| validationConstraintParameter | Object | The value the policy gives to the constraint: "type"<br>("value"), "value" (String). Optional |
| constraintStatus | Object | The "status" field: "applied" or "disabled" (not applied) |
| level | String | "fail" — the result of the constraint defines the status of<br>the signature; "warning" — the result is a remark and does<br>not change the status of the signature. Optional — for an<br>applied constraint |
| validationStatus | Object<br>VALIDATION_STATUS | The result of the constraint. Optional — for an applied<br>constraint |

| **Identifier** | **What is checked** |
| --- | --- |
| formatChecking | Format of the signature |
| identificationOfTheSigningCertificate | Identification of the signing certificate |
| x509CertificateValidation | The chain of the signing certificate: building, validity periods, status |
| x509ValidationOfTimeStampsAndRevocationData | The certificates of the time-stamps and of the status data |
| cryptographicVerification | The hash of the signed data and the signature value |
| validationMaterialReferences | The references to the certificates and to the status data match them (when the attributes are present) |
| unknownCriticalExtensions | Unknown critical extensions of the certificates |
| revocationFreshnessChecker | Freshness of the data on the status of a certificate |
| caRemovesExpiredCerts | Status data issued after a certificate expired |
| statusOfRevocationDataSigners | Status of the certificates of OCSP responders and CRL signers |
| tsaExtendedKeyUsage | Extended key usage of a time-stamping service certificate |
| tsaTrust | The time a time-stamping service must be trusted at |
| signerKeyUsage | Key usage of the signing certificate |
| cryptographicConstraints | Constraints on cryptographic algorithms: the hash algorithms<br>and key sizes of the signature, the certificates and the<br>time-stamps. In a "reportData" record - "algorithm" (the<br>algorithm, for a key with its size) and "reliableUntil" (the<br>date it was considered reliable until) |
| withdrawnAlgorithms | Algorithms taken out of use by a decision of a regulator (not<br>for a cryptographic weakness): a signature or a time-stamp made<br>after the date. Always a warning |
| pastValidation | The past validation of the signature (the value of "pastValidation") |
| timeStampOrderAndDelay | Order of the time-stamps (the content, the signature, the archive<br>ones - each not earlier than the previous one given the accuracy<br>and the ordering field, RFC 3161, 2.4.2; else<br>"TIMESTAMP_ORDER_FAILURE" naming the time-stamps) and the<br>time-stamp delay (the value of "timeStampDelay") |
| signaturePolicy | Signature policy (not applied) |

### Structure of VALIDATION_OBJECT

| **Field name** | **Type** | **Description** |
| --- | --- | --- |
| id | String | Identifier of the object in the report: for a certificate —<br>its identifier in the cache (Base64), for a time-stamp —<br>"TS-&lt;signer index&gt;-&lt;type&gt;[-&lt;number&gt;]" |
| objectType | String | Type of the object: "certificate", "timestamp" |
| CN, validity, selfSigned,<br>trusted, issuerCertId |  | For a certificate — as in the CERT_CHAIN_INFO structure |
| revocationNotChecked | String | For the certificate of an OCSP responder or a CRL signer whose<br>status was not looked for - the reason: "ocspNoCheck" (the<br>id-pkix-ocsp-nocheck extension), "noRevocationAvailable" (the<br>noRevAvail or validity-assured-short-term extension),<br>"trustedList" (a service of a trusted list). Optional |
| timeStampType | String | For a time-stamp: "CONTENT", "SIGNATURE", "ARCHIVE",<br>"ARCHIVE-V2" |
| timeStampQualification | String | For a time-stamp whose certificate is in a trusted list: "QTSA" —<br>the qualified time-stamping service was provided at the time of the<br>time-stamp, "TSA" — otherwise. Optional |
| poeProvisioning | Object | For a time-stamp: "poeTime" (Time) — the time of the<br>time-stamp. Optional |
| validationReport | Object | For a time-stamp: the "signatureValidationStatus" field (the<br>VALIDATION_STATUS structure) — the result of its validation.<br>A time-stamp that does not pass the validation is not used |
| genTime, policyId, hashAlgo,<br>hashedMessage, statusDigest,<br>statusSignature, signerCertId |  | For a time-stamp — as in the TIMESTAMP_INFO structure |

### Request example for the validation type "FULL-ETSI"

```
{
  "method": "VERIFY",
  "parameters": {
    "signature": {
      "bytes": "MIIa2wYJKoZI...AAAAAAAAAAAA"
    },
    "options": {
      "validationType": "FULL-ETSI",
      "validationPolicy": {
        "basedOn": "UkraineDefault",
        "checkCriticalExtensions": true
      }
    }
  }
}
```

### Response example for the validation type "FULL-ETSI"

```
{
  "errorCode": 0,
  "method": "VERIFY",
  "result": {
    "content": {
      "type": "1.2.840.113549.1.7.1"
    },
    "signatureValidationReports": [
      {
        "signerInfoIndex": 0,
        "signatureIdentifier": {
          "digestAlgAndValue": {
            "digestMethod": "2.16.840.1.101.3.4.2.1",
            "digestValue": "ns1xBg+UvlJJ...Qo5cF1c="
          },
          "signatureValue": "MEUCIQCEYV9s...8Xw5Aw==",
          "hashOnly": false,
          "docHashOnly": false
        },
        "signatureValidationStatus": {
          "mainIndication": "INDETERMINATE",
          "subIndications": [
            "REVOKED_NO_POE"
          ],
          "associatedValidationReportData": [
            {
              "trustAnchor": "MDAwKzEUMBIG...AgEB",
              "certificateChain": {
                "signingCertificate": "MCwwJzEQMA4G...AgEL",
                "intermediateCertificates": [
                  "MDAwKzEUMBIG...AgEC"
                ],
                "trustAnchor": "MDAwKzEUMBIG...AgEB"
              }
            },
            {
              "relatedValidationObject": "MCwwJzEQMA4G...AgEL",
              "revocationStatusInformation": {
                "validationObjectId": "MCwwJzEQMA4G...AgEL",
                "revocationTime": "2026-01-01 00:00:00",
                "revocationReason": "keyCompromise"
              },
              "additionalValidationReportData": {
                "reportData": [
                  { "type": "mainIndication", "value": "INDETERMINATE" },
                  { "type": "subIndication", "value": "REVOKED_NO_POE" }
                ]
              }
            }
          ]
        },
        "signatureValidationProcess": {
          "signatureValidationProcessId": "LTVM"
        },
        "validationTimeInfo": {
          "validationTime": "2026-10-11 14:27:04",
          "bestSignatureTime": {
            "poeTime": "2026-10-11 14:27:04",
            "typeOfProof": "validation",
            "poeObject": "TS-0-SIGNATURE"
          }
        },
        "signersDocument": {
          "digestAlgAndValue": {
            "digestMethod": "2.16.840.1.101.3.4.2.1",
            "digestValue": "auinVVUgn9bE...Yjbb0Ns="
          }
        },
        "signerInformation": {
          "signerCertificate": "MCwwJzEQMA4G...AgEL",
          "signer": "Test Leaf Revoked"
        },
        "validationConstraintsEvaluationReport": {
          "signatureValidationPolicy": {
            "policyName": "custom",
            "basedOn": "UkraineDefault"
          },
          "validationConstraints": [
            {
              "validationConstraintIdentifier": "formatChecking",
              "constraintStatus": { "status": "applied" },
              "level": "fail",
              "validationStatus": { "mainIndication": "PASSED" }
            },
            {
              "validationConstraintIdentifier": "x509CertificateValidation",
              "constraintStatus": { "status": "applied" },
              "level": "fail",
              "validationStatus": {
                "mainIndication": "INDETERMINATE",
                "subIndications": [ "REVOKED_NO_POE" ],
                "associatedValidationReportData": [ ... ]
              }
            },
            {
              "validationConstraintIdentifier": "revocationFreshnessChecker",
              "validationConstraintParameter": { "type": "value", "value": "120" },
              "constraintStatus": { "status": "applied" },
              "level": "fail",
              "validationStatus": { "mainIndication": "PASSED" }
            },
            {
              "validationConstraintIdentifier": "cryptographicConstraints",
              "constraintStatus": { "status": "disabled" }
            },
            ...
          ]
        },
        "signatureFormat": "CAdES-T",
        "signAlgo": "1.2.840.10045.4.3.2",
        "timeStamps": [
          "TS-0-SIGNATURE"
        ],
        "certificates": [ ... ],
        "signedAttributes": [ ... ],
        "unsignedAttributes": [ ... ]
      }
    ],
    "signatureValidationObjects": [
      {
        "id": "TS-0-SIGNATURE",
        "objectType": "timestamp",
        "timeStampType": "SIGNATURE",
        "poeProvisioning": {
          "poeTime": "2026-10-11 14:27:04"
        },
        "validationReport": {
          "signatureValidationStatus": {
            "mainIndication": "PASSED"
          }
        },
        "genTime": "2026-10-11 14:27:04",
        "policyId": "1.2.3.4.1",
        "hashAlgo": "2.16.840.1.101.3.4.2.1",
        "hashedMessage": "Lm0QBajhkgfg...3aE1U0I=",
        "statusDigest": "VALID",
        "statusSignature": "VALID",
        "signerCertId": "MCwwJzEQMA4G...AgEK"
      },
      {
        "id": "MCwwJzEQMA4G...AgEL",
        "objectType": "certificate",
        "CN": "Test Leaf Revoked",
        "validity": {
          "notBefore": "2026-10-09 20:21:28",
          "notAfter": "2026-11-08 20:21:28"
        },
        "selfSigned": false,
        "trusted": false,
        "issuerCertId": "MDAwKzEUMBIG...AgEC"
      },
      ...
    ]
  }
}
```

### Request example for validation of signed data in “RAW” format

```
{
  "method": "VERIFY",
  "parameters": {
    "signature": {
      "bytes": "MEYCIQCpNEQQ...b0Icmdl+yPst",
      "content": "MWkwGAYJKoZI...AgUj+NmRJtw="
    },
    "signParams": {
      "signAlgo": "1.2.840.10045.4.3.2"
    },
    "signerPubkey": {
      "certId": "MIH+MIHlMQsw...NQAAAFwAAAA="
    }
  }
}
```

### Request example for validation of signed data in “CMS/CAdES” format

```
{
  "method": "VERIFY",
  "parameters": {
    "signature": {
      "bytes": "MIIHkQYJKoZI...ZNcGXe57GF5j"
    }
  }
}
```

### Response example for validation of signed data in "CMS/CAdES" format

```
{
  "errorCode": 0,
  "method": "VERIFY",
  "result": {
    "content": {
      "type": "1.2.840.113549.1.7.1",
      "bytes": "QWxpY2UgYW5k...ZV9hbmRfQm9i"
    },
    "certIds": [ "MGwwVDELMAkG...CwAAAD0AAAA=", ... ],
    "signatureInfos": [
      {
        "signerCertId": "MGwwVDELMAkG...CwAAAD0AAAA=",
        "signatureFormat": "CAdES-T",
        "status": "TOTAL-VALID",
        "validSignatures": true,
        "validDigests": true,
        "bestSignatureTime": "2021-07-08 12:32:41",
        "signAlgo": "1.2.804.2.1.1.1.1.3.1.1",
        "statusSignature": "VALID",
        "digestAlgo": "1.2.804.2.1.1.1.1.2.1",
        "statusMessageDigest": "VALID",
        "signingTime": "2021-07-08 12:32:39",
        "statusEssCert": "VALID",
        "contentTS": {
          "genTime": "2021-07-08 12:32:40",
          "policyId": "1.2.804.2.1.1.1.2.3.1",
          "hashAlgo": "1.2.804.2.1.1.1.1.2.1",
          "hashedMessage": "DxNVEwtKggoeT...le3BwYCYMrIzM=",
          "statusDigest": "VALID",
          "statusSignature": "VALID",
          "signerCertId": "MIIBMTCCARcx...EAAADkAAAA"
        },
        "signatureTS": {
          "genTime": "2021-07-08 12:32:41",
          "policyId": "1.2.804.2.1.1.1.2.3.1",
          "hashAlgo": "1.2.804.2.1.1.1.1.2.1",
          "hashedMessage": "cgdf4po1UowRj...4QmGX3iyPAMFg=",
          ...
        },
        "signedAttributes": [
          { "type": "1.2.840.113549.1.9.3", "bytes": "BgkqhkiG9w0BBwE=" },
          { "type": "1.2.840.113549.1.9.5", "bytes": "Fw0yMzAyMTUxNTI1MDda" },
          { "type": "1.2.840.113549.1.9.4", "bytes": "BCAPE1UTC0qCC...7cHBgJgysjMw==" },
          ...
        ]
      }
    ]
  }
}
```

### Response example for validation of signed data in "RAW" format

```
{
  "errorCode": 0,
  "method": "VERIFY",
  "result": {
    "statusSignature": "VALID"
  }
}
```

## ENCRYPT method

The method is intended for encrypting data for one or more recipients.

The encryption key value is generated from random data by default. If necessary, the value is specified in the dataEncryptionKey parameter.

Encryption parameters depend on the encryption algorithm. By default, the values of the encryption parameters (for example, the IV initialization vector) are generated from random data. If necessary, the values are specified in the encryptionAlgoParams parameter. DER encoding of ASN1 is used for encoding the parameters; the structure of the encryption parameters must be valid for the selected encryption algorithm (Kalyna or GOST 28147).

In the case of external encryption, the content parameter must be absent, the dataEncryptionKey parameter is mandatory, and the encryptionAlgoParams parameter is optional and may have any valid encryption parameter value.

### Structure of the parameters field in the request

| **Field name**   | **Type**                        | **Description**                                                                              |
| ---------------- | ------------------------------- | ------------------------------------------------------------------------------------------- |
| content          | Object<br>CONTENT_PARAMS        | Structure with data and encryption parameters.<br>Optional                                  |
| recipientInfos   | Object[],<br>RECIPINFO_PARAMS   | Array of structures containing recipient parameters                                         |
| originatorCertIds | Base64[]                       | Array of originator certificate identifiers.<br>Optional                                    |
| unprotectedAttrs | Object[],<br>ATTRIBUTE_PARAMS[] | Array of structures containing attribute data for<br>the unencrypted part of the data. Optional |

### Structure CONTENT_PARAMS

| **Field name**       | **Type** | **Description**                                                                                              |
| -------------------- | ------- | ------------------------------------------------------------------------------------------------------------ |
| bytes                | Base64  | Data to be encrypted                                                                                          |
| encryptionAlgo       | OID     | Encryption algorithm identifier: DSTU 7624 CFB<br>"1.2.804.2.1.1.1.1.1.3.3.2", GOST 28147 CFB "1.2.804.2.1.1.1.1.1.1.3",<br>AES-CBC "2.16.840.1.101.3.4.1.2" (128), "…1.22" (192), "…1.42" (256).<br>Optional, the default is DSTU 7624 if the key of the first<br>recipient is DSTU 4145, otherwise AES-256-CBC |
| encryptionAlgoParams | Base64  | Encryption parameters in DER encoding.<br>Optional, random values are used<br>by default                      |
| dataEncryptionKey    | Base64  | Encryption key value. Optional, random<br>values are used by default                                          |
| type                 | OID     | Data type identifier. Default is<br>"1.2.840.113549.1.7.1" (pkcs7-data)                                       |

### Structure RECIPINFO_PARAMS

| **Field name** | **Type** | **Description**                                                              |
| -------------- | ------- | ---------------------------------------------------------------------------- |
| certId         | Base64  | Recipient certificate identifier                                              |
| kdfAlgo        | OID     | Key derivation function algorithm identifier (a recipient<br>with a DSTU 4145 or ECDSA key). Optional, the default is<br>"1.2.804.2.1.1.1.1.3.7" for DSTU 4145, "1.3.132.1.11.1" for ECDSA |
| keyWrapAlgo    | OID     | Key wrap algorithm identifier.<br>Optional, depends on kdfAlgo                |
| keyEncryptionAlgo | OID  | Key encryption algorithm identifier (a recipient with an RSA key):<br>"1.2.840.113549.1.1.7" (RSAES-OAEP) or "1.2.840.113549.1.1.1"<br>(RSAES-PKCS1-v1_5). Optional, the default is RSAES-OAEP |
| digestAlgo     | OID     | Digest algorithm identifier for RSAES-OAEP.<br>Optional, SHA-256 by default |

### Structure ATTRIBUTE_PARAMS

| **Field name** | **Type** | **Description**             |
| -------------- | ------- | --------------------------- |
| type           | OID     | Attribute type identifier    |
| bytes          | Base64  | Attribute data               |

### Recommended data encryption schemes

| **№** | **encryptionAlgo**          | **kdfAlgo**             | **keyWrapAlgo**            |
| ----- | --------------------------- | ----------------------- | -------------------------- |
| 1     | "1.2.804.2.1.1.1.1.1.3.3.2" | "1.2.804.2.1.1.1.1.3.7" | "1.2.804.2.1.1.1.1.1.3.11" |
| 2     | "1.2.804.2.1.1.1.1.1.3.3.2" | "1.2.804.2.1.1.1.1.3.8" | "1.2.804.2.1.1.1.1.1.3.11" |
| 3     | "1.2.804.2.1.1.1.1.1.1.3"   | "1.2.804.2.1.1.1.1.3.4" | "1.2.804.2.1.1.1.1.1.1.5"  |
| 4     | "1.2.804.2.1.1.1.1.1.1.3"   | "1.2.804.2.1.1.1.1.3.5" | "1.2.804.2.1.1.1.1.1.1.5"  |
| 5     | "2.16.840.1.101.3.4.1.42"   | "1.3.132.1.11.1"        | "2.16.840.1.101.3.4.1.45"  |

Schemes 1–4 are for a recipient with a DSTU 4145 key, scheme 5 is for a recipient with an ECDSA key (NIST curves).

For a recipient with an ECDSA key: kdfAlgo — "1.3.133.16.840.63.0.2" (SHA-1), "1.3.132.1.11.0" (SHA-224), "1.3.132.1.11.1" (SHA-256), "1.3.132.1.11.2" (SHA-384), "1.3.132.1.11.3" (SHA-512) and the corresponding cofactor schemes "1.3.133.16.840.63.0.3", "1.3.132.1.14.0" – "1.3.132.1.14.3"; keyWrapAlgo — "2.16.840.1.101.3.4.1.5" (AES-128), "2.16.840.1.101.3.4.1.25" (AES-192), "2.16.840.1.101.3.4.1.45" (AES-256, the default).

The recipient certificate must have the key usage keyAgreement (DSTU 4145, ECDSA) or keyEncipherment (RSA).

### Structure of the result field in the response

| **Field name** | **Type** | **Description**  |
| -------------- | ------- | ---------------- |
| bytes          | Base64  | Encrypted data   |

### Request example
```
{
  "method": "ENCRYPT",
  "parameters": {
    "content": {
      "bytes": "VGhlIHF1aWNrIGJyb...p5IGRvZw==",
      "encryptionAlgo": "1.2.804.2.1.1.1.1.1.1.3"
    },
    "recipientInfos": [
      {
        "certId": "MIH6MIHhMRYw...HgYAdKV2AA==",
        "kdfAlgo": "1.2.804.2.1.1.1.1.3.4"
      }
    ]
  }
}
```

### Response example
```
{
  "errorCode": 0,
  "method": "ENCRYPT",
  "result": {
    "bytes": "MIIBSAYJKoZIhvcNAQcDo...srvSh3rZYugDU="
  }
}
```

## DECRYPT method

The method is intended for decrypting data.

Data decryption options are set in the optional options parameter:

- noDecrypt — do not perform key unwrapping; used to identify the recipient;
- returnEncryptedContent — return the encrypted data value;
- returnEncryptionKey — return the encryption key value.

In the case of external encryption, to decrypt the data it is necessary to obtain the key value and encryption parameters — the returnEncryptionKey parameter must be set to true.

The key value and encryption parameters are returned in the encryptedContent field of the response.

### Structure of the parameters field in the request

| **Field name** | **Type**                  | **Description**                                     |
| -------------- | ------------------------- | --------------------------------------------------- |
| bytes          | Base64                    | Encrypted data                                      |
| options        | Object<br>DECRYPT_OPTIONS | DECRYPT_OPTIONS structure. Optional<br>parameter    |
| noDecrypt      | Boolean                   | Do not perform data decryption (alternative to<br>options.noDecrypt). Optional, default<br>false |

### Structure DECRYPT_OPTIONS

| **Field name**         | **Type** | **Description**                                                              |
| ---------------------- | ------- | ---------------------------------------------------------------------------- |
| noDecrypt              | Boolean | Do not perform data decryption.<br>Optional, default false                   |
| returnEncryptedContent | Boolean | Return the encrypted data value.<br>Optional, default false                   |
| returnEncryptionKey    | Boolean | Return the encryption key value.<br>Optional, default false                   |

### Structure of the result field in the response

| **Field name**   | **Type**                    | **Description**                                                                                        |
| ---------------- | --------------------------- | ------------------------------------------------------------------------------------------------------ |
| content          | Object<br>CONTENT_INFO      | CONTENT_INFO structure containing the decrypted<br>data                                                |
| encryptedContent | Object<br>ENCRYPTED_CONTENT | ENCRYPTED_CONTENT structure containing<br>encryption parameters/data. Optional                          |
| originatorCertIds | Base64[]                   | Array of originator certificate identifiers                                                             |
| originatorCertId | Base64                      | Originator certificate identifier.<br>Optional                                                          |
| recipientKeyId   | Hex                         | Identifier of the recipient key that was<br>used for decryption. Optional                               |
| recipientKeys    | Object[]<br>RECIPIENT_KEY[] | Array of data about recipient keys in the<br>RECIPIENT_KEY structure. Optional                          |
| unprotectedAttrs | Object[]                    | Array of attributes in the ATTRIBUTE_PARAMS structure<br>stored in the unprotectedAttrs field. Optional |
| expectedCerts    | Object[]<br>EXPECTED_CERT_INFO[] | Array of information about the certificate required<br>for decryption. Optional — present if<br>the required certificates were not found (see the VERIFY method) |

### Structure CONTENT_INFO

| **Field name** | **Type** | **Description**          |
| -------------- | ------- | ------------------------ |
| bytes          | Base64  | Decrypted data           |
| type           | OID     | Data type identifier     |

### Structure ENCRYPTED_CONTENT

| **Field name**    | **Type** | **Description**                                     |
| ----------------- | ------- | --------------------------------------------------- |
| bytes             | Base64  | Encrypted data. Optional                             |
| algorithm         | OID     | Encryption algorithm identifier.<br>Optional         |
| parameters        | Base64  | Encryption parameters. Optional                      |
| dataEncryptionKey | Base64  | Encryption key value. Optional                       |

### Structure RECIPIENT_KEY

| **Field name** | **Type** | **Description**                                         |
| -------------- | ------- | ------------------------------------------------------- |
| issuer         | Object  | Description of the certificate issuer. Optional          |
| serialNumber   | Hex     | Serial number of the recipient certificate.<br>Optional  |
| issuerBytes    | Base64  | DER-encoded description of the certificate issuer.<br>Optional |
| certId         | Base64  | Recipient certificate identifier.<br>Optional            |
| keyId          | Hex     | Recipient key identifier. Optional                       |

### Request example

```
{
  "method": "DECRYPT",
  "parameters": {
    "bytes": "MIIDTwYJKoZIhvcNAQcDoIID...q+YjNBPU2y7lM/4="
  }
}
```

### Response example
```
{
  "errorCode": 0,
  "method": "DECRYPT",
  "result": {
    "content": {
      "bytes": "VGhlIHF1aWNrIGJyb...p5IGRvZw==",
      "type": "1.2.840.113549.1.7.1"
    },
    "recipientKeys": [
      {
        "issuer": { ... },
        "serialNumber": "3ED5083160DBC59B04000000A91E060074A57600",
        "issuerBytes": "MIHhMRYwFAYDVQQK...UlVBLTQzMzk1MDMz",
        "certId": "MIH6MIHhMRYw...HgYAdKV2AA==",
        "keyId": "6B1B77C0D1A1B604...CDEDB782"
      }
    ],
    "originatorCertIds": [],
    "originatorCertId": "MIH6MIHhMRYw...HgYAdKV2AA==",
    "recipientKeyId": "6B1B77C0D1A1B604...CDEDB782"
  }
}
```

## ADD_CERT method

The method is intended for adding certificates to the local certificate cache or to the storage. Certificates can be added to the cache permanently (with saving to disk) or temporarily (only for the current session, until DEINIT is executed or the application is restarted). If the permanent certificate cache has not been initialized (the path to the corresponding directory was not specified during library initialization), only temporary addition is possible.

Certificates can be added in two ways: as an array of certificates or as a certificate bundle (p7b file). The bundle and certificates fields cannot be present in the request at the same time.

If a certificate being added to the certificate cache is already stored in the cache, it will not be added — the response will return the identifier of the existing certificate (the isUnique flag will have the value false).

If the storage field has the value true, the certificates will be saved to the currently opened storage.

### Structure of the parameters field in the request

| **Field name** | **Type**  | **Description**                                                                          |
| -------------- | -------- | --------------------------------------------------------------------------------------- |
| bundle         | Base64   | Certificate bundle. Optional                                                              |
| certificates   | Base64[] | Array of certificates. Optional                                                           |
| permanent      | Boolean  | Save the certificate in the certificate cache.<br>Optional, default is false              |
| storage        | Boolean  | Add certificates to the storage. Optional,<br>default is false                            |

### Structure of the result field in the response

| **Field name** | **Type**                  | **Description**                          |
| -------------- | ------------------------- | ---------------------------------------- |
| added          | Object[]<br>CERT_ADDED[]  | Array of information about added certificates |

### Structure CERT_ADDED

| **Field name** | **Type** | **Description**                                                                           |
| -------------- | ------- | ----------------------------------------------------------------------------------------- |
| errorCode      | Integer | Error code of certificate addition (0 — success)                                           |
| certId         | Base64  | Certificate identifier in the certificate cache.<br>Present if errorCode equals 0          |
| isUnique       | Boolean | Certificate uniqueness flag.<br>Present if errorCode equals 0                              |

### Request example

```
{
  "method": "ADD_CERT",
  "parameters": {
    "certificates": [ "MIIErjCCBFag...Fp23iPeya2s=", ... ]
  }
}
```

### Response example

```
{
  "errorCode": 0,
  "method": "ADD_CERT",
  "result": {
    "added": [
      { "errorCode": 0, "certId": "MIH+MIHlMQsw...NQAAAFwAAAA=", "isUnique": true },
      ...
    ]
  }
}
```

## CERT_INFO method

The method is intended for obtaining information about a certificate. The certificate must comply with the x.509 standard and be version 3.

The method returns an array of certificate extensions in the order in which they are stored in the certificate. If a certificate extension is known to the library, it will be decoded. The list of certificate extensions that can be decoded in CERT_INFO is given in Appendix C. The list of certificate subject and issuer description fields that can be decoded is given in Appendix E.

### Structure of the parameters field in the request

| **Field name** | **Type** | **Description**                                             |
| -------------- | ------- | ----------------------------------------------------------- |
| bytes          | Base64  | Certificate. Mutually exclusive with the certId field       |
| certId         | Base64  | Certificate identifier. Mutually exclusive with the<br>bytes field |

### Structure of the result field in the response

| **Field name**       | **Type**                         | **Description**                        |
| -------------------- | -------------------------------- | -------------------------------------- |
| version              | Integer                          | Certificate version                     |
| serialNumber         | Hex                              | Unique number of the certificate in the CA |
| issuer               | Object                           | Description of the certificate issuer   |
| validity             | Object<br>CERT_VALIDITY          | Certificate validity period             |
| subject              | Object                           | Description of the certificate subject  |
| subjectPublicKeyInfo | Object<br>SUBJECT_PUBLICKEY_INFO | Public key of the certificate subject   |
| extensions           | Object[],<br>EXTENSION_INFO[]    | Array of extensions the certificate has |
| signatureInfo        | Object<br>SIGNATURE_INFO         | Electronic signature of the certificate |
| selfSigned           | Boolean                          | Flag indicating the certificate is self-signed |
| trusted              | Boolean                          | Flag indicating the certificate is trusted at this time: given at<br>initialization or a certificate of a service of a trusted list within<br>its period of trust (see the ADD_TRUST_LIST method). For<br>a certificate given by the bytes field that is not in the certificate<br>cache — false |
| trustListSigner      | Boolean                          | Flag indicating the certificate is for verifying the signature of<br>trusted lists (trustListCache.trustListSignerCerts of the INIT method). Optional |
| trustServices        | Object[]<br>TRUST_SERVICE[]      | The services of trusted lists this certificate is the certificate of.<br>Optional |

### Structure TRUST_SERVICE

| **Field name** | **Type** | **Description** |
| -------------- | -------- | --------------- |
| listId         | String   | Identifier of the trusted list |
| type           | String   | Service type: the part of the type identifier after "/Svctype/",<br>for example "CA/QC", "TSA/QTST", "Certstatus/OCSP/QC",<br>"NationalRootCA-QC" |
| tspName        | String   | Name of the trust service provider |
| tspId          | String   | Registration identifier of the provider from TSPTradeName (ETSI TS 119 612, 5.4.2),<br>for example "NTRUA-36865753". Optional |
| serviceName    | String   | Name of the service |
| forESignatures | Boolean  | The service is for electronic signatures. Optional |
| forESeals      | Boolean  | The service is for electronic seals. Optional |
| statuses       | Object[]<br>TRUST_SERVICE_STATUS[] | Statuses of the service: the first is the current one, then the<br>previous ones |

### Structure TRUST_SERVICE_STATUS

| **Field name** | **Type** | **Description** |
| -------------- | -------- | --------------- |
| status         | String   | Service status: the last part of the status identifier, for example<br>"granted", "withdrawn", "recognisedatnationallevel" |
| from           | String   | Time the status started (UTC) |
| to             | String   | Time the status ended (UTC). Optional — absent for the current<br>status |

### Structure SUBJECT_PUBLICKEY_INFO

| **Field name** | **Type** | **Description**                          |
| -------------- | ------- | ---------------------------------------- |
| bytes          | Base64  | DER-encoded subjectPublicKeyInfo field    |
| algorithm      | OID     | Public key algorithm identifier           |
| parameters     | Base64  | Public key algorithm parameters           |
| publicKey      | Base64  | Public key value                          |

### Structure EXTENSION_INFO

| **Field name** | **Type**                         | **Description**                              |
| -------------- | -------------------------------- | -------------------------------------------- |
| extnId         | String                           | Extension identifier                          |
| critical       | Boolean                          | Flag indicating the extension is critical. Optional |
| extnValue      | Base64                           | Encoded extension value                       |
| decoded        | Object<br>DECODED_EXTENSION_INFO | Decoded extension value. Optional             |

### Structure DECODED_EXTENSION_INFO

| **Field name** | **Type** | **Description**         |
| -------------- | ------- | ----------------------- |
| id             | String  | Extension name           |
| value          | Object  | Extension value.         |

### Structure SIGNATURE_INFO

| **Field name** | **Type** | **Description**                           |
| -------------- | ------- | ----------------------------------------- |
| algorithm      | OID     | Signature algorithm identifier             |
| parameters     | Base64  | Signature algorithm parameters. Optional   |
| signature      | Base64  | Signature value                            |

### Request example

```
{
  "method": "CERT_INFO",
  "parameters": {
    "bytes": "MIIErjCCBFagAwIBAgIUFXeRu...NcYCFp23iPeya2s="
  }
}
```

### Response example

```
{
  "errorCode": 0,
  "method": "CERT_INFO",
  "result": {
    "version": 3,
    "serialNumber": "157791B9508857ED0400...0000",
    "issuer": { "C": "UA", "SERIALNUMBER": "UA-12345678-0001", "CN": "Центр сертифікації ключів", "O": "Test CA", "L": "Київ" },
    "validity": { "notBefore": "2020-08-26 12:34:56", "notAfter": "2022-08-26 12:34:56" },
    "subject": { "C": "UA", "CN": "Серпень Аугусто", "L": "Київ", "SN": "Серпень", "G": "Аугусто" },
    "subjectPublicKeyInfo": {
      "bytes": "MFkwEwYHKoZIzj0CAQY...nZOCZhbZMl3XsA==",
      "algorithm": "1.2.804.2.1.1.1.1.3.1.1",
      "parameters": "MFEGDSqGJAIBAQEBAwEB...uPrFeQQ=",
      "publicKey": "BCEhu7U+dG5kWwuTfPV30tf...8SjmlDitQE="
    },
    "extensions": [
      {
        "extnId": "2.5.29.14",
        "extnValue": "BCAzM/MjlbJMdildTG...98Wazw8wPoj+g==",
        "decoded": {
          "id": "subjectKeyIdentifier",
          "value": {
            "keyIdentifier": "BCB3BE7274D075DD...1370"
          }
        }
      },
      {
        "extnId": "2.5.29.35",
        "extnValue": "BCC8s75ydNB13VIlK2...PPVx/adALwTcA==",
        "decoded": {
          "id": "authorityKeyIdentifier",
          "value": {
            "keyIdentifier": "D0069AA0A8DF7D70...11A6"
          }
        }
      },
      {
        "extnId": "2.5.29.15",
        "critical": true,
        "extnValue": "AwIGwA==",
        "decoded": {
          "id": "keyUsage",
          "value": {
            "digitalSignature": true,
            "contentCommitment": true
          }
        }
      },
      ...
    ],
    "signatureInfo": {
      "algorithm": "1.2.804.2.1.1.1.1.3.1.1",
      "signature": "MIIErjCCBFagAwIBAg...cYCFp23iPeya2s="
    },
    "selfSigned": false
  }
}
```

## GET_CERT method

The method is intended for obtaining a certificate (in DER encoding) from the certificate cache. The method returns the certificate if it is present in the certificate cache; otherwise an error is returned — certificate not found ("CERT_NOT_FOUND").

### Structure of the parameters field in the request

| **Field name** | **Type** | **Description**           |
| -------------- | ------- | ------------------------- |
| certId         | Base64  | Certificate identifier     |

### Structure of the result field in the response

| **Field name** | **Type** | **Description** |
| -------------- | ------- | ---------- |
| bytes          | Base64  | Certificate |

### Request example

```
{
  "method": "GET_CERT",
  "parameters": {
    "certId": "MIH+MIHlMQsw...NQAAAFwAAAA="
  }
}
```

### Response example

```
{
  "errorCode": 0,
  "method": "GET_CERT",
  "result": {
    "bytes": "MIIErjCCBFag...Fp23iPeya2s="
  }
}
```

## LIST_CERTS method

The method is intended for obtaining a list of certificate identifiers from the certificate cache.

The subjectKeyIdentifiers parameter specifies which certificates to return, namely by matching the value of the certificate's subjectKeyIdentifier extension against any value from the array of identifiers. By default the subjectKeyIdentifiers parameter is absent — data for all certificates will be obtained.

### Structure of the parameters field in the request

| **Field name**        | **Type** | **Description**                                                                     |
| --------------------- | ------- | ----------------------------------------------------------------------------------- |
| showCertInfos         | Boolean | Output information for each certificate.<br>Optional, default false    |
| storage               | Boolean | Flag indicating that certificates are stored on the storage.<br>Optional, default false |
| subjectKeyIdentifiers | Hex[]   | Array of private key identifiers.<br>Optional                             |
| subjectKeyId          | Hex     | Private key identifier (deprecated<br>parameter, use<br>subjectKeyIdentifiers). Optional |
| publicKeyBytes        | Base64  | Public key value for filtering<br>certificates. Optional              |
| offset                | Integer | Index of the first certificate.<br>Optional, default 0                       |
| pageSize              | Integer | Maximum number of certificates. Optional                                    |

### Structure of the result field in the response

| **Field name** | **Type**               | **Description**                                                                |
| -------------- | --------------------- | ----------------------------------------------------------------------- |
| certIds        | Base64[]              | Array of certificate identifiers                                      |
| certInfos      | Object[]<br>CERT_INFO | Array of certificate information<br>(CERT_INFO structure). Optional |
| count          | Integer               | Number of certificates                                                  |
| offset         | Integer               | Index of the first certificate                                              |
| pageSize       | Integer               | Maximum number of certificates                                      |

### Structure of the CERT_INFO field

| **Field name**         | **Type**                 | **Description**                                                             |
| ---------------------- | ----------------------- | -------------------------------------------------------------------- |
| certId                 | Base64                  | Certificate identifier                                            |
| serialNumber           | Hex                     | Unique certificate number in the CA                                   |
| issuer                 | Object                  | Description of the certificate issuer                                             |
| validity               | Object<br>CERT_VALIDITY | Certificate validity period                                               |
| subject                | Object                  | Description of the certificate owner                                             |
| keyAlgo                | OID                     | Key algorithm identifier                                        |
| subjectKeyIdentifier   | Hex                     | Key identifier of the certificate owner                             |
| authorityKeyIdentifier | Hex                     | Key identifier of the certificate issuer                              |
| keyUsage               | Object<br>KEY_USAGE     | Key usage, the KEY_USAGE structure<br>is described in Appendix C      |
| extendedKeyUsage       | OID[]                   | Array of extended key usage<br>identifiers. Optional |
| extKeyUsage            | OID[]                   | Array of extended key usage<br>identifiers (deprecated parameter). Optional |
| isCa                   | Boolean                 | Flag indicating a CA certificate. Optional,<br>default false      |
| isCmp  | Boolean | Flag indicating a CMP-service certificate. Optional,<br>default false  |
| isOcsp | Boolean | Flag indicating an OCSP-service certificate. Optional,<br>default false |
| isTsp  | Boolean | Flag indicating a TSP-service certificate. Optional,<br>default false  |
| statusByCRL  | Object<br>CERT_STATUS_INFO | Known certificate status by CRL. Optional    |
| statusByOCSP | Object<br>CERT_STATUS_INFO | Known certificate status by OCSP. Optional   |

### Structure of CERT_STATUS_INFO

| **Field name** | **Type** | **Description**                                                         |
| -------------- | ------- | ---------------------------------------------------------------- |
| status         | String  | Certificate status:<br>"UNDEFINED", "GOOD", "REVOKED", "UNKNOWN" |
| validTime      | Time    | Time at which the status is valid                                    |

### Request example

```
{
  "method": "LIST_CERTS",
  "parameters": {
    "offset": 10,
    "pageSize": 10
  }
}
```

### Response example (with certificate information)

```
{
  "errorCode": 0,
  "method": "LIST_CERTS",
  "result": {
    "certIds": [ "MIGWMH4xCzAJ...QAAAFwAAAA=", ... ],
    "certInfos": [
      ...,
      {
      "certId": "MIH+MIHlMQsw...NQAAAFwAAAA=",
      "serialNumber": "05E19E2CD92EA29...10000004A010000",
      "issuer": { "O": "Test CA", "CN": "Test CA", "C": "UA", "L": "Київ" },
      "validity": { "notBefore": "2023-05-08 08:30:00", "notAfter": "2028-05-08 08:30:00" },
      "subject": { "O": "Test CA", "CN": "OCSP-service", "C": "UA", "L": "Київ" },
      "keyAlgo": "1.2.804.2.1.1.1.1.3.1.1",
      "subjectKeyIdentifier": "BCB3BE7274D075DD...1370",
      "authorityKeyIdentifier": "D0069AA0A8DF7D70...11A6",
      "keyUsage": { "digitalSignature": true },
      "extKeyUsage": ["1.3.6.1.5.5.7.3.9"],
      "isOcsp": true
      },
      ...
    ],
    "count": 29,
    "offset": 10,
    "pageSize": 10
  }
}
```

### Response example (without certificate information)

```
{
  "errorCode": 0,
  "method": "LIST_CERTS",
  "result": {
    "certIds": [ "MIGWMH4xCzAJ...QAAAFwAAAA=", ... ],
    "count": 29,
    "offset": 10,
    "pageSize": 10
  }
}
```

## REMOVE_CERT method

The method removes a certificate from the certificate cache or from the opened storage.

If the certificate to be removed is not specified (bytes and certId are absent), all temporary certificates are removed from the cache (those that were added by the ADD*CERT method without the \_permanent = true* flag or added indirectly in other methods).

A certificate trusted at the initialization (the "certCache.trustedCerts" parameter of the INIT method) is not removed: the method returns the error CERT_TRUSTED_NOT_REMOVABLE.

Output parameters: none.

### Structure of the parameters field in the request

| **Field name** | **Type** | **Description**                                                                        |
| -------------- | ------- | -------------------------------------------------------------------------------------- |
| bytes          | Base64  | Certificate. Optional                                                               |
| certId         | Base64  | Certificate identifier. Optional                                                |
| permanent      | Boolean | Remove the certificate from the permanent cache.<br>Optional, default false |
| storage        | Boolean | Remove the certificate from the storage. Optional,<br>default false              |

### Request example

```
{
  "method": "REMOVE_CERT",
  "parameters": {
    "certId": "MIH+MIHlMQsw...NQAAAFwAAAA="
  }
}
```

### Response example

```
{
  "errorCode": 0,
  "method": "REMOVE_CERT",
  "result": {}
}
```

## VERIFY_CERT method

The method is intended for certificate validation. If the certificate is self-signed, the issuerCertId field is absent from the response.

The validateTime field sets the time value at which the certificate's validity must be determined. If this field is present, validation is performed only by CRL. If this field is absent, the current time is used.

When the checkTrustedRoot parameter is set to true, the certificate chain up to the root is built (as when verifying a signature); if it does not end in a trusted root certificate, the error CERT_NOT_TRUSTED is returned, and if a certificate is missing, the information to find it is in the "expectedCerts" field. Default false: only the certificate and its issuer are checked.

OCSP responses and CRLs are checked by the rules given in the description of the VERIFY method.

### Structure of the parameters field in the request

| **Field name** | **Type** | **Description**                                                                                                |
| -------------- | ------- | -------------------------------------------------------------------------------------------------------------- |
| bytes          | Base64  | Certificate. Mutually exclusive with the certId field                                                                     |
| certId         | Base64  | Key identifier. Mutually exclusive with the<br>certificate field                                                    |
| validationType | String  | Types of certificate validation by revocation status.<br>Has the following values: "CRL" and "OCSP".<br>Optional |
| validateTime   | Time    | Validation time value. Optional                                                                          |
| checkTrustedRoot | Boolean | The certificate chain must end in a trusted<br>root certificate. Optional, default false |

### Structure of the result field in the response

| **Field name**  | **Type**                    | **Description**                                                                   |
| --------------- | -------------------------- | --------------------------------------------------------------------------------- |
| validateTime    | Time                       | Validation check time value                                                 |
| subjectCertId   | Base64                     | User certificate identifier                                             |
| validity        | Object<br>CERT_VALIDITY    | User certificate validity period                                                |
| expired         | Boolean                    | Flag indicating that the certificate has expired                                      |
| selfSigned      | Boolean                    | Flag indicating that the certificate is self-signed                                              |
| trusted         | Boolean                    | Flag indicating that the certificate is trusted                                                   |
| statusSignature | String                     | Status of the certificate's electronic signature:<br>"VALID", "INVALID", "FAILED"          |
| issuerCertId    | Base64                     | Issuer certificate identifier. Optional                                   |
| validateByCRL   | Object<br>VALIDATE_BY_CRL  | Result of checking the user certificate<br>using CRL. Optional  |
| validateByOCSP  | Object<br>VALIDATE_BY_OCSP | Result of checking the user certificate<br>using OCSP. Optional |
| expectedCerts   | Object[]<br>EXPECTED_CERT_INFO[] | Array of information about the certificate required<br>for validation. Optional — present only on<br>error (see VERIFY method) |
| expectedCrls    | Object[]<br>EXPECTED_CRL_INFO[]  | Array of information about the CRL file required<br>for validation. Optional — present only on<br>error (see VERIFY method)   |

### Structure of the VALIDATE_BY_CRL field

| **Field name**   | **Type** | **Description**                                                                                                                                                                                                                                                                              |
| ---------------- | ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| status           | String  | Certificate status:<br>"UNDEFINED", "GOOD", "REVOKED", "UNKNOWN"                                                                                                                                                                                                                             |
| revocationReason | String  | Revocation reason. Possible values:<br>"UNDEFINED", "UNSPECIFIED", "KEY_COMPROMISE",<br>"CA_COMPROMISE", "AFFILIATION_CHANGED",<br>"SUPERSEDED", "CESSATION_OF_OPERATION",<br>"CERTIFICATE_HOLD", "REMOVE_FROM_CRL",<br>"PRIVILEGE_WITHDRAWN", "AA_COMPROMISE".<br>Optional |
| revocationTime   | Time    | Revocation time. Optional                                                                                                                                                                                                                                                              |
| full             | Object<br>CRL_INFO | Information about the full CRL                                                                                                                                                                                                                                                        |
| delta            | Object<br>CRL_INFO | Information about the delta CRL. Optional                                                                                                                                                                                                                                       |

### Structure of the CRL_INFO field

| **Field name**  | **Type** | **Description**                                                         |
| --------------- | ------- | ---------------------------------------------------------------- |
| url             | String  | CRL storage URL. Optional                                 |
| crlId           | Base64  | CRL identifier in the CRL cache                                     |
| statusSignature | String  | Status of the CRL's electronic signature:<br>"VALID", "INVALID", "FAILED" |

### Structure of the VALIDATE_BY_OCSP field

| **Field name**   | **Type**                             | **Description**                                                                                                                                                                                                                                                                              |
| ---------------- | ----------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| status           | String                              | Certificate status:<br>"UNDEFINED", "GOOD", "REVOKED", "UNKNOWN"                                                                                                                                                                                                                             |
| revocationReason | String                              | Revocation reason. Possible values:<br>"UNDEFINED", "UNSPECIFIED", "KEY_COMPROMISE",<br>"CA_COMPROMISE", "AFFILIATION_CHANGED",<br>"SUPERSEDED", "CESSATION_OF_OPERATION",<br>"CERTIFICATE_HOLD", "REMOVE_FROM_CRL",<br>"PRIVILEGE_WITHDRAWN", "AA_COMPROMISE".<br>Optional |
| revocationTime   | Time                                | Revocation time. Optional                                                                                                                                                                                                                                                                |
| responseStatus   | String                              | OCSP response status:<br>"UNDEFINED", "SUCCESSFUL",<br>"MALFORMED_REQUEST", "INTERNAL_ERROR",<br>"TRY_LATER", "SIG_REQUIRED", "UNAUTHORIZED"                                                                                                                                                |
| responderId      | Object<br>RDNAME_INFO<br>or<br>Hex | Certificate description or key identifier of the OCSP<br>service. Optional. The list of certificate description<br>elements is given in Appendix E                                                                                                                                          |
| statusSignature  | String                              | Status of the OCSP response's electronic signature:<br>"VALID", "INVALID", "FAILED"                                                                                                                                                                                                          |
| producedAt       | Time                                | OCSP response creation time                                                                                                                                                                                                                                                                 |
| thisUpdate       | Time                                | Creation time of the current OCSP record                                                                                                                                                                                                                                          |
| nextUpdate       | Time                                | Creation time of the next OCSP record.<br>Optional                                                                                                                                                                                                                                        |
| certIds          | Base64[]                            | Array of identifiers of the certificates present in the<br>OCSP response. Optional                                                                                                                                                                                                           |
| certId           | Base64                              | Certificate identifier of the OCSP response<br>signer. Optional                                                                                                                                                                                                                        |
| ocspNoCheck      | Boolean                             | Flag indicating that the certificate has the<br>ocsp-no-check extension (id-pkix-ocsp-nocheck).<br>Optional                                                                                                                                                                                |

### Request example

```
{
  "method": "VERIFY_CERT",
  "parameters": {
    "bytes": "MIIErjCCBFag...Fp23iPeya2s="
  }
}
```

### Response example

```
{
  "errorCode": 0,
  "method": "VERIFY_CERT",
  "result": {
    "validateTime": "2021-04-29 12:34:56",
    "subjectCertId": "MIH+MIHlMQsw...NQAAAFwAAAA=",
    "validity": { "notBefore": "2020-08-26 23:13:07", "notAfter": "2022-08-26 23:13:07" },
    "expired": false,
    "selfSigned": false,
    "trusted": false,
    "statusSignature": "VALID",
    "issuerCertId": "MIH+MIHlMQsw...AQAAAAEAAAA="
  }
}
```

### Response example with OCSP response

```
{
  "errorCode": 0,
  "method": "VERIFY_CERT",
  "result": {
    "validateTime": "2021-04-29 12:34:56",
    "subjectCertId": "MIH+MIHlMQsw...NQAAAFwAAAA=",
    "validity": { "notBefore": "2020-08-26 23:13:07", "notAfter": "2022-08-26 23:13:07" },
    "expired": false,
    "selfSigned": false,
    "trusted": false,
    "statusSignature": "VALID",
    "issuerCertId": "MIH+MIHlMQsw...AQAAAAEAAAA=",
    "validateByOCSP": {
      "status": "GOOD",
      "responseStatus": "SUCCESSFUL",
      "responderId": { "O": "Test CA", "CN": "OCSP-service", "C": "UA", "L": "Київ" },
      "statusSignature": "VALID",
      "producedAt": "2021-04-29 12:34:56",
      "thisUpdate": "2021-04-29 12:34:56"
    }
  }
}
```

## GENERATE_CERTBUNDLE method

The method is intended for generating a file containing a certificate bundle and CRLs in PKCS#7 format. It is used for storing several certificates in a single file, usually a trust chain (root and intermediate certificates). The certificates and crls parameters are optional; one of them must be specified.

For storage in a binary file, it is recommended to use the p7b file extension. The result can be used in the ADD_CERT method (bundle parameter).

### Structure of the parameters field in the request

| **Field name** | **Type**  | **Description**                         |
| -------------- | -------- | -------------------------------- |
| certificates   | Base64[] | Array of certificates. Optional |
| crls           | Base64[] | Array of CRL files. Optional   |

### Structure of the result field in the response

| **Field name** | **Type** | **Description**         |
| -------------- | ------- | ---------------- |
| bytes          | Base64  | Generated data |

### Request example

```
{
  "method": "GENERATE_CERTBUNDLE",
  "parameters": {
    "certificates": [ "MIIDLzCCAtSg...XSqzC+Q0k4jq", "MIIEuDCCA6Cg...4/swFO0jGQNQ" ]
  }
}
```

### Response example

```
{
  "errorCode": 0,
  "method": "GENERATE_CERTBUNDLE",
  "result": {
    "bytes": "MIIIGgYJKoZI...FO0jGQNQMQA="
  }
}
```

## CERT_STATUS_BY_OCSP method

The method is intended for forming an OCSP request and obtaining an OCSP response. The method allows forming an OCSP request based on the issuer certificate and the certificate serial number, or based on individual parameters. If the url field is not specified in the method request, the OCSP request will not be sent to the OCSP service — the result of the method will be only the requestBytes field in the method response.

### Structure of the parameters field in the request

| **Field name** | **Type** | **Description**                                                                                                                                                  |
| -------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| url            | String  | OCSP-service URL. Optional                                                                                                                                     |
| hashAlgo       | OID     | Hash algorithm identifier                                                                                                                                         |
| issuerCertId   | Base64  | Issuer certificate identifier. Optional                                                                                                                           |
| serialNumber   | Hex     | Unique certificate number in the CA                                                                                                                                        |
| issuerBytes    | Base64  | Value of the issuer field of the certificate issuer.<br>Optional                                                                                                                 |
| issuerNameHash | Hex     | Hash value of the issuer field of the certificate issuer.<br>Optional                                                                                                            |
| issuerKeyHash  | Hex     | Hash value of the public key of the certificate<br>issuer. Optional                                                                                                       |
| nonceLen       | Integer | Length of the one-time random number in the OCSP<br>request. If the value is 0 or absent, the<br>random number is not used in the OCSP request.<br>Optional |

### Structure of the result field in the response

| **Field name**  | **Type**                             | **Description**                                                                                                                                   |
| --------------- | ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| requestBytes    | Base64                              | OCSP request                                                                                                                                 |
| bytes           | Base64                              | OCSP response                                                                                                                             |
| responseStatus  | String                              | OCSP response status: "UNDEFINED", "SUCCESSFUL",<br>"MALFORMED_REQUEST", "INTERNAL_ERROR",<br>"TRY_LATER", "SIG_REQUIRED", "UNAUTHORIZED" |
| status          | String                              | Certificate status:<br>"UNDEFINED", "GOOD", "REVOKED", "UNKNOWN"                                                                           |
| revocationReason | String                             | Revocation reason (see the VERIFY_CERT method).<br>Optional — present if the status is "REVOKED"                                          |
| revocationTime  | Time                                | Revocation time. Optional — present if the<br>status is "REVOKED"                                                                        |
| certIds         | Base64[]                            | Array of identifiers of the certificates present in the<br>OCSP response                                                                       |
| certId          | Base64                              | Certificate identifier                                                                                                                  |
| producedAt      | Time                                | OCSP response creation time                                                                                                               |
| thisUpdate      | Time                                | Creation time of the current OCSP record                                                                                                        |
| nextUpdate      | Time                                | Creation time of the next OCSP record.<br>Optional                                                                                      |
| responderId     | Object<br>RDNAME_INFO<br>or<br>Hex | Certificate description or key identifier of the OCSP<br>service. Optional. The list of certificate description<br>elements is given in Appendix E        |
| statusSignature | String                              | Status of the OCSP response's electronic signature:<br>"VALID", "INVALID", "FAILED"                                                                |

### Request example

```
{
  "method": "CERT_STATUS_BY_OCSP",
  "parameters": {
    "url": "http://url_ca/services/ocsp/",
    "hashAlgo": "1.2.804.2.1.1.1.1.2.1",
    "issuerCertId": "MIH+MIHlMQsw...AQAAAAEAAAA=",
    "serialNumber": "157791B9508857ED04000000...0000"
  }
}
```

### Response example

```
{
  "errorCode": 0,
  "method": "CERT_STATUS_BY_OCSP",
  "result": {
    "requestBytes": "MHAwbjBsMGow...AKkeBgBzpXYA",
    "bytes": "MII2ZwoBAKCC...uvw4P7wsFTk=",
    "responseStatus": "SUCCESSFUL",
    "status": "GOOD",
    "certIds": [ "MIH+MIHlMQsw...NQAAAFwAAAA=", "MIH+MIHlMQsw...AQAAAAEAAAA=" ],
    "certId": "MIH+MIHlMQsw...NQAAAFwAAAA=",
    "producedAt": "2023-08-01 12:34:56",
    "thisUpdate": "2023-08-01 12:34:56",
    "responderId": { "O": "Test CA", "CN": "OCSP-service", "C": "UA", "L": "Київ" },
    "statusSignature": "VALID"
  }
}
```

## ADD_TRUST_LIST method

The method is intended for adding a trusted list (ETSI TS 119 612, an XML document with a XAdES signature). The method does not download a trusted list.

A trusted list is accepted if:

- it is signed by one of the certificates given in the trustListCache.trustListSignerCerts field of the INIT method;
- its sequence number is not less than the number of the trusted list with the same identifier accepted before.

The certificates of the services of the trusted list are added to the certificate cache (without saving to disk) with the information about the services; a certificate of a service becomes trusted for the period from the first time the service was provided to the end of the last period it was provided in (without a limit while the service is provided). The trust is decided at a time: for the certificate of the signer — at the best signature time, for the certificate of a time-stamping service — at the time of its time-stamp (with the validation policy value "tsaTrust" equal to "proofOfExistence" — at the time of a later valid time-stamp that covers it, and without one — at the validation time), for the VERIFY_CERT method — at the validation time; if the certificate of a trusted list was not trusted at that time, the report of the validation type "FULL-ETSI" has the sub-indication "NO_CERTIFICATE_CHAIN_FOUND_NO_POE". Breaks in the provision of the service within this period do not affect the trust and are taken into account in the signature quality only. A certificate that is trusted itself at that time (a certificate of a service of a trusted list — a time-stamping service, an OCSP responder) ends its own chain: the certificates of its issuers and its status are not needed. The time-stamps of a service whose certificate is revoked for a key compromise or with no reason given are not accepted whenever they were made; of one revoked for another reason — are accepted if made before the revocation (RFC 3161, section 4). Adding a trusted list again replaces the information received from its previous version. The information about the services is returned by the CERT_INFO method and used by the VERIFY method.

For a session with a shared memory the trusted list is applied to the shared memory and is in effect for all its sessions; the certificates for signing trusted lists and the directory of trusted lists are the ones given at the initialization of the shared memory.

### Structure of the parameters field in the request

| **Field name** | **Type** | **Description** |
| -------------- | -------- | --------------- |
| bytes          | Base64   | Trusted list (XML document). Mutually exclusive with the text field |
| text           | String   | Trusted list as the text of the XML document (UTF-8). Mutually<br>exclusive with the bytes field |

### Structure of the result field in the response

| **Field name**    | **Type** | **Description** |
| ----------------- | -------- | --------------- |
| listId            | String   | Identifier of the trusted list: its first distribution point<br>(DistributionPoints), or the territory and the type of the list if<br>there is none |
| type              | String   | Type of the trusted list: the last part of the TSLType identifier |
| territory         | String   | Scheme territory (SchemeTerritory) |
| schemeName        | String  | Name of the scheme: in English if the list has it, else the first one. May be empty |
| schemeOperatorName | String | Name of the scheme operator: the same. May be empty |
| sequenceNumber    | Integer  | Sequence number of the trusted list (TSLSequenceNumber) |
| listIssueDateTime | String   | Issue time of the trusted list (UTC). Optional |
| nextUpdate        | String   | Time of the next update (UTC). Optional |
| signerCertId      | Base64   | Identifier of the certificate the trusted list is signed with |
| countProviders    | Integer  | Number of trust service providers |
| countServices     | Integer  | Number of services |
| countCerts        | Integer  | Number of certificates of the services |
| countAddedCerts   | Integer  | Number of certificates that were not in the certificate cache |
| countTrustedCerts | Integer  | Number of certificates of the trusted list that are trusted at this time |
| countSkippedCerts | Integer  | Number of certificates the library did not parse (for example,<br>x.509 version 1); their services are not taken into account |
| stored            | Boolean  | Flag indicating the trusted list is saved in the directory<br>trustListCache.path |
| warnings          | String[] | Remarks on the certificate that signs the trusted list<br>(ETSI TS 119 612, clause 5.7.1). Optional |

In case of an error the result field may contain: "detail" (String) — the reason of the refusal; "xmlError" (String) and "xmlErrorOffset" (Integer) — the error of parsing the XML document and its offset.

| **Value of warnings** | **Description** |
| --- | --- |
| "SIGNER_WITHOUT_TSL_SIGNING_KEY_PURPOSE" | The certificate has no extended key usage<br>id-tsl-kp-tslSigning (0.4.0.2231.3.0) |
| "SIGNER_WITH_OTHER_KEY_USAGE" | The key usage of the certificate has values other than<br>digitalSignature and nonRepudiation |
| "SIGNER_COUNTRY_IS_NOT_SCHEME_TERRITORY" | The country in the name of the certificate is not the scheme territory |
| "SIGNER_ORGANIZATION_IS_NOT_SCHEME_OPERATOR_NAME" | The organization in the name of the certificate is none of the<br>scheme operator names |
| "SIGNER_ISSUER_IS_NOT_A_SERVICE_OF_THE_LIST" | The certificate is not self-signed and its issuer is not a service<br>of this trusted list |
| "LIST_NEXT_UPDATE_PASSED" | The next update time of the list (NextUpdate) is passed: the list<br>is accepted, it is to be obtained again (ETSI TS 119 612, 5.3.15) |

Errors of the method: TRUST_LIST_INVALID, TRUST_LIST_VERIFY_FAILED, TRUST_LIST_SIGNER_NOT_TRUSTED, TRUST_LIST_OBSOLETE (Appendix A).

### Request example

```
{
  "method": "ADD_TRUST_LIST",
  "parameters": {
    "bytes": "PD94bWwgdmVy...dExpc3Q+"
  }
}
```

### Response example

```
{
  "errorCode": 0,
  "method": "ADD_TRUST_LIST",
  "result": {
    "listId": "https://czo.gov.ua/download/tl/TL-UA-DSTU.xml",
    "type": "CClist",
    "territory": "UA",
    "sequenceNumber": 196,
    "listIssueDateTime": "2026-09-17 13:33:00",
    "nextUpdate": "2027-03-17 13:33:00",
    "signerCertId": "MIIBJzCB1TCB...AgEBAgEH",
    "countProviders": 34,
    "countServices": 416,
    "countCerts": 416,
    "countAddedCerts": 416,
    "countTrustedCerts": 255,
    "countSkippedCerts": 0,
    "stored": true,
    "warnings": [
      "SIGNER_ORGANIZATION_IS_NOT_SCHEME_OPERATOR_NAME"
    ]
  }
}
```

## LIST_TRUST_LISTS method

The method returns the list of the accepted trusted lists: the last accepted version of every list (the ADD_TRUST_LIST method and the lists of the directory of trusted lists read at the initialization).

Input parameters: none.

### Structure of the result field in the response

| **Field name** | **Type** | **Description** |
| -------------- | -------- | --------------- |
| trustLists     | Object[]<br>TRUST_LIST_INFO[] | The accepted trusted lists |

### Structure of the TRUST_LIST_INFO record

| **Field name** | **Type** | **Description** |
| -------------- | -------- | --------------- |
| listId            | String  | Identifier of the list |
| type              | String  | Type of the list |
| territory         | String  | Scheme territory |
| schemeName        | String  | Name of the scheme: in English if the list has it, else the first one. May be empty |
| schemeOperatorName | String | Name of the scheme operator: the same. May be empty |
| sequenceNumber    | Integer | Sequence number of the list |
| listIssueDateTime | String  | Issue time of the list. Optional |
| nextUpdate        | String  | Next update time. Optional |
| nextUpdatePassed  | Boolean | Flag: the next update time is passed |
| signerCertId      | Base64  | Identifier of the certificate that signs the list |
| countCerts        | Integer | Number of the certificates of the services of the list |
| countTrustedCerts | Integer | Number of the certificates trusted by the list when it was accepted |
| stored            | Boolean | Flag: the list is kept in the directory of trusted lists |

### Request example

```
{
  "method": "LIST_TRUST_LISTS"
}
```

### Response example

```
{
  "errorCode": 0,
  "method": "LIST_TRUST_LISTS",
  "result": {
    "trustLists": [
      {
        "listId": "https://czo.gov.ua/download/tl/TL-UA-DSTU.xml",
        "type": "CClist",
        "territory": "UA",
        "sequenceNumber": 196,
        "listIssueDateTime": "2026-09-17 13:33:00",
        "nextUpdate": "2026-12-17 13:33:00",
        "nextUpdatePassed": false,
        "signerCertId": "MIIBJzCB1TCB...AgEBAgEH",
        "countCerts": 416,
        "countTrustedCerts": 255,
        "stored": true
      }
    ]
  }
}
```

## ADD_CRL method

The method is intended for adding a CRL (certificate revocation list) to the CRL cache. It returns the CRL identifier in the CRL cache. CRLs may be added to the CRL cache permanently (with storage on disk) or temporarily (only for the duration of the current session until DEINIT is executed or the application is restarted, or until REMOVE_CRL without "crlId"). The CRLs of signatures are added temporarily during VERIFY as well. If a CRL is in the cache as a temporary one, adding it again with "permanent" true stores it on disk. As soon as a newer CRL of the same issuer and segment is added, the older ones become obsolete: their files are deleted from disk at once, and from memory by the REMOVE_CRL method; an older CRL added after a newer one is not stored on disk. If the permanent CRL cache is not initialized (the path to the corresponding directory was not specified when initializing the library), only temporary addition of CRLs is possible.

The CRL must conform to the x.509 standard.

A CRL is added only if it is signed by its issuer: the certificate cache must hold a certificate with the key identifier of the CRL (authorityKeyIdentifier) and the name of the CRL issuer, with the cRLSign bit of keyUsage, and the signature of the CRL must be valid. Otherwise an error is returned (CERT_NOT_FOUND, VERIFY_FAILED, INVALID_KEY_USAGE or CRL_NOT_FOUND). The same checks apply to a CRL the library downloads itself. The CRL cache keeps the freshest CRL of every issuer, for segmented CRLs - of every segment.

### Structure of the parameters field in the request

| **Field name** | **Type** | **Description**                       |
| -------------- | ------- | ------------------------------ |
| bytes          | Base64  | Binary CRL data               |
| permanent      | Boolean | Flag to save the CRL in the CRL cache |

### Structure of the result field in the response

| **Field name** | **Type** | **Description**                        |
| -------------- | ------- | ------------------------------- |
| crlId          | Base64  | CRL identifier               |
| isUnique       | Boolean | Certificate uniqueness flag |

### Request example

```
{
  "method": "ADD_CRL",
  "parameters": {
    "bytes": "MIIJajCCCRIC...15Wd5gBHHCg="
  }
}
```

### Response example

```
{
  "errorCode": 0,
  "method": "ADD_CRL",
  "result": {
    "crlId": "MIHtMIHlMQsw...0ZfQsgIDAULT",
    "isUnique": true
  }
}
```

## CRL_INFO method

The method is intended for obtaining the information stored in a CRL.

### Structure of the parameters field in the request

| **Field name**   | **Type** | **Description**                                                             |
| ---------------- | ------- | ---------------------------------------------------------------------------- |
| bytes            | Base64  | Binary CRL data. Mutually exclusive with the crlId field                              |
| crlId            | Base64  | CRL identifier. Mutually exclusive with the bytes field                             |
| showRevokedCerts | Boolean | Display the list of revoked certificates.<br>Default true |

### Structure of the result field in the response

| **Field name**    | **Type**                         | **Description**                                                                      |
| ----------------- | ------------------------------- | ----------------------------------------------------------------------------- |
| issuer            | Object                          | Issuer description                                                                  |
| thisUpdate        | Time                            | Creation time of the current CRL                                                   |
| nextUpdate        | Time                            | Creation time of the next CRL                                                  |
| countRevokedCerts | Integer                         | Number of revoked certificates                                            |
| authorityKeyId    | Hex                             | CA key identifier                                                        |
| crlNumber         | Hex                             | CRL issue sequence number                                                  |
| deltaCrlIndicator | Hex                             | Number of the full CRL issue. Optional                                       |
| distributionPoints | String[]                       | Array of full CRL storage URLs.<br>Optional                       |
| freshestCRL       | String[]                        | Array of delta CRL storage URLs.<br>Optional                    |
| revokedCerts      | Object[]<br>REVOKED_CERT_INFO[] | Array of revoked certificates<br>(REVOKED_CERT_INFO structure). Optional |

### Structure of the REVOKED_CERT_INFO field

| **Field name**  | **Type** | **Description**                                                                                                                                                                                                                                                                              |
| --------------- | ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| userCertificate | Hex     | Serial number of the revoked certificate                                                                                                                                                                                                                                                      |
| revocationDate  | Time    | Revocation time                                                                                                                                                                                                                                                                              |
| crlReason       | String  | Revocation reason. Optional. Possible<br>values:<br>"UNDEFINED", "UNSPECIFIED", "KEY_COMPROMISE",<br>"CA_COMPROMISE", "AFFILIATION_CHANGED",<br>"SUPERSEDED", "CESSATION_OF_OPERATION",<br>"CERTIFICATE_HOLD", "REMOVE_FROM_CRL",<br>"PRIVILEGE_WITHDRAWN", "AA_COMPROMISE" |
| invalidityDate  | Time    | Invalidity time                                                                                                                                                                                                                                                                              |

### Request example

```
{
  "method": "CRL_INFO",
  "parameters": {
    "bytes": "MIIJajCCCRIC...15Wd5gBHHCg="
  }
}
```

### Response example
```
{
  "errorCode": 0,
  "method": "CRL_INFO",
  "result": {
    "issuer": { "C": "UA", "SERIALNUMBER": "UA-12345678-0001", "CN": "Центр сертифікації ключів", "O": "Організація", "OU": "ЦСК", "L": "Київ" },
    "thisUpdate": "2021-07-31 06:00:00",
    "nextUpdate": "2021-08-07 06:00:00",
    "countRevokedCerts": 25,
    "authorityKeyId": "D0069AA0...9EA28CC7",
    "crlNumber": "0142D3",
    "revokedCerts": [
      { "userCertificate": "157791B95088...14000000", "revocationDate": "2019-04-17 15:16:22", "crlReason": "SUPERSEDED", "invalidityDate": "2019-04-17 15:16:22" },
      { "userCertificate": "157791B95088...35000000", "revocationDate": "2019-11-07 14:20:06", "crlReason": "CERTIFICATE_HOLD", "invalidityDate": "2019-11-07 14:20:06" },
      ...
    ]
  }
}
```

## LIST_CRLS method

The method is intended for obtaining a list of CRLs in the CRL cache.

### Structure of the parameters field in the request

| **Field name** | **Type** | **Description**                                                        |
| -------------- | ------- | ------------------------------------------------------------------------ |
| showCrlInfos   | Boolean | Output information for each CRL.<br>Optional, default false |
| offset         | Integer | Index of the first CRL.<br>Optional, default 0                    |
| pageSize       | Integer | Maximum number of CRLs. Optional                                  |

### Structure of the result field in the response

| **Field name** | **Type**              | **Description**                                                      |
| -------------- | -------------------- | ------------------------------------------------------------- |
| crlIds         | Base64[]             | Array of CRL identifiers                                     |
| crlInfos       | Object[]<br>CRL_INFO | Array of CRL information (CRL_INFO structure).<br>Optional |
| count          | Integer              | Number of CRLs                                                 |
| offset         | Integer              | Index of the first CRL                                            |
| pageSize       | Integer              | Maximum number of CRLs                                     |

### Structure of the CRL_INFO field

| **Field name**    | **Type** | **Description**                               |
| ----------------- | ------- | --------------------------------------- |
| crlId             | Base64  | CRL identifier                       |
| issuer            | Object  | Issuer description                            |
| thisUpdate        | Time    | Creation time of the current CRL             |
| nextUpdate        | Time    | Creation time of the next CRL            |
| countRevokedCerts | Integer | Number of revoked certificates      |
| authorityKeyId    | Hex     | CA key identifier                  |
| crlNumber         | Hex      | CRL issue sequence number                             |
| deltaCrlIndicator | Hex      | Number of the full CRL issue. Optional                  |
| distributionPoints | String[] | Array of full CRL storage URLs.<br>Optional |
| freshestCRL       | String[]  | Array of delta CRL storage URLs.<br>Optional |
| isObsolete        | Boolean  | Flag indicating that the CRL is obsolete                                  |

### Request example

```
{
  "method": "LIST_CRLS",
  "parameters": {
    "offset": 0,
    "showCrlInfos": true
  }
}
```

### Response example
```
{
  "errorCode": 0,
  "method": "LIST_CRLS",
  "result": {
    "crlIds": [ "MIHpMIHhMRYw...RltGE0ZbQutC", ... ],
    "crlInfos": [
      {
        "crlId": "MIHpMIHhMRYw...RltGE0ZbQutC",
        "issuer": { "C": "UA", "SERIALNUMBER": "UA-12345678-0001", "CN": "Центр сертифікації ключів", "O": "Організація", "OU": "ЦСК", "L": "Київ" },
        "thisUpdate": "2023-08-01 14:51:10",
        "nextUpdate": "2023-08-01 16:53:12",
        "countRevokedCerts": 118,
        "authorityKeyId": "D0069AA0...9EA28CC7",
        "crlNumber": "095178",
        "deltaCrlIndicator": "0947B1",
        "isObsolete": true
      },
      {
        "crlId": "MIHpMIHhMRYw...MDMzAgMJj9g=",
        "issuer": { "C": "UA", "SERIALNUMBER": "UA-12345678-0001", "CN": "Центр сертифікації ключів", "O": "Організація", "OU": "ЦСК", "L": "Київ" },
        "thisUpdate": "2023-08-01 16:53:12",
        "nextUpdate": "2023-08-01 18:53:12",
        "countRevokedCerts": 123,
        "authorityKeyId": "D0069AA0...9EA28CC7",
        "crlNumber": "095179",
        "deltaCrlIndicator": "0947B1"
      },
      ...
    ],
    "count": 4,
    "offset": 0,
    "pageSize": 4
  }
}
```

## REMOVE_CRL method

The method is intended for removing a specified CRL (optionally) and obsolete CRLs from the CRL cache. If a CRL identifier is specified in the request, the method first removes the specified CRL, and then all obsolete CRLs. Without a CRL identifier the method removes the obsolete and the temporary CRLs (added without "permanent" true, the CRLs of signatures included). Response parameters: none.

### Structure of the parameters field in the request

| **Field name** | **Type** | **Description**                                                                                        |
| -------------- | ------- | ------------------------------------------------------------------------------------------------ |
| crlId          | Base64  | CRL identifier in the CRL cache                                                                     |
| permanent      | Boolean | Flag to remove the CRL from the CRL storage location.<br>Optional, default false |

### Request example

```
{
  "method": "REMOVE_CRL",
  "parameters": {
    "crlId": "MIHtMIHlMQsw...0ZfQsgIDAULT",
    "permanent": true
  }
}
```

### Response example

```
{
  "errorCode": 0,
  "method": "REMOVE_CRL",
  "result": {}
}
```

## RANDOM_BYTES method

The method is intended for generating a cryptographically secure pseudorandom sequence.

### Structure of the parameters field in the request

| **Field name** | **Type** | **Description**                                            |
| -------------- | -------- | ---------------------------------------------------------- |
| length         | Integer  | Length of the data in bytes, the value must be<br>greater than 0 |

### Structure of the result field in the response

| **Field name** | **Type** | **Description**            |
| -------------- | -------- | -------------------------- |
| bytes          | Base64   | Generated random data      |

### Request example

```
{
  "method": "RANDOM_BYTES",
  "parameters": {
    "length": 32
  }
}
```

### Response example

```
{
  "errorCode": 0,
  "method": "RANDOM_BYTES",
  "result": {
    "bytes": "exW+I6VE8nAnKS7U+xtLxePF1V5dJXIIV2RevNW5LmM="
  }
}
```

## DIGEST method

The method is intended for hashing data. The hashAlgo or signAlgo parameter (only one of them at a time) is used to specify the hashing algorithm. The data to be hashed can be provided in one of three ways:

- directly as a base64-encoded string;

- as a full path to a file containing the data to be hashed (the file must be readable);

- as a pointer to and size of a memory region.

### Structure of the parameters field in the request

| **Field name** | **Type** | **Description**                                          |
| -------------- | -------- | -------------------------------------------------------- |
| hashAlgo       | String   | Hashing algorithm. Mutually exclusive with the<br>signAlgo field |
| signAlgo       | String   | Signature algorithm. Mutually exclusive with the hashAlgo field |
| bytes          | Base64   | Input data, if the data is given directly                |
| file           | String   | Input data stored in a file                              |
| ptr            | Hex      | Pointer to the data in memory                            |
| size           | Integer  | Length of the input data in memory                       |

### Structure of the result field in the response

| **Field name** | **Type** | **Description**                            |
| -------------- | -------- | ------------------------------------------ |
| hashAlgo       | String   | Hashing algorithm that was used            |
| bytes          | Base64   | Hash function value of the data            |

### Request example, data given directly

```
{
  "method": "DIGEST",
  "parameters": {
    "hashAlgo": "2.16.840.1.101.3.4.2.1",
    "bytes": "VGhlIHF1aWNrIGJyb3duIGZve...IGRvZw=="
  }
}
```

### Request example, data stored in a file

```
{
  "method": "DIGEST",
  "parameters": {
    "hashAlgo": "2.16.840.1.101.3.4.2.1",
    "file": "~/docs/filename.doc"
  }
}
```

### Request example, data located in memory

```
{
  "method": "DIGEST",
  "parameters": {
    "hashAlgo": "2.16.840.1.101.3.4.2.1",
    "ptr": "000001940D2F8400",
    "size": 10000000
  }
}
```

### Response example

```
{
  "errorCode": 0,
  "method": "DIGEST",
  "result": {
    "hashAlgo": "2.16.840.1.101.3.4.2.1",
    "bytes": "16j7swfXgJRpypq8sAguT41...vzfJ5ZI="
  }
}
```

## ASN1_DECODE method

The method is intended for decoding DER-encoded ASN.1 data. The list of ASN.1 types that can be decoded is given in Appendix D.

### Structure of the parameters field in the request

| **Field name** | **Type**                   | **Description**                                  |
| -------------- | -------------------------- | ------------------------------------------------ |
| items          | Object[],<br>DECODE_ITEM[] | Array of structures containing the data to decode |

### Structure DECODE_ITEM

| **Field name** | **Type** | **Description**               |
| -------------- | -------- | ----------------------------- |
| bytes          | Base64   | Data to decode                |
| id             | String   | Data identifier. Optional     |

### Structure of the result field in the response

| **Field name** | **Type**                    | **Description**                              |
| -------------- | --------------------------- | -------------------------------------------- |
| decoded        | Object[],<br>DECODED_ITEM[] | Array of structures containing the decoded data |

### Structure DECODED_ITEM

| **Field name** | **Type**                    | **Description**                                                                                              |
| -------------- | --------------------------- | ------------------------------------------------------------------------------------------------------------- |
| id             | String                      | Data identifier. Optional — present<br>if it was specified in the request                                    |
| tag            | String<br>or<br>Integer     | ASN.1 type identifier (tag):<br>String — for known tags (see Appendix D);<br>Integer — for unknown ones      |
| value          | Base64<br>Boolean<br>String | Decoded value according to the ASN.1 type                                                                    |
| integer        | Integer                     | Integer number. Optional                                                                                     |
| bytes          | Base64                      | Value without decoding. Optional                                                                             |
| error          | Boolean                     | Decoding error indicator. Optional —<br>present only in case of an error                                     |

### Request example

```
{
  "method": "ASN1_DECODE",
  "parameters": {
    "items": [
      { "id": "boolean-true", "bytes": "AQH/" },
      { "id": "integer-1", "bytes": "AgEB" },
      { "id": "integer-big", "bytes": "AhQ9tz578NV1sgEAAAABAAAAugAAAA==" },
      { "id": "octet-string", "bytes": "BAowMTIzNDU2Nzg5" },
      { "id": "null", "bytes": "BQA=" },
      { "id": "oid-12345", "bytes": "BgQqAwQF" },
      { "id": "printable-string", "bytes": "EytUaGUgcXVpY2sgYnJvd24gZm94IGp1bXBzIG92ZXIgdGhlIGxhenkgZG9n" },
      { "id": "utf8-string", "bytes": "DFzQodC/0YDQuNGC0L3QsCDQsdGD0YDQsCDQu9C40YHQuNGG0Y8g0YHRgtGA0LjQsdCw0ZQg0YfQtdGA0LXQtyDQu9C10LTQsNGH0L7Qs9C+INGB0L7QsdCw0LrRgw==" },
      { "id": "ia5-string", "bytes": "FitUaGUgcXVpY2sgYnJvd24gZm94IGp1bXBzIG92ZXIgdGhlIGxhenkgZG9n" },
      { "id": "utc-time", "bytes": "Fw0yMTA3MDgxMjM0NTZa" },
      { "id": "generalized-time", "bytes": "GA8yMDIxMDcwODEyMzQ1Nlo=" }
    ]
  }
}
```

### Response example
```
{
  "errorCode": 0,
  "method": "ASN1_DECODE",
  "result": {
    "decoded": [
      { "id": "boolean-true", "tag": "BOOLEAN", "value": true },
      { "id": "integer-1", "tag": "INTEGER", "value": "AQ==", "integer": 1 },
      { "id": "integer-big", "tag": "INTEGER", "value": "Pbc+e/DVdbIBAAAAAQAAALoAAAA=" },
      { "id": "octet-string", "tag": "OCTET_STRING", "value": "MDEyMzQ1Njc4OQ==" },
      { "id": "null", "tag": "NULL" },
      { "id": "oid-12345", "tag": "OID", "value": "1.2.3.4.5" },
      {
        "id": "printable-string",
        "tag": "PRINTABLE_STRING",
        "value": "The quick brown fox jumps over the lazy dog",
        "bytes": "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw=="
      },
      {
        "id": "utf8-string",
        "tag": "UTF8_STRING",
        "value": "Спритна бура лисиця стрибає через ледачого собаку",
        "bytes": "0KHQv9GA0LjRgtC90LAg0LHRg9GA0LAg0LvQuNGB0LjRhtGPINGB0YLRgNC40LHQsNGUINGH0LXRgNC10Lcg0LvQtdC00LDRh9C+0LPQviDRgdC+0LHQsNC60YM="
      },
      {
        "id": "ia5-string",
        "tag": "IA5_STRING",
        "value": "The quick brown fox jumps over the lazy dog",
        "bytes": "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw=="
      },
      {
        "id": "utc-time",
        "tag": "UTC_TIME",
        "value": "2021-07-08 12:34:56",
        "integer": 1625747696000
      },
      {
        "id": "generalized-time",
        "tag": "GENERALIZED_TIME",
        "value": "2021-07-08 12:34:56",
        "integer": 1625747696000
      }
    ]
  }
}
```

## ASN1_ENCODE method

The method is intended for encoding data according to ASN.1 DER encoding. The list of ASN.1 types that can be encoded is given in Appendix D.

### Structure of the parameters field in the request

| **Field name** | **Type**                   | **Description**                                  |
| -------------- | -------------------------- | ------------------------------------------------ |
| items          | Object[],<br>ENCODE_ITEM[] | Array of structures containing the data to encode |

### Structure ENCODE_ITEM

| **Field name** | **Type**                    | **Description**                                          |
| -------------- | --------------------------- | -------------------------------------------------------- |
| tag            | String                      | ASN.1 type identifier (tag)                              |
| value          | Base64<br>Boolean<br>String | Data to encode. Optional, depends on the<br>type         |
| integer        | Integer                     | Integer number. Optional, depends on the type            |
| id             | String                      | Data identifier. Optional                                |

### Structure of the result field in the response

| **Field name** | **Type**                     | **Description**                              |
| -------------- | ---------------------------- | -------------------------------------------- |
| encoded        | Object[],<br>ENCODED_ITEM[]  | Array of structures containing the encoded data |

### Structure ENCODED_ITEM

| **Field name** | **Type** | **Description**                                                           |
| -------------- | -------- | -------------------------------------------------------------------------- |
| bytes          | Base64   | Encoded data                                                              |
| id             | String   | Data identifier. Optional                                                 |
| error          | Boolean  | Encoding error indicator. Optional —<br>present only in case of an error  |

### Request example

```
{
  "method": "ASN1_ENCODE",
  "parameters": {
    "items": [
      {
        "id": "boolean-FALSE",
        "tag": "BOOLEAN",
        "value": false
      }, {
        "id": "boolean-TRUE",
        "tag": "BOOLEAN",
        "value": true
      }, {
        "id": "integer-1-as-integer",
        "tag": "INTEGER",
        "integer": 1
      }, {
        "id": "integer-2-as-value",
        "tag": "INTEGER",
        "value": "Ag=="
      }, {
        "id": "integer-big",
        "tag": "INTEGER",
        "value": "Pbc+e/DVdbIBAAAAAQAAALoAAAA="
      }, {
        "id": "octet-string",
        "tag": "OCTET_STRING",
        "value": "MDEyMzQ1Njc4OQ=="
      }, {
        "id": "null",
        "tag": "NULL"
      },
      {
        "id": "oid-12345",
        "tag": "OID",
        "value": "1.2.3.4.5"
      }, {
        "id": "printable-string",
        "tag": "PRINTABLE_STRING",
        "value": "The quick brown fox jumps over the lazy dog"
      }, {
        "id": "utf8-string",
        "tag": "UTF8_STRING",
        "value": "Спритна бура лисиця стрибає через ледачого собаку"
      }, {
        "id": "ia5-string",
        "tag": "IA5_STRING",
        "value": "The quick brown fox jumps over the lazy dog"
      }, {
        "id": "utc-time-as-unixtime",
        "tag": "UTC_TIME",
        "integer": 1625747696000
      }, {
        "id": "utc-time-as-text",
        "tag": "UTC_TIME",
        "value": "2021-07-08 12:34:56"
      }, {
        "id": "generalized-time-as-unixtime",
        "tag": "GENERALIZED_TIME",
        "integer": 1625747696000
      }, {
        "id": "generalized-time-as-text",
        "tag": "GENERALIZED_TIME",
        "value": "2021-07-08 12:34:56"
      }
    ]
  }
}
```

### Response example

```
{
  "errorCode": 0,
  "method": "ASN1_ENCODE",
  "result": {
    "encoded": [
      { "id": "boolean-FALSE", "bytes": "AQEA" },
      { "id": "boolean-TRUE", "bytes": "AQH/" },
      { "id": "integer-1-as-integer", "bytes": "AgEB" },
      { "id": "integer-2-as-value", "bytes": "AgEC" },
      { "id": "integer-big", "bytes": "AhQ9tz578NV1sgEAAAABAAAAugAAAA==" },
      { "id": "octet-string", "bytes": "BAowMTIzNDU2Nzg5" },
      { "id": "null", "bytes": "BQA=" },
      { "id": "oid-12345", "bytes": "BgQqAwQF" },
      { "id": "printable-string", "bytes": "EytUaGUgcXVpY2sgYnJvd24gZm94IGp1bXBzIG92ZXIgdGhlIGxhenkgZG9n" },
      { "id": "utf8-string", "bytes": "DFzQodC/0YDQuNGC0L3QsCDQsdGD0YDQsCDQu9C40YHQuNGG0Y8g0YHRgtGA0LjQsdCw0ZQg0YfQtdGA0LXQtyDQu9C10LTQsNGH0L7Qs9C+INGB0L7QsdCw0LrRgw==" },
      { "id": "ia5-string", "bytes": "FitUaGUgcXVpY2sgYnJvd24gZm94IGp1bXBzIG92ZXIgdGhlIGxhenkgZG9n" },
      { "id": "utc-time-as-unixtime", "bytes": "Fw0yMTA3MDgxMjM0NTZa" },
      { "id": "utc-time-as-text", "bytes": "Fw0yMTA3MDgxMjM0NTZa" },
      { "id": "generalized-time-as-unixtime", "bytes": "GA8yMDIxMDcwODEyMzQ1Nlo=" },
      { "id": "generalized-time-as-text", "bytes": "GA8yMDIxMDcwODEyMzQ1Nlo=" }
    ]
  }
}
```

# Appendix A. Error codes

Table A.1. Error codes

| **Code**                           | **Value**    | **Description**                                                                                                                                                                             |
| ---------------------------------- | ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `RET_OK`                           | 0            | Operation completed successfully                                                                                                                                                          |
| `RET_UAPKI_GENERAL_ERROR`          | 0x1001       | Undefined error                                                                                                                                                                           |
| `RET_UAPKI_CONNECTION_ERROR`       | 0x1002       | Server connection error                                                                                                                                                                   |
| `RET_UAPKI_INVALID_JSON_FORMAT`    | 0x1003       | Invalid JSON request format                                                                                                                                                               |
| `RET_UAPKI_INVALID_METHOD`         | 0x1004       | Method does not exist                                                                                                                                                                     |
| `RET_UAPKI_INVALID_PARAMETER`      | 0x1005       | Invalid parameter                                                                                                                                                                         |
| `RET_UAPKI_UNKNOWN_PROVIDER`       | 0x1006       | Unknown provider                                                                                                                                                                          |
| `RET_UAPKI_FILENAME_REQUIRED`      | 0x1007       | A file name is required as the storage identifier                                                                                                                                         |
| `RET_UAPKI_LOGIN_REQUIRED`         | 0x1008       | A user name is required                                                                                                                                                                   |
| `RET_UAPKI_NOT_INITIALIZED`        | 0x1009       | Library not initialized                                                                                                                                                                   |
| `RET_UAPKI_ALREADY_INITIALIZED`    | 0x100A       | Library already initialized                                                                                                                                                               |
| `RET_UAPKI_NO_STORAGE`             | 0x100B       | Storage not opened                                                                                                                                                                        |
| `RET_UAPKI_KEY_NOT_SELECTED`       | 0x100C       | Key not selected                                                                                                                                                                          |
| `RET_UAPKI_INVALID_KEY_USAGE`      | 0x100D       | The key cannot be used for the operation according to<br>its intended purpose                                                                                                             |
| `RET_UAPKI_UNSUPPORTED_ALG`        | 0x100E       | Cryptographic primitive not supported                                                                                                                                                     |
| `RET_UAPKI_INVALID_HASH_SIZE`      | 0x100F       | Invalid hash value size                                                                                                                                                                   |
| `RET_UAPKI_INVALID_KEY_ID`         | 0x1010       | Invalid key identifier                                                                                                                                                                    |
| `RET_UAPKI_JSON_FAILURE`           | 0x1011       | JSON subsystem error                                                                                                                                                                      |
| `RET_UAPKI_INVALID_BIT_STRING`     | 0x1012       | ASN.1 error                                                                                                                                                                               |
| `RET_UAPKI_UNEXPECTED_BIT_STRING`  | 0x1013       | ASN.1 error                                                                                                                                                                               |
| `RET_UAPKI_TOO_LONG_BIT_STRING`    | 0x1014       | ASN.1 error                                                                                                                                                                               |
| `RET_UAPKI_TIME_ERROR`             | 0x1015       | Invalid time                                                                                                                                                                              |
| `RET_UAPKI_NOT_SUPPORTED`          | 0x1016       | Not supported                                                                                                                                                                             |
| `RET_UAPKI_NOT_ALLOWED`            | 0x1017       | Not allowed                                                                                                                                                                               |
| `RET_UAPKI_OFFLINE_MODE`           | 0x1018       | An attempt to perform an operation for which there is not<br>enough information (access to trust-service online resources<br>is required) while offline mode is enabled. For example,<br>current CRLs are missing |
| `RET_UAPKI_STORAGE_NOT_OPEN`       | 0x1019       | Storage not opened                                                                                                                                                                        |
| `RET_UAPKI_PROVIDER_NOT_LOADED`    | 0x101A       | Storage library not loaded                                                                                                                                                                |
| `RET_UAPKI_UNSUPPORTED_CMAPI`      | 0x101B       | The storage library does not support this operation                                                                                                                                      |
| `RET_UAPKI_STORAGE_ALREADY_OPENED` | 0x101C       | Storage already opened                                                                                                                                                                    |
| `RET_UAPKI_INVALID_SESSION`        | 0x101D       | Invalid session handle (uapki_session_process)                                                                                                                                           |
| `RET_UAPKI_INVALID_SHARED_MEMORY`  | 0x101E       | Invalid shared memory handle (uapki_session_process, uapki_session_shared_memory_process)                                                                                               |
| `RET_UAPKI_FILE_OPEN_ERROR`        | 0x1020       | File open error                                                                                                                                                                           |
| `RET_UAPKI_FILE_READ_ERROR`        | 0x1021       | File read error                                                                                                                                                                           |
| `RET_UAPKI_FILE_WRITE_ERROR`       | 0x1022       | File write error                                                                                                                                                                          |
| `RET_UAPKI_FILE_GET_SIZE_ERROR`    | 0x1023       | Error determining file size                                                                                                                                                               |
| `RET_UAPKI_FILE_DELETE_ERROR`      | 0x1024       | File delete error                                                                                                                                                                         |
| `RET_UAPKI_HTTP_STATUS_NOT_OK`     | 0x1025       | Server response not successful                                                                                                                                                            |
| `RET_UAPKI_INVALID_CONTENT_INFO`   | 0x1030       | Invalid signature or encrypted data structure                                                                                                                                             |
| `RET_UAPKI_INVALID_STRUCT`         | 0x1031       | Invalid (or unsupported) ASN.1 structure                                                                                                                                                  |
| `RET_UAPKI_INVALID_STRUCT_VERSION` | 0x1032       | Invalid (or unsupported) ASN.1 structure<br>version number                                                                                                                                |
| `RET_UAPKI_CONTENT_NOT_PRESENT`                  | 0x1033 | No data for signature verification                 |
| `RET_UAPKI_INVALID_ATTRIBUTE`                    | 0x1034 | Invalid signature attributes                       |
| `RET_UAPKI_ATTRIBUTE_NOT_PRESENT`                | 0x1035 | Signature attributes missing                       |
| `RET_UAPKI_EXTENSION_NOT_PRESENT`                | 0x1036 | Required extensions missing                        |
| `RET_UAPKI_EXTENSION_NOT_SET_CRITICAL`     | 0x1037 | Missing extensions not marked as critical          |
| `RET_UAPKI_INVALID_COUNT_ITEMS`                  | 0x1038 | Invalid number of items                            |
| `RET_UAPKI_INVALID_DIGEST`                       | 0x1039 | Invalid digest                                     |
| `RET_UAPKI_OTHER_RECIPIENT`                      | 0x103A | File encrypted for a different recipient           |
| `RET_UAPKI_INDEX_OUT_OF_RANGE`                   | 0x103B | Index out of range                                 |
| `RET_UAPKI_INVALID_CONTENT_TYPE`                 | 0x103C | Invalid content type                               |
| `RET_UAPKI_CERT_STORE_LOAD_ERROR`                | 0x1040 | Certificate cache load error                       |
| `RET_UAPKI_CERT_NOT_FOUND`                       | 0x1041 | Certificate not found                              |
| `RET_UAPKI_CERT_VALIDITY_NOT_BEFORE_ERROR` | 0x1042 | Certificate validity period has not started yet    |
| `RET_UAPKI_CERT_VALIDITY_NOT_AFTER_ERROR`  | 0x1043 | Certificate validity period has expired            |
| `RET_UAPKI_CERT_ISSUER_NOT_FOUND`                | 0x1044 | Issuer certificate not found                       |
| `RET_UAPKI_CERT_STATUS_REVOKED`                  | 0x1045 | Certificate revoked                                |
| `RET_UAPKI_CERT_STATUS_UNKNOWN`                  | 0x1046 | Certificate status undetermined                    |
| `RET_UAPKI_CERT_NOT_TRUSTED`                     | 0x1047 | Certificate is not trusted                         |
| `RET_UAPKI_CERT_CHAIN_NOT_FOUND`                 | 0x1048 | Certificate chain not built                        |
| `RET_UAPKI_CRL_STORE_LOAD_ERROR`                 | 0x1050 | CRL cache load error                               |
| `RET_UAPKI_CRL_URL_NOT_PRESENT`                  | 0x1051 | CRL distribution point missing                     |
| `RET_UAPKI_CRL_NOT_DOWNLOADED`                   | 0x1052 | CRL download error                                 |
| `RET_UAPKI_CRL_NOT_FOUND`                        | 0x1053 | CRL not found                                      |
| `RET_UAPKI_CRL_EXPIRED`                          | 0x1054 | CRL validity period has expired                    |
| `RET_UAPKI_OCSP_URL_NOT_PRESENT`                 | 0x1060 | OCSP access point missing                          |
| `RET_UAPKI_OCSP_NOT_RESPONDING`                  | 0x1061 | OCSP server not responding                         |
| `RET_UAPKI_OCSP_RESPONSE_NOT_SUCCESSFUL`   | 0x1062 | OCSP response not successful                       |
| `RET_UAPKI_OCSP_RESPONSE_VERIFY_FAILED`    | 0x1063 | Invalid OCSP response signature                    |
| `RET_UAPKI_OCSP_RESPONSE_VERIFY_ERROR`     | 0x1064 | Error while validating the OCSP response signature |
| `RET_UAPKI_OCSP_RESPONSE_INVALID_NONCE`    | 0x1065 | The nonce fields of the OCSP response and request do not match |
| `RET_UAPKI_OCSP_RESPONSE_INVALID`                | 0x1066 | OCSP response structure is invalid                 |
| `RET_UAPKI_TSP_URL_NOT_PRESENT`                  | 0x1070 | TSP server access point not specified              |
| `RET_UAPKI_TSP_NOT_RESPONDING`                   | 0x1071 | TSP server not responding                          |
| `RET_UAPKI_TSP_RESPONSE_NOT_GRANTED`       | 0x1072 | Timestamp not granted                              |
| `RET_UAPKI_TSP_RESPONSE_NOT_EQUAL_REQUEST` | 0x1073 | TSP response does not match the request            |
| `RET_UAPKI_TSP_RESPONSE_INVALID`                 | 0x1074 | TSP response structure is invalid                  |
| `RET_UAPKI_TRUST_LIST_INVALID`                   | 0x1078 | The trusted list does not conform to the format    |
| `RET_UAPKI_TRUST_LIST_VERIFY_FAILED`             | 0x1079 | Invalid signature of the trusted list              |
| `RET_UAPKI_TRUST_LIST_SIGNER_NOT_TRUSTED`        | 0x107A | The certificate that signs the trusted list is not trusted for that |
| `RET_UAPKI_TRUST_LIST_OBSOLETE`                  | 0x107B | A trusted list with a greater sequence number is accepted |
| `RET_UAPKI_CERT_TRUSTED_NOT_REMOVABLE`          | 0x107C | A certificate trusted at the initialization is not removed |

Table A.2. Storage error codes

| **Code**                                           | **Value**    | **Description**                                           |
| -------------------------------------------------- | ------------ | -------------------------------------------------------- |
| `RET_OK`                                           | 0            | Operation completed successfully                          |
| `RET_CM_GENERAL_ERROR`                             | 0x0401       | Undefined storage provider error                          |
| `RET_CM_INVALID_PARAMETER`                         | 0x0402       | Invalid parameter                                         |
| `RET_CM_LIBRARY_NOT_LOADED`                        | 0x0403       | Storage provider load error                               |
| `RET_CM_ALREADY_INITIALIZED`                       | 0x0404       | Storage provider already initialized                      |
| `RET_CM_NOT_INITIALIZED`                           | 0x0405       | Storage provider not initialized                          |
| `RET_CM_UNSUPPORTED_API`                           | 0x0406       | Function not supported by the storage provider            |
| `RET_CM_UNSUPPORTED_PARAMETER`                     | 0x0407       | Parameter not supported by the storage provider           |
| `RET_CM_NO_SESSION`                                | 0x0408       | Storage session not opened                                |
| `RET_CM_INVALID_MECHANISM`                         | 0x0409       | Invalid cryptographic primitive<br>identifier             |
| `RET_CM_UNSUPPORTED_MAC`                           | 0x040A       | Unsupported MAC calculation algorithm                     |
| `RET_CM_INVALID_MAC`                               | 0x040B       | Invalid MAC                                               |
| `RET_CM_WITHOUT_MAC`                               | 0x040C       | MAC missing                                               |
| `RET_CM_INVALID_CONTENT_INFO`                      | 0x040D       | Invalid signature or encrypted data structure             |
| `RET_CM_UNSUPPORTED_CONTENT_INFO`                  | 0x040E       | Invalid (or unsupported) ASN.1 structure                  |
| `RET_CM_INVALID_SAFE_BAG`                          | 0x040F       | Invalid structure of encrypted data or keys               |
| `RET_CM_NOT_AUTHORIZED`                            | 0x0410       | User not authorized                                       |
| `RET_CM_INVALID_PASSWORD`                          | 0x0411       | Invalid password                                          |
| `RET_CM_READONLY_SESSION`                          | 0x0412       | Storage opened read-only                                  |
| `RET_CM_BAG_NOT_FOUND`                             | 0x0413       | Invalid ASN.1 structure                                   |
| `RET_CM_KEY_NOT_FOUND`                             | 0x0414       | Key not found on the storage                              |
| `RET_CM_CERTIFICATE_NOT_FOUND`                     | 0x0415       | Certificate not found on the storage                      |
| `RET_CM_KEY_NOT_SELECTED`                          | 0x0416       | Current key not selected                                  |
| `RET_CM_UNSUPPORTED_ALG`                           | 0x0417       | Cryptographic primitive not supported                     |
| `RET_CM_UNSUPPORTED_CIPHER_ALG`                    | 0x0418       | Encryption algorithm not supported                        |
| `RET_CM_UNSUPPORTED_ELLIPTIC_CURVE`                | 0x0419       | Elliptic curve not supported                              |
| `RET_CM_UNSUPPORTED_RSA_LEN`                       | 0x041A       | RSA key length not supported                              |
| `RET_CM_UNSUPPORTED_KEY_DERIVATION_FUNC_ALG` | 0x041B       | Key derivation function not supported                     |
| `RET_CM_INVALID_HASH`                              | 0x041C       | Invalid hash value                                        |
| `RET_CM_INVALID_KEY`                               | 0x041D       | Invalid key                                               |
| `RET_CM_INVALID_ELLIPTIC_CURVE`                    | 0x041E       | Invalid elliptic curve                                    |
| `RET_CM_INVALID_UTF8_STR`                          | 0x041F       | Invalid UTF8 string                                       |
| `RET_CM_INVALID_JSON`                              | 0x0420       | Invalid JSON format                                       |
| `RET_CM_INVALID_PARAM_DH`                          | 0x0421       | Invalid key agreement protocol parameters                 |
| `RET_CM_UNSUPPORTED_KEY_CONTAINER`                 | 0x0422       | Unsupported key format                                    |
| `RET_CM_UNSUPPORTED_FORMAT`                        | 0x0423       | Unsupported format                                        |
| `RET_CM_CONNECTION_ERROR`                          | 0x0424       | Connection error                                          |
| `RET_CM_INVALID_RESPONSE`                          | 0x0425       | Invalid response                                          |
| `RET_CM_RESPONSE_ERROR`                            | 0x0426       | Invalid response                                          |
| `RET_CM_ACCESS_DENIED`                             | 0x0427       | Access denied                                             |
| `RET_CM_JSON_FAILURE`                              | 0x0428       | JSON subsystem error                                      |
| `RET_CM_STORAGE_NOT_OPEN`                          | 0x0429       | No storage is open                                        |
| `RET_CM_TOKEN_ERROR`                               | 0x042A       | Hardware storage error                                    |
| `RET_CM_TOKEN_NO_FREE_SESSIONS` | 0x042B | Hardware storage is busy                    |
| `RET_CM_TOKEN_NO_FREE_SPACE`    | 0x042C | No free space on the hardware storage       |
| `RET_CM_TOKEN_ALREADY_LOGGED`   | 0x042D | User already authenticated                  |
| `RET_CM_TOKEN_RESERVED`         | 0x042E | Hardware storage is reserved                |
| `RET_CM_STORAGE_NOT_FOUND`      | 0x042F | Storage not found                           |
| `RET_CM_FILE_OPEN_ERROR`        | 0x0430 | File open error                             |
| `RET_CM_FILE_READ_ERROR`        | 0x0431 | File read error                             |
| `RET_CM_FILE_WRITE_ERROR`       | 0x0432 | File write error                            |
| `RET_CM_FILE_DELETE_ERROR`      | 0x0433 | File delete error                           |
| `RET_CM_DECODE_ASN1_ERROR`      | 0x0434 | ASN.1 decoding error                        |
| `RET_CM_ENCODE_ASN1_ERROR`      | 0x0435 | ASN.1 DER-encoding error                    |
| `RET_CM_PASSWORD_NOT_SET`       | 0x0436 | Password not set                            |
| `RET_CM_INVALID_CERTIFICATE`    | 0x0437 | Invalid certificate                         |
| `RET_CM_INVALID_KEYID`          | 0x0438 | Invalid key identifier                      |
| `RET_CM_INVALID_WRAPPED_KEY`    | 0x0439 | Invalid or corrupted wrapped key            |

# Appendix B. Signature formats

Table B.1. Signature formats supported by the library

| **Format name**           | **Short description**                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `RAW`                    | The raw output data sequence of the digital signature. Has a specific binary format for each<br>digital signature algorithm.                                                                                                                                                                                                                                                                                                                                                                |
| `CMS`                    | Basic signature format with signer identification by the public key<br>identifier.<br>Has two mandatory signed attributes:<br>1) contentType;<br>2) messageDigest.                                                                                                                                                                                                                                                                                                                          |
| `CAdES-BES`              | Basic signature format with signer identification by the identifier of the<br>signer's certificate.<br>Has three mandatory signed attributes:<br>1) contentType;<br>2) messageDigest;<br>3) signingCertificateV2.                                                                                                                                                                                                                                                                          |
| `CAdES-T`                | A signature format that is an extended variant of the CAdES-BES format with two<br>additional attributes: a timestamp on the data (contentTimestamp) and a<br>timestamp on the signature (timeStampToken).<br>Has 4 mandatory signed attributes:<br>1) contentType;<br>2) messageDigest;<br>3) signingCertificateV2;<br>4) contentTimestamp.<br>Has one mandatory unsigned attribute:<br>1) timeStampToken.                                                                                 |
| `CAdES-C`                | A signature format that is an extended variant of the CAdES-T format with two<br>additional unsigned attributes: certificateRefs and revocationRefs.<br>The list of 4 mandatory signed attributes is the same as CAdES-T.<br>Has three mandatory unsigned attributes:<br>1) timeStampToken;<br>2) certificateRefs;<br>3) revocationRefs.<br>Only CRLs are used to check certificate status; accordingly, the<br>revocationRefs attribute contains references to the CRLs used.              |
| `CAdES-XL`               | A signature format that is an extended variant of the CAdES-C format with two<br>additional unsigned attributes: certValues and revocationValues.<br>The list of 4 mandatory signed attributes is the same as CAdES-T.<br>Has 5 mandatory unsigned attributes:<br>1) timeStampToken;<br>2) certificateRefs;<br>3) revocationRefs;<br>4) certValues;<br>5) revocationValues.                                                                                                                 |
| `CAdES-A`                | A signature format that is an extended variant of the CAdES-XL format with one<br>additional unsigned attribute — the archive timestamp<br>archiveTimestampV3 whose token has the ats-hash-index-v3 attribute<br>(ETSI EN 319 122-1, 5.5.2, 5.5.3; earlier versions of the library added<br>ats-hash-index or no index to the token).<br>The list of 4 mandatory signed attributes is the same as CAdES-T.<br>Has 6 mandatory unsigned attributes:<br>1) timeStampToken;<br>2) certificateRefs;<br>3) revocationRefs;<br>4) certValues;<br>5) revocationValues;<br>6) archiveTimestampV3.                                                            |
| `CAdES-B-LT`             | The baseline format of the B-LT level of ETSI EN 319 122-1: CAdES-T with the signingTime attribute,<br>all the certificates used for the validation (including the trusted root) are in<br>SignedData.certificates, and the CRLs and OCSP responses (RFC 5940) are in SignedData.crls.<br>There are no certificateRefs, revocationRefs, certValues and revocationValues attributes. |
| `CAdES-B-LTA`            | The baseline format of the B-LTA level of ETSI EN 319 122-1: CAdES-B-LT with an archive time-stamp<br>archive-time-stamp-v3 whose token has the ats-hash-index-v3 attribute (5.5.2, 5.5.3). |

The CMS/CAdES family of formats allows the use of optional attributes. For example, the signingTime attribute is used among the signed attributes. Depending on the task, non-standard attributes may be used (within the CMS/CAdES standard).

For compatibility the SIGN and BUILD_CMS_2PASS methods accept the names "CAdES-LT" and "CAdES-LTA" as synonyms of "CAdES-XL" and "CAdES-A" respectively. These are not the B-LT and B-LTA levels of the baseline signatures of ETSI EN 319 122-1: those keep the validation data in SignedData and have no reference and value attributes. If the signature format is not specified (empty string), "CAdES-BES" is used by default.

# Appendix C. Certificate extensions

Table C.1. Certificate extensions that can be decoded in CERT_INFO

| **Extension name**            | **OID**              | **Short description**                                   |
| ---------------------------- | -------------------- | ------------------------------------------------------- |
| `authorityInfoAccess`        | `1.3.6.1.5.5.7.1.1`  | Information about issuer resources                      |
| `authorityKeyIdentifier`     | `2.5.29.35`          | Key identifier of the certificate<br>issuer             |
| `basicConstraints`           | `2.5.29.19`          | Basic constraints                                       |
| `cRLDistributionPoints`      | `2.5.29.31`          | References to the storage addresses<br>of full CRL files |
| `certificatePolicies`        | `2.5.29.32`          | Certificate policies                                    |
| `extKeyUsage`                | `2.5.29.37`          | Extended key usage                                      |
| `freshestCRL`                | `2.5.29.46`          | References to the storage addresses<br>of delta CRL files |
| `issuerAltName`              | `2.5.29.18`          | Issuer alternative name                                 |
| `keyUsage`                   | `2.5.29.15`          | Key usage                                               |
| `ocspNoCheck`                | `1.3.6.1.5.5.7.48.1.5` | ocsp-no-check indicator                               |
| `qcStatements`               | `1.3.6.1.5.5.7.1.3`  | Qualified certificate profiles                          |
| `subjectAltName`             | `2.5.29.17`          | Subject alternative name                                |
| `subjectDirectoryAttributes` | `2.5.29.9`           | Additional signer attributes                            |
| `subjectInfoAccess`          | `1.3.6.1.5.5.7.1.11` | Information about resources available<br>to the certificate holder |
| `subjectKeyIdentifier`       | `2.5.29.14`          | Key identifier of the certificate<br>holder             |

Table C.2. KEY_USAGE extension values

| **Field name**    | **Type** | **Description**                                              |
| ----------------- | ------- | ------------------------------------------------------------- |
| digitalSignature  | Boolean | Optional, default false                                       |
| contentCommitment | Boolean | Synonym of nonRepudiation.<br>Optional, default false         |
| keyEncipherment   | Boolean | Optional, default false                                       |
| dataEncipherment  | Boolean | Optional, default false                                       |
| keyAgreement      | Boolean | Optional, default false                                       |
| keyCertSign       | Boolean | Optional, default false                                       |
| crlSign           | Boolean | Optional, default false                                       |
| encipherOnly      | Boolean | Optional, default false                                       |
| decipherOnly      | Boolean | Optional, default false                                       |

# Appendix D. ASN1 types

Table D.1. ASN1 types supported by the ASN1_DECODE and ASN1_ENCODE methods

| **ASN1 type name**  | **Short description**                                               |
| ------------------- | ------------------------------------------------------------------- |
| `BOOLEAN`           | Boolean value                                                       |
| `INTEGER`           | Integer                                                             |
| `BIT_STRING`        | Bit sequence (ASN1_DECODE only)                                     |
| `OCTET_STRING`      | Arbitrary byte (octet) sequence                                     |
| `NULL`              | Absent value                                                        |
| `OID`               | Object identifier                                                   |
| `ENUMERATED`        | Enumerated type (ASN1_DECODE only)                                  |
| `PRINTABLE_STRING`  | Text encoded in the printable subset of ASCII                       |
| `UTF8_STRING`       | Text in UTF-8 encoding                                              |
| `IA5_STRING`        | Text in IA-5 encoding (first part of the ASCII table)               |
| `BMP_STRING`        | Text in UCS-2 encoding (ASN1_DECODE only)                           |
| `UTC_TIME`          | Coordinated Universal Time without century (year given as 2 digits) |
| `GENERALIZED_TIME`  | Coordinated Universal Time with century (year given as 4 digits)    |

Types marked "ASN1_DECODE only" are supported only during decoding; the ASN1_ENCODE method does not encode them.

# Appendix E. Certificate description elements

Table E.1. Certificate description elements in the RDNAME_INFO structure \*

| **Name**       | **OID**    | **Distinguished name** |
| -------------- | ---------- | ---------------------- |
| `C`            | `2.5.4.6`  | country                |
| `CN`           | `2.5.4.3`  | commonName             |
| `G`            | `2.5.4.42` | givenName              |
| `L`            | `2.5.4.7`  | locality               |
| `O`            | `2.5.4.10` | organization           |
| `OI`           | `2.5.4.97` | organizationIdentifier |
| `OU`           | `2.5.4.11` | organizationalUnit     |
| `S`            | `2.5.4.8`  | state                  |
| `SERIALNUMBER` | `2.5.4.5`  | serialNumber           |
| `SN`           | `2.5.4.4`  | surname                |
| `STREET`       | `2.5.4.9`  | streetAddress          |
| `TITLE`        | `2.5.4.12` | title                  |

- if a certificate description element is unknown (not present in the table), the OID value is used instead of the name.
