# UAPKI. Programmer's Manual

Languages: [Українська](UAPKI-PM-2.0.16.md) | **English**

| | |
| ------------------- | ---------- |
| Library version     | 2.0.16     |
| Document revision   | 2          |
| Revision date       | 2026-07-16 |

The version number in the document title corresponds to the version of the uapki library it describes (`project(uapki VERSION ...)` in `library/uapki/CMakeLists.txt`; returned by the VERSION method). The document revision is incremented when the description is edited without a change of the library version.

## Change history

| Revision | Date       | Changes                                                                                                                                                          |
| ------- | ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1       | —          | Initial version of the document (PDF)                                                                                                                               |
| 2       | 2026-07-16 | Conversion to Markdown. Verification against the library code v2.0.16: documented missing request/response fields and error codes, corrected field names and types, extended Appendices B, C, D. English version of the document added |

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

Interaction with the library is performed by calling the methods listed in Table 2. Methods are invoked via two exported library functions: process and json_free, whose interface is described in Table 3. All interaction with the library methods is based on the use of a text string composed according to JSON rules (hereinafter — JSON string).

The library supports multithreading, i.e. the ability to call methods simultaneously in parallel from different threads. Due to implementation specifics of the library, methods are divided into three types of multithreading support (the multithreading support type is specified in Table 2):

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
| 21    | VERIFY              | Verify signed data                          | MT      |
| 22    | ENCRYPT             | Encrypt data                                   | MT      |
| 23    | DECRYPT             | Decrypt data                                 | MT      |
| 24    | ADD_CERT            | Add a certificate to the certificate cache             | MT      |
| 25    | CERT_INFO           | Certificate information                          | MT      |
| 26    | GET_CERT            | Get a certificate from the certificate cache           | MT      |
| 27    | LIST_CERTS          | List of certificates in the certificate cache           | MT      |
| 28    | REMOVE_CERT         | Remove a certificate from the certificate cache          | ST      |
| 29    | VERIFY_CERT         | Certificate validation                              | MT      |
| 30    | GENERATE_CERTBUNDLE | Generate a certificate bundle                      | IND      |
| 31    | CERT_STATUS_BY_OCSP | Create an OCSP request and get an OCSP response | MT      |
| 32    | ADD_CRL             | Add a CRL to the CRL cache                             | MT      |
| 33    | CRL_INFO            | CRL information                                | MT      |
| 34    | LIST_CRLS           | List of CRLs in the CRL cache                          | MT      |
| 35    | REMOVE_CRL          | Remove outdated CRLs from the CRL cache                 | ST      |
| 36    | RANDOM_BYTES        | Generate a pseudorandom sequence           | MT      |
| 37    | DIGEST              | Data hashing                                    | IND      |
| 38    | ASN1_DECODE         | Decode DER-encoded ASN.1 data              | IND      |
| 39    | ASN1_ENCODE         | Encode data according to ASN.1 DER encoding         | IND      |

Table 3. List of exported library functions

| **№** | **Function name** | **Short description**                   |
| ----- | ---------------- | ----------------------------------- |
| 1     | process          | char* process(const char* request); |
| 2     | json_free        | void json_free(char\* buf);         |

### Function process

The function is intended for calling a library method, passing parameters to it, and obtaining the result of its execution.

### Input parameters

request — a pointer to a null-terminated JSON string in UTF8 encoding that defines the method being called and its parameters (method name, method parameters).

### Output parameters

returns a pointer to a null-terminated JSON string in UTF8 encoding containing the result of the method execution. The memory referenced by this pointer must always be released after processing using the json_free function.

### Function json_free

The function is intended for releasing the memory allocated by the process function for returning the result of a library method execution.

### Input parameters

the buf parameter is a pointer to a null-terminated JSON string in UTF8 encoding that was returned by the process function;

Output parameters:

none.

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
    "version": "2.0.16",
    "uapkicVersion": "2.0.2",
    "uapkifVersion": "2.0.2"
  }
}
```

## INIT method

The method is intended for initializing the library. Input parameters are optional. The output parameters return the current status/parameter values of the library subsystems. If the library has been initialized, the DEINIT method must be executed before finishing work with it.

If methods that change the internal state of the library (i.e. of type ST and MT) are used, library initialization is mandatory. Methods that do not change the internal state of the library are of type IND, for example: VERSION and DIGEST.

Library parameters can be set in two ways: via parameters or via a configuration file. The parameters and the configuration file have the same structure. If a configuration file is used, its path must be specified in the "configFile" field (recommended name "uapki-config.json").

If the library parameters are not set, the default parameters will be used. To work with storages, the storage provider parameters must be set.

Starting from version 2.0.16, the INIT method (by default) performs a self-test. The self-test can be canceled by setting the skipSelfTest parameter to true. The duration of the self-test depends on system performance.

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
| offline         | Boolean                      | "Offline" operation mode. Optional                     |
| ocsp            | Object<br>OCSP_PARAMS        | OCSP service parameters. Optional                    |
| proxy           | Object<br>PROXY_PARAMS       | PROXY service parameters. Optional                   |
| skipSelfTest    | Boolean                      | Skip the self-test. Optional                 |
| tsp             | Object<br>TSP_PARAMS         | TSP service parameters. Optional                     |
| validationByCrl | Boolean                      | Certificate status verification by CRL.<br>Optional |

### Structure CERT_CACHE_PARAMS

| **Field name** | **Type**  | **Description**                                                                                                                                    |
| -------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| path           | String   | Full path to the directory. Optional. If the path<br>to the directory is not set, only the<br>temporary in-memory certificate cache is used |
| trustedCerts   | Base64[] | Array of trusted certificates. Optional                                                                                                  |

### Structure CRL_CACHE_PARAMS

| **Field name** | **Type** | **Description**                                                                                                                           |
| -------------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| path           | String  | Full path to the directory. Optional. If the path<br>to the directory is not set, only the<br>temporary in-memory CRL cache is used |
| useDeltaCrl    | Boolean | Use delta CRL. Optional,<br>default true                                                                |

### Structure OCSP_PARAMS

| **Field name** | **Type** | **Description**                                                                                                                                                                                                                                               |
| -------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| nonceLen       | Integer | Length of the one-time random number in the OCSP<br>request. Value range: 0, 8..64. If the value<br>equals 0 or is out of range, the<br>random number in the OCSP request is not used.<br>Optional, default is 20 |

### Structure PROXY_PARAMS

| **Field name** | **Type** | **Description**                                                                                                                         |
| -------------- | ------- | -------------------------------------------------------------------------------------------------------------------------------- |
| url            | String  | URL of the PROXY service. If the value is absent<br>or is an empty string, the PROXY service is not<br>used. Optional. |
| credentials    | String  | Authentication parameters for the PROXY service.<br>Optional                                                                       |

### Structure TSP_PARAMS

| **Field name** | **Type** | **Description**                                                                                                                                                                                                                                            |
| -------------- | ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| certReq        | Boolean | Requirement to return the service certificate in the TSP response.<br>Optional, default is false                                                                                                                                                 |
| forced         | Boolean | Requirement to use the TSP service URLs<br>specified in the "url" field, ignoring the addresses specified in the<br>signer's certificate. Optional,<br>default is false                                                               |
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
| countCmProviders | Integer                   | Number of loaded storage providers |
| offline          | Boolean                   | "Offline" operation mode                  |
| ocsp             | Object<br>OCSP_INFO       | Information about the OCSP service parameters  |
| proxy            | Object<br>PROXY_INFO      | Information about the PROXY service parameters |
| tsp              | Object<br>TSP_INFO        | Information about the TSP service parameters   |
| validationByCrl  | Boolean                   | Certificate status verification by CRL |

### Structure CERT_CACHE_INFO

| **Field name**    | **Type** | **Description**                                            |
| ----------------- | ------- | --------------------------------------------------- |
| countTrustedCerts | Integer | Number of trusted certificates in the certificate cache |
| countCerts        | Integer | Total number of certificates in the certificate cache |

### Structure CRL_CACHE_INFO

| **Field name** | **Type** | **Description**                          |
| -------------- | ------- | --------------------------------- |
| countCrls      | Integer | Number of CRLs in the CRL cache          |
| useDeltaCrl    | Boolean | Delta CRL is used    |

### Structure OCSP_INFO

| **Field name** | **Type** | **Description**                                                                                                                                     |
| -------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| nonceLen       | Integer | Length of the one-time random nonce in the OCSP<br>request. If the value equals 0, the random<br>nonce in the OCSP request is not used |

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

Attention! Only one storage can be open at a time, and it is available to all threads.

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

Attention! Only one key can be selected at a time, and it is available to all threads. When another key is selected, it changes for all threads of the application.

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

Signature formats are described in Appendix B. The signature format names "CAdES-LT" and "CAdES-LTA" are synonyms for "CAdES-XL" and "CAdES-A" respectively.

### Structure of the parameters field in the request

| **Field name** | **Type**                       | **Description**                             |
| -------------- | ------------------------------ | ------------------------------------------- |
| signParams     | Object,<br>SIGN_PARAMS         | Set of signature parameters                 |
| dataTbs        | Object[],<br>DATA_TBS_PARAMS[] | Array of structures containing the data to be signed |
| options        | Object,<br>OPTION_PARAMS       | Set of additional parameters. Optional      |

### Structure SIGN_PARAMS

| **Field name**   | **Type** | **Description**                                                                                                         |
| ---------------- | ------- | ----------------------------------------------------------------------------------------------------------------------- |
| signatureFormat  | String  | Signature format:<br>"RAW", "CMS", "CAdES-BES", "CAdES-T", "CAdES-C",<br>"CAdES-XL" ("CAdES-LT"), "CAdES-A" ("CAdES-LTA") |
| signAlgo         | OID     | Signature algorithm identifier. Optional                                                                                |
| digestAlgo       | OID     | Digest algorithm identifier. Optional                                                                                   |
| detachedData     | Boolean | Detached signature (data is not encapsulated).<br>Optional, default true                                                |
| includeCert      | Boolean | Add the key owner's certificate to the signature.<br>Optional, default false                                            |
| includeTime      | Boolean | Add the host time (untrusted) to the signature.<br>Optional, default false                                              |
| includeContentTS | Boolean | Add a content timestamp to the signature.<br>Optional, default false                                                    |
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

The method supports generation of PKCS#7 signatures of the following formats: "CMS", "CAdES-BES", "CAdES-T", "CAdES-XL" and "CAdES-A".

On the first pass, data corresponding to the signedAttributes structure is generated. Additionally, the hash value of this data can be obtained: the digestAlgo parameter must be specified - the result will be in the digestBytes field.

On the second pass, all parameters required for the final generation of the PKCS#7 signature are specified.

To generate a CAdES signature, on the first pass the certId and includeSigningCert (value true) parameters must be specified, and on the second pass the certId and signatureFormat parameters with the corresponding CAdES format value. When a CAdES signature is created with a timestamp, the includeContentTS parameter (value true) must be specified on the first pass, and on the second pass the signatureFormat parameter with one of the values: "CAdES-T", "CAdES-XL" and "CAdES-A".

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
| includeContentTS   | Boolean                         | Add a content timestamp.<br>Optional, defaults to false                                                           |
| signedAttributes   | Object[],<br>ATTRIBUTE_PARAMS[] | Add an array of attributes to be signed.<br>Optional                                                              |

### Structure of STEP2_CMS_PARAMS

| **Field name**     | **Type**                        | **Description**                                                                                        |
| ------------------ | ------------------------------- | ----------------------------------------------------------------------------------------------------- |
| bytes              | Base64                          | Signed attributes (the signedAttributes field)                                                         |
| signatureFormat    | String                          | Signature format:<br>"CMS", "CAdES-BES", "CAdES-T",<br>"CAdES-XL" ("CAdES-LT"), "CAdES-A" ("CAdES-LTA") |
| signAlgo           | OID                             | Signature algorithm identifier                                                                         |
| signAlgoParams     | Base64                          | Signature algorithm parameters. Optional                                                               |
| signBytes          | Base64                          | Signature value of the signed attributes                                                               |
| digestAlgo         | OID                             | Hash algorithm identifier                                                                              |
| digestAlgoParams   | Base64                          | Hash algorithm parameters (DER encoding).<br>Optional                                                  |
| certId             | Base64                          | Certificate identifier in the certificate cache.<br>Optional, only for a CAdES signature               |
| keyId              | Base64                          | Key identifier.<br>Optional, only for a CMS signature                                                  |
| contentBytes       | Base64                          | Content data. Optional                                                                                 |
| includeCert        | Boolean                         | Add the key owner's certificate. Optional                                                              |
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

## VERIFY method

The method is intended for validation of a signature in CMS/CAdES format or in the output format of cryptographic primitives ("RAW"). The description of signature formats is given in Appendix B. The "signature" field is mandatory — the signed data is stored in the "signature.bytes" field

To validate a CMS/CAdES-format signature as a detached signature, the original data is additionally specified in the "signature.content" field. If the CMS/CAdES-format signature has encapsulated data, the "signature.content" field is not used.

The method supports three types of validation of a CMS/CAdES-format signature (the "options.validationType" field): 1) "STRUCT" — validation of the signature structure (default), the signature data structure, the electronic signature of the signed attributes and timestamps (if present) are verified;

2. "CHAIN" — validation of the signature structure and the certificate chain, includes item 1 and building the certificate chain of the signer and of the timestamps (if present), by which the validity of the certificate chain can be verified;

3. "FULL" — full validation of the signature, includes item 2 and validation of the validity of all certificates in the chain at the moment the signature was created.

To simplify the analysis of the signature validation results, the result fields "validSignatures", "validDigests" and "bestSignatureTime" can be used. The "bestSignatureTime" field contains the best trusted signature time (in order of priority: "signingTime", "contentTS.genTime" and "signatureTS.genTime").

When the "CHAIN" or "FULL" validation type is used, the "certificateChain" field stores information about the certificate chain (an array of CERT_CHAIN_INFO records).

If a certificate is missing for validation, the information for finding it is stored in the "expectedCerts" field (an array of EXPECTED_CERT_INFO records).

If a CRL is missing to determine the certificate status, the information for finding it is stored in the "expectedCrls" field (an array of EXPECTED_CRL_INFO records).

The "warnings" field contains warnings about the signature validation result (an array of text strings).

During full signature validation, the following logic is used to determine the certificate status:
| Signature formats        | Description                                                     |
| ------------------------ | --------------------------------------------------------------- |
| "CAdES-BES",             | The OCSP service is used first; if the online status cannot be  |
| "CAdES-T"                | determined, the CRL is used                                     |
| "CAdES-C",               | The CRL is used first; if the CRL cannot be obtained, the       |
| "CAdES-XL",<br>"CAdES-A" | OCSP service is used                                            |

To forbid the use of the OCSP service, the "options.onlyCrl" parameter must be set to true (default — false) or the library must be initialized with the "validationByCrl" parameter set to true. The "options.onlyCrl" parameter has higher priority than the (global) "validationByCrl".

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

### Structure of SIGNER_PUBKEY

| **Field name** | **Type** | **Description**                                                                                                            |
| -------------- | ------- | ------------------------------------------------------------------------------------------------------------------------ |
| certificate    | Base64  | Signer's certificate. Optional                                                                                            |
| certId         | Base64  | Identifier of the signer's certificate. Optional                                                                          |
| spki           | Base64  | Signer's public key with key parameters,<br>a SubjectPublicKeyInfo structure per the “x.509” standard.<br>Optional        |

### Structure of OPTION_PARAMS

| **Field name**        | **Type** | **Description**                                                                                                                                                   |
| --------------------- | ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| validationType        | String  | Signature validation type:<br>"STRUCT", "CHAIN", "FULL".<br>Optional, defaults to "STRUCT"                                                                       |
| verifySignerInfoIndex | Integer | Verify an individual user (the first index<br>equals 0). If the index equals -1, all<br>users are verified.<br>Optional, defaults to -1                          |
| onlyCrl               | Boolean | Use CRLs exclusively. Optional, defaults to<br>false                                                                                                             |

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
| signatureFormat     | String  | CMS/CAdES signature format:<br>"CMS", "CAdES-BES", "CAdES-T", "CAdES-C",<br>"CAdES-XL", "CAdES-A"                        |
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
| archiveTS             | Object<br>TIMESTAMP_INFO          | Archive timestamp. Optional — present<br>if the signed data has the corresponding attribute                                                                                                                           |
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
| encryptionAlgo       | OID     | Encryption algorithm identifier                                                                               |
| encryptionAlgoParams | Base64  | Encryption parameters in DER encoding.<br>Optional, random values are used<br>by default                      |
| dataEncryptionKey    | Base64  | Encryption key value. Optional, random<br>values are used by default                                          |
| type                 | OID     | Data type identifier. Default is<br>"1.2.840.113549.1.7.1" (pkcs7-data)                                       |

### Structure RECIPINFO_PARAMS

| **Field name** | **Type** | **Description**                                                              |
| -------------- | ------- | ---------------------------------------------------------------------------- |
| certId         | Base64  | Recipient certificate identifier                                              |
| kdfAlgo        | OID     | Key derivation function algorithm identifier                                  |
| keyWrapAlgo    | OID     | Key wrap algorithm identifier.<br>Optional, depends on kdfAlgo                |

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

### Structure of the parameters field in the request

| **Field name** | **Type** | **Description**                                                                                                |
| -------------- | ------- | -------------------------------------------------------------------------------------------------------------- |
| bytes          | Base64  | Certificate. Mutually exclusive with the certId field                                                                     |
| certId         | Base64  | Key identifier. Mutually exclusive with the<br>certificate field                                                    |
| validationType | String  | Types of certificate validation by revocation status.<br>Has the following values: "CRL" and "OCSP".<br>Optional |
| validateTime   | Time    | Validation time value. Optional                                                                          |

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

## ADD_CRL method

The method is intended for adding a CRL (certificate revocation list) to the CRL cache. It returns the CRL identifier in the CRL cache. CRLs may be added to the CRL cache permanently (with storage on disk) or temporarily (only for the duration of the current session until DEINIT is executed or the application is restarted). If the permanent CRL cache is not initialized (the path to the corresponding directory was not specified when initializing the library), only temporary addition of CRLs is possible.

The CRL must conform to the x.509 standard.

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

The method is intended for removing a specified CRL (optionally) and obsolete CRLs from the CRL cache. If a CRL identifier is specified in the request, the method first removes the specified CRL, and then all obsolete CRLs. Response parameters: none.

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
| `CAdES-XL`<br>`CAdES-LT` | A signature format that is an extended variant of the CAdES-C format with two<br>additional unsigned attributes: certValues and revocationValues.<br>The list of 4 mandatory signed attributes is the same as CAdES-T.<br>Has 5 mandatory unsigned attributes:<br>1) timeStampToken;<br>2) certificateRefs;<br>3) revocationRefs;<br>4) certValues;<br>5) revocationValues.                                                                                                                 |
| `CAdES-A`<br>`CAdES-LTA` | A signature format that is an extended variant of the CAdES-XL format with one<br>additional unsigned attribute — the archive timestamp<br>archiveTimestampV3.<br>The list of 4 mandatory signed attributes is the same as CAdES-T.<br>Has 6 mandatory unsigned attributes:<br>1) timeStampToken;<br>2) certificateRefs;<br>3) revocationRefs;<br>4) certValues;<br>5) revocationValues;<br>6) archiveTimestampV3.                                                            |

The CMS/CAdES family of formats allows the use of optional attributes. For example, the signingTime attribute is used among the signed attributes. Depending on the task, non-standard attributes may be used (within the CMS/CAdES standard).

The signature format names "CAdES-LT" and "CAdES-LTA" are synonyms of "CAdES-XL" and "CAdES-A" respectively. They can be used only in the SIGN and BUILD_CMS_2PASS methods. If the signature format is not specified (empty string), "CAdES-BES" is used by default.

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
