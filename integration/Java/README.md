# UAPKI for Java

Java integration of the UAPKI crypto library (PKI with support of Ukrainian and international cryptographic
standards). It is a port of the .NET integration (`integration/Net`): the same methods, models, error messages
and behaviour, in Java style.

- Package `com.specinfosystems.uapki`, Maven coordinates `com.specinfosystems:uapki:3.0.0`
- Java 17 or later
- Dependencies: [JNA](https://github.com/java-native-access/jna) 5.17.0, [Gson](https://github.com/google/gson) 2.14.0
- The native library `uapki` 3.0 or later (and `uapkic`, `uapkif`, the key storage providers such as `cm-pkcs12`)
  is **not** included in the jar, see [Native libraries](#native-libraries)

## Build

```sh
./gradlew build            # jar, sources and javadoc jars, tests
./gradlew publish -Pmaven_repo=<url> -PrepoUsername=<user> -PrepoPassword=<password>
```

The tests that call the native library need the environment variables `UAPKI_CM_PROVIDERS` (directory with
`cm-pkcs12`) and `UAPKI_TEST_DATA` (`library/test/data`); without them these tests are skipped. The test data is
not modified (the certificates and the key storage are copied into a temporary directory):

```sh
UAPKI_CM_PROVIDERS=/path/to/build/lib UAPKI_TEST_DATA=../../library/test/data \
    ./gradlew test -Djna.library.path=/path/to/build/lib
```

## Usage

Since 3.0 `Uapki` is an instance class: every instance is a separate library session with its own state
(initialization, opened key storage, selected key). Sessions can be used in parallel from different threads.

```java
import com.specinfosystems.uapki.*;

Config config = new Config()
        .setCmProviders(new CmProvidersParams()
                .setDir("/opt/uapki/lib/")      // the library appends the file name: keep the trailing separator
                .setAllowedProviders(List.of(new CmProviderParams("cm-pkcs12"))))
        .setCertCache(new CertCacheParams().setPath("/var/lib/app/certs/"))
        .setCrlCache(new CrlCacheParams().setPath("/var/lib/app/crls/"));

try (Uapki uapki = new Uapki()) {                // uapki_session_create, freed by close()
    uapki.init(config);
    uapki.openKeyStorage("key.p12", password, KeyStorageOpenMode.RO);
    uapki.selectKey(uapki.getOpenedKeyStorage().storage().keys().get(0));
    List<byte[]> signatures = uapki.sign(List.of(data), SignAlgo.DSTU4145_GOST34311, SignatureFormat.CADES_BES, false);

    ValidationResult result = uapki.verify(signatures.get(0), null);
    boolean valid = result.signatureInfos().get(0).validSignatures();

    uapki.closeKeyStorage();
    uapki.deinit();
}
```

The configuration can also be passed as JSON (`uapki.init("{\"cmProviders\":{...}}")`), and any request can be sent
as is with `uapki.process("{\"method\":\"VERSION\"}")`.

Errors are reported by the unchecked `UapkiException`; `getErrorCode()` returns the error code of the library
(0 for errors of the integration itself).

### Sessions

| Instance | Native API | `close()` |
|---|---|---|
| `Uapki.global()` | `process` - the global library instance, as in 2.x | does nothing |
| `new Uapki()` | `uapki_session_create` / `uapki_session_process` | `uapki_session_free` |
| `Uapki.createSharedMemory()` | `uapki_session_shared_memory_create` | `uapki_session_shared_memory_free` |
| `new Uapki(sharedMemory)` | a session that uses the shared memory | `uapki_session_free` |

- A session and a shared memory must be closed with `close()` (try-with-resources). If they are not, they are
  released by a `java.lang.ref.Cleaner` after garbage collection, but do not rely on it.
- `close()` called from another thread waits until the call in progress is finished; calls after `close()` throw
  `UapkiException` ("Помилка. Сесію звільнено" / "Помилка. Спільну пам'ять звільнено").
- The state getters `getUapkiInfo()`, `getOpenedKeyStorage()`, `getSelectedKey()` belong to the instance and are
  not synchronized: do not call the methods that change the state (`init`, `openKeyStorage`, `selectKey`, ...) of
  one instance concurrently from different threads. Use a session per thread (or per task) instead.

### Shared memory

The certificate and CRL caches can be shared by several sessions:

```java
try (Uapki shared = Uapki.createSharedMemory()) {   // only the cache methods are allowed
    shared.init(new Config().setCertCache(new CertCacheParams().setPath(certDir)).setCrlCache(new CrlCacheParams().setPath(crlDir)));
    try (Uapki session = new Uapki(shared)) {
        session.init(sessionConfig);                 // the session sees the shared certificates and CRLs
        ...
    }
}
```

Methods that are not allowed for the shared memory (key storages, signing, ...) fail with the error code `0x1017`.
The shared memory does not load the key storage providers (`getUapkiInfo().providers()` is empty).
`new Uapki(x)` throws `IllegalArgumentException` if `x` is not a shared memory. Close the sessions before the shared
memory: a session whose shared memory is closed rejects calls.

### Global instance

`Uapki.global()` is the global library instance (the `process` function), as in 2.x. It is never freed and works
with older native libraries too.

## Native libraries

The native libraries are loaded from the filesystem by JNA with the library name `uapki` (`uapki.dll`,
`libuapki.so`, `libuapki.dylib`). JNA searches:

1. the system property `jna.library.path` (e.g. `java -Djna.library.path=/opt/uapki/lib ...`);
2. the system paths: `PATH` on Windows, `LD_LIBRARY_PATH` and the linker configuration on Linux,
   `DYLD_LIBRARY_PATH` on macOS.

`uapki` depends on `uapkic` and `uapkif`: keep them in the same directory (on Linux they must also be found by the
dynamic linker, e.g. via RPATH or `LD_LIBRARY_PATH`). The key storage providers
(`cm-pkcs12`, `cm-pkcs11`, ...) are loaded by `uapki` from the directory given in the INIT configuration
(`cmProviders.dir`), not by JNA.

On Windows make sure that an older `uapki.dll` (for example from `C:\Program Files\UAPKI`) on `PATH` does not
shadow the one you want: set `jna.library.path`, and check `Uapki.global().getVersion()`.

Sessions require the native library uapki 3.0 or later. With an older library `new Uapki()` and
`Uapki.createSharedMemory()` throw `UapkiException` ("Помилка. Бібліотека uapki не підтримує сесії (потрібна
версія 3.0 або новіша)"), while `Uapki.global()` keeps working.

Java 22+ prints a warning about restricted native access by JNA; add `--enable-native-access=ALL-UNNAMED`
to the JVM options to avoid it.

## API

The methods mirror the .NET integration one-to-one (`Init` -> `init`, `GetCertInfo` -> `getCertInfo`, `Do` ->
`process`, ...); optional C# parameters are provided as overloads. Enum constants are in upper snake case
(`SignAlgo.DSTU4145_GOST34311`, `SignatureFormat.CADES_BES`) with `oid()` and `fromOid(...)`; display names
come from the resource bundle `UapkiResources` (Ukrainian by default, English for the `en` locale). Results are
records or immutable classes with record-style accessors (`cert.subject().cn()`); request parameters are
classes with chainable setters. Times are returned as `java.time.Instant` (UTC).

Main methods: `init`, `deinit`, `getVersion`, `getKeyStorages`, `openKeyStorage`, `openKeyStorageCmd`,
`closeKeyStorage`, `changePassword`, `updateKeysInOpenedStorage`, `selectKey`, `selectKeyByCert`, `selectKeyCmd`,
`deleteKey`, `generateKey`, `getCertInfo`, `getCertsShortInfoList`, `getCerts`, `getCert`, `removeCert`,
`importCerts`, `importCert`, `importCertBundle`, `verifyCert`, `getCertByOcsp`, `getCrlInfo`, `importCrl`,
`removeCrl`, `getAllCrls`, `getCsr`, `verifyCsr`, `getDigest`, `getFileDigest`, `getRandomBytes`, `encrypt`,
`decrypt`, `modifyCms`, `sign`, `signFiles`, `verify`, `process` and the static `cmp`/`cmpAsync` (certificates
from the CMP servers of a CA by key identifiers).

## Migration from the old API (com.sit.uapki)

The old integration (`com.sit.uapki`, Java 1.7, one class per method in `com.sit.uapki.method`) is replaced
entirely; it is not source compatible.

| Old (`com.sit.uapki`) | New (`com.specinfosystems.uapki`) |
|---|---|
| `new Library()` - loaded the natives extracted from the jar resources, global state | `new Uapki()` (session, `close()` it) or `Uapki.global()`; the natives come from the filesystem (`jna.library.path`, `PATH`, `LD_LIBRARY_PATH`) |
| Maven `com.sit:uapki` | `com.specinfosystems:uapki:3.0.0` |
| `lib.init(Init.Parameters)` | `uapki.init(Config)` or `uapki.init(String json)`; cm providers directory in `cmProviders.dir` |
| `lib.version()`, `getName()` | `uapki.getVersion()` |
| `lib.getProviders()` | `uapki.getUapkiInfo().providers()` |
| `lib.getStorages(providerId)` | `uapki.getKeyStorages()` |
| `lib.openStorage(providerId, storageId, password, mode, ...)` | `uapki.openKeyStorage(KeyStorage, password, mode[, loginParams, openParams])`, `uapki.openKeyStorage(fileName, password, mode)` for PKCS#12 files |
| `lib.closeStorage()` | `uapki.closeKeyStorage()` |
| `lib.getKeys()` | `uapki.getOpenedKeyStorage().storage().keys()` (loaded on open), `updateKeysInOpenedStorage()` |
| `lib.selectKey(KeyId)` | `uapki.selectKey(Key)` / `selectKey(String keyId)`; `getSelectedKey()` |
| `lib.createKey(...)`, `deleteKey(KeyId)` | `uapki.generateKey(...)`, `deleteKey(Key)` |
| `lib.changePassword(password, newPassword)` | `uapki.changePassword(newPassword)` (storage opened for writing) |
| `lib.sign(Sign.Parameters)` returning `Document`s | `uapki.sign(List<byte[]>, SignAlgo, SignatureFormat, detached, ...)` returning `byte[]` signatures; `signFiles(...)` |
| `lib.verify(PkiData[, content])` | `uapki.verify(byte[] signature, byte[] content)`, `verify(String file)` |
| `PkiData`, `PkiOid`, `PkiTime`, ... wrappers | `byte[]`, `String` OIDs and enums with `oid()`, `java.time.Instant` |
| checked `com.sit.uapki.UapkiException` | unchecked `com.specinfosystems.uapki.UapkiException` with `getErrorCode()` |
| `lib.processJson(request)` | `uapki.process(request)` |
| `initKeyUsage(...)` | no equivalent (not in the .NET integration); send the request with `process(...)` |

## License

BSD 2-Clause, see [LICENSE](../../LICENSE).
