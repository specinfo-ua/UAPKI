The UAPKI is crypto library for using in PKI with support of Ukrainian and internationlal cryptographic standards

## Usage

Since 3.0 `Uapki` is an instance class: every instance is a separate library session with its own
state (initialization, opened key storage, selected key). Sessions can be used in parallel from
different threads.

```csharp
using var uapki = new Uapki();           // uapki_session_create, freed by Dispose
uapki.Init(config);
uapki.OpenKeyStorage("key.p12", password, Uapki.KeyStorageOpenMode.RO);
uapki.SelectKey(uapki.OpenedKeyStorage!.Storage.Keys![0]);
var signatures = uapki.Sign(datas, Uapki.SignAlgo.Dstu4145_Gost34311, Uapki.SignatureFormat.CAdES_BES, false);
```

Certificate and CRL caches can be shared by several sessions:

```csharp
using var shared = Uapki.CreateSharedMemory();   // only the cache methods are allowed
shared.Init(cachesConfig);
using var session = new Uapki(shared);
```

`Uapki.Global` is the global library instance (the `process` function), as in 2.x; it is never freed.

Sessions require the native uapki library 3.0 or later; with an older library `new Uapki()` throws
`UapkiException`, while `Uapki.Global` keeps working.

### Migration from 2.x

The static methods became instance methods: replace `Uapki.Method(...)` with
`Uapki.Global.Method(...)`, or create a session. The state properties (`UapkiInfo`, `OpenedKeyStorage`,
`SelectedKey`) belong to the instance and are not synchronized between threads.
