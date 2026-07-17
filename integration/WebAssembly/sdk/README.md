# UAPKI · WebAssembly SDK

UAPKI (Ukrainian & international PKI crypto: DSTU-4145, ECDSA, RSA, CAdES,
PKCS#12/JKS containers, …) compiled to WebAssembly, with a **thin ES-module
wrapper over the library's JSON protocol** for browsers.

The SDK does **not** invent a high-level API. You send a request **object** and
get the response **object** back — exactly the protocol described in the
programmer's manual (`doc/UAPKI-PM-*.pdf`). The SDK only removes the
infrastructure friction: loading the module, the async bridge, string
marshalling, memory freeing. No filesystem — everything is base64.

## Install

**Not published to the npm registry** — the module is distributed as files:
take the `sdk/` folder from the release asset `uapki-vX.Y.Z-wasm.zip`, or build
it yourself (`library/wasm/README.md`). It holds `index.mjs` (the wrapper),
`index.d.ts` (types) and the built module `uapki.mjs` + `uapki.wasm`.

Copy it into your project and import by path:

```js
import { createUapki } from './lib/uapki/index.mjs';
```

If you'd rather manage it as a dependency, install the folder locally — that is
what `package.json` here is for:

```sh
npm i ./vendor/uapki-wasm      # then: import … from '@uapki/wasm'
```

`../INTEGRATION.md` walks through the whole setup (React, Vue, Angular,
bundlers, CSP, troubleshooting).

## Quick start

```js
import { createUapki, toBase64, fromBase64 } from './lib/uapki/index.mjs';

// The loader is a plain ES module — no <script> tag, no globals. Only
// uapki.wasm needs a URL once your bundler moves things around (see below).
const uapki = await createUapki();

// object in -> object out. Response is { errorCode, method, result?, error? }.
const version = await uapki.process({ method: 'VERSION' });
console.log(version.result);   // { name: 'UAPKI', version: '2.0.16', ... }
```

Full sign + verify cycle (no filesystem, keys and data are base64):

```js
await uapki.process({
    method: 'INIT',
    parameters: {
        cmProviders: { dir: '', allowedProviders: [{ lib: 'cm-pkcs12' }] },
        certCache: { path: '', trustedCerts: [] },   // empty path = no filesystem
        crlCache: { path: '' },
        offline: true                                 // browser HTTP via fetch when false
    }
});

// Open a key container FROM MEMORY: storage is the literal "file://memory",
// and the container bytes go into openParams.bytes (base64). This is the
// protocol's in-memory mode — the only place a magic value is needed.
const open = await uapki.process({
    method: 'OPEN',
    parameters: {
        provider: 'PKCS12',
        storage: 'file://memory',
        password: '…',
        mode: 'RO',
        openParams: { bytes: toBase64(keyFileBytes) }   // Uint8Array|ArrayBuffer|File(.arrayBuffer())
    }
});
if (open.errorCode !== 0) throw new Error(open.error);

const keys = (await uapki.process({ method: 'KEYS' })).result.keys;
await uapki.process({ method: 'SELECT_KEY', parameters: { id: keys[0].id } });

const signed = await uapki.process({
    method: 'SIGN',
    parameters: {
        signParams: { signatureFormat: 'CAdES-BES', detachedData: false, includeCert: true },
        options: { ignoreCertStatus: true },
        dataTbs: [{ id: 'doc-0', bytes: toBase64('data to sign') }]
    }
});
const p7s = signed.result.signatures[0].bytes;   // base64 CMS signature (.p7s)

const verified = await uapki.process({ method: 'VERIFY', parameters: { signature: { bytes: p7s } } });
verified.result.signatureInfos[0].status;         // "TOTAL-VALID"

await uapki.process({ method: 'CLOSE' });
await uapki.process({ method: 'DEINIT' });
```

All other methods (`DIGEST`, `ENCRYPT`, `DECRYPT`, `ADD_CERT`, `CERT_INFO`,
`ASN1_ENCODE`, …) take their payloads as inline base64 — no special handling.
Robust request/response examples for every method are the JSON task files in
`library/test/data/*.json`.

## API

| Export | Signature | |
|---|---|---|
| `createUapki(options?)` | `Promise<Uapki>` | Loads the module and returns an instance. |
| `uapki.process(request)` | `Promise<response>` | One request object → full response object. |
| `uapki.module` | `EmscriptenModule` | Escape hatch to the raw module (rarely needed). |
| `toBase64(data)` | `string` | `Uint8Array \| ArrayBuffer \| TypedArray \| string` → base64. |
| `fromBase64(str)` | `Uint8Array` | base64 → bytes. |
| `UapkiError` | class | Thrown on loader/argument errors (not protocol errors). |

`createUapki(options)`:

- `wasmUrl` — URL of `uapki.wasm`. Default: resolved relative to the loader.
- `wasmBinary` — raw `.wasm` bytes (`Uint8Array`/`ArrayBuffer`), when you load
  the file yourself (Node, bundler asset import).
- `moduleFactory` — an already loaded Emscripten factory, to bypass importing
  `./uapki.mjs` (custom loading scheme).
- `locateFile` — custom Emscripten asset locator (overrides `wasmUrl`).

`process()` returns the response verbatim — **it never throws on protocol
errors**; check `response.errorCode` yourself, as the manual describes. Calls
must be serialized: the library keeps global state (init / open storage /
selected key).

## Loading in bundlers (Vite / webpack / Next)

The JS side needs nothing: `uapki.mjs` is a normal ES module, so bundlers
handle it like any dependency. Only `uapki.wasm` is a runtime asset — the
loader looks for it next to itself, which breaks once the bundler moves chunks
around. The simplest, bundler-agnostic setup:

1. Copy `uapki.wasm` into your app's `public/` folder (served at the site root)
   and keep the `.mjs` files with your sources.
2. Point the SDK at it:
   ```js
   import { createUapki } from './lib/uapki/index.mjs';
   const uapki = await createUapki({ wasmUrl: '/uapki.wasm' });
   ```

Alternatively import the `.wasm` as an asset and pass `{ wasmBinary }`.

The module is browser-only (`web`,`worker`): with SSR (Next, Nuxt) call
`createUapki()` on the client only. In a Web Worker, use a module worker
(`new Worker(url, { type: 'module' })`) — the loader is ESM.

## Frameworks

Ready-to-copy adapters live in `../examples/`, and `../INTEGRATION.md` is the
full web-integration guide (frameworks, bundlers, CSP, network/CORS,
troubleshooting):

- **React** — `react-useUapki.jsx`: a `useUapki()` hook (`{ uapki, ready, error }`)
  plus a `<SignDemo/>` component.
- **Vue 3** — `vue-useUapki.js`: a `useUapki()` composable returning refs.
- **Angular** — `angular-uapki.service.ts`: a lazily loaded singleton service.
- **Vanilla** — `vanilla.html`: no bundler. Shows the bridge to non-ESM code:
  a `<script type="module">` loads the SDK and hands the page a promise, while
  all the usage code stays a plain `<script>`.

## Node.js

The same module runs in Node (as a test/CI harness; for production server use
prefer the native N-API addon in `integration/Node.js`). The browser-only build
has no Node file loading, so inject the wasm bytes:

```js
import { readFileSync } from 'node:fs';
import { createUapki } from './lib/uapki/index.mjs';
if (!globalThis.crypto) globalThis.crypto = (await import('node:crypto')).webcrypto;

const wasmPath = new URL('./lib/uapki/uapki.wasm', import.meta.url);
const uapki = await createUapki({ wasmBinary: readFileSync(wasmPath) });
```

See `../test-node.mjs` for a working example.

## Notes

- The module is built for the browser (`web`,`worker`); network methods
  (TSP/OCSP/CRL) go through `fetch()` and require the target servers to allow
  CORS. In `offline: true` mode nothing is fetched (CAdES-BES).
- See `library/wasm/README.md` for the build and platform details.
