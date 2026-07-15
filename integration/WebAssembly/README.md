# UAPKI · WebAssembly (браузер)

Використання бібліотеки UAPKI, зібраної у WebAssembly, з JavaScript у
браузері: підписання CAdES, перевірка підпису, робота з контейнерами ключів
(PKCS#12/PFX, JKS, PKCS#8, ІІТ key-6.dat), сертифікатами, гешування,
шифрування/розшифрування CMS EnvelopedData — повністю на стороні клієнта,
ключ і пароль не покидають машину користувача.

Збірка модуля описана в `library/wasm/README.md`; після збірки тут
з'являються `uapki.js` + `uapki.wasm`. Готовий модуль також публікує
GitHub Actions workflow `wasm-build` (artifact `uapki-wasm`).

WASM-модуль експонує той самий **JSON-протокол** (`process`/`json_free`),
що й нативна бібліотека — див. `doc/UAPKI-PM-*.pdf` і приклади задач у
`library/test/data/*.json`.

## JSON-консоль (`console.html`)

Універсальний інструмент для тестування протоколу і вивчення API — довільний
запит до `process()` без написання коду. Файли треба віддавати по HTTP
(через `file://` браузер не завантажить .wasm):

```sh
python -m http.server 8000 --directory integration/WebAssembly
# відкрити http://localhost:8000/console.html
```

Можливості:

- **пресети** всіх основних методів (VERSION, INIT, OPEN, KEYS, SELECT_KEY,
  ADD_CERT, SIGN, VERIFY, ENCRYPT, DECRYPT, DIGEST, …) з коректними OID;
- **сценарії** — той самий формат `{"tasks":[…]}`, що у тестових файлах
  `library/test/data/*.json`: підтримуються `skip`, `comment`,
  `actionByError: "STOP"|"CLOSE"` та `//`-коментарі;
- **підстановки між кроками**: у будь-якому рядковому значенні
  `{{METHOD:шлях.до.поля}}` замінюється на значення з результату
  попереднього кроку, наприклад `{"id": "{{KEYS:keys.0.id}}"}` або
  `{"bytes": "{{SIGN:signatures.0.bytes}}"}`;
- **панель MEMFS**: завантаження файлів контейнерів у `/storage/`,
  вставка шляху/base64 у запит, збереження результатів у файл;
- історія запитів, Ctrl+Enter для виконання.

Швидкий старт: завантажте контейнер на панелі «Файли», оберіть сценарій
«Зчитати ключ» або «Підписати і перевірити», виправте `storage`/`password`,
Ctrl+Enter.

## JSON-протокол із JavaScript

`process()` може призупинятись на мережевих запитах (Asyncify + `fetch`),
тому викликається асинхронно (`cwrap` з `{ async: true }` повертає Promise):

```js
const module = await createUapkiModule();
const proc = module.cwrap("process", "number", ["number"], { async: true });

async function uapki(method, parameters) {
    const req = module.stringToNewUTF8(JSON.stringify({ method, parameters }));
    const resPtr = await proc(req);
    const res = JSON.parse(module.UTF8ToString(resPtr));
    module._free(req);
    module._json_free(resPtr);
    if (res.errorCode !== 0) throw new Error(`${method}: ${res.error} (${res.errorCode})`);
    return res.result;
}

//  мінімальний цикл підпису
module.FS.mkdir("/storage");
module.FS.writeFile("/storage/key.p12", keyFileBytes /* Uint8Array */);

await uapki("INIT", {
    cmProviders: { dir: "", allowedProviders: [{ lib: "cm-pkcs12" }] },
    certCache: { path: "/certs/", trustedCerts: [] },
    crlCache: { path: "/crls/" },
    offline: true    //  false вмикає TSP/OCSP/CRL через fetch (потрібен CORS)
});
await uapki("OPEN", { provider: "PKCS12", storage: "/storage/key.p12", password: "…", mode: "RO" });
const { keys } = await uapki("KEYS");
await uapki("SELECT_KEY", { id: keys[0].id });
const { signatures } = await uapki("SIGN", {
    signParams: { signatureFormat: "CAdES-BES", detachedData: false, includeCert: true, includeTime: true },
    options: { ignoreCertStatus: true },
    dataTbs: [{ id: "doc-0", bytes: btoa("data to sign") }]
});
//  signatures[0].bytes — base64 CMS-підпису (.p7s)
const verified = await uapki("VERIFY", { signature: { bytes: signatures[0].bytes } });
await uapki("CLOSE");
```

Мережевий режим (`offline: false`): TSP/OCSP/CRL-запити йдуть через браузерний
`fetch()`, тож цільові сервери мають дозволяти CORS (для публічних TSP без
CORS — reverse-proxy на своєму домені; свій URL вмикається через
`tsp: { url: "…", forced: true }`). Деталі та інші обмеження платформи
(MEMFS, статичний cm-pkcs12) — див. `library/wasm/README.md`.

Повний перелік методів і параметрів — у `doc/UAPKI-PM-*.pdf`; робочі приклади
запитів для кожного методу — у `library/test/data/*.json` (їх можна вставляти
в консоль без змін).

## Тестування (`test-node.mjs`)

Модуль призначений **тільки для браузера**; для серверного Node.js існує
нативний N-API-аддон — див. `integration/Node.js`.

Смок-тест `test-node.mjs` використовує Node лише як тестову обв'язку
(байти `.wasm` передаються через `Module.wasmBinary`, тож браузерному
завантажувачу не потрібні Node-гілки). Він проганяє протокол наскрізь на
тестових даних репозиторію: DIGEST з відомим геш-значенням, відкриття
JKS-контейнера (включно з негативним кейсом невірного пароля), повний цикл
підпису/перевірки CAdES-BES на ключі ДСТУ-4145:

```sh
node integration/WebAssembly/test-node.mjs            # використовує uapki.js поруч
node integration/WebAssembly/test-node.mjs build-wasm/wasm/uapki.js
```

Цей самий тест виконується в CI (workflow `wasm-build`) після кожної збірки.
