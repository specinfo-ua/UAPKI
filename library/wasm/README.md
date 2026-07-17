# uapki-wasm — збірка UAPKI у WebAssembly

Ціль збірки, що компілює бібліотеку UAPKI у WebAssembly-модуль для
веб-браузера (платформа `wasm`). Використання модуля, JSON-протокол і
консоль для тестування — див. `integration/WebAssembly/`.

## Склад

| Файл | Призначення |
|---|---|
| `CMakeLists.txt` | Лінкує `uapki` + `cm-pkcs12` у `uapki.mjs`/`uapki.wasm` |
| `main-wasm.c` | Порожня точка входу (модуль керується з JavaScript) |
| `pre.js` | Джерело ентропії: `Module.getRandomValue()` через Web Crypto |
| `build-wasm.ps1` / `build-wasm.sh` | Збірка через Docker (образ `emscripten/emsdk`) |

## Особливості платформи wasm

- **Завантажувач — ES-модуль** (`-sEXPORT_ES6`): `uapki.mjs` експортує фабрику
  модуля дефолтним експортом, тож інтегратор просто імпортує його
  (`import createUapkiModule from "./uapki.mjs"`) — без `<script>`-тегів і
  глобальних змінних, і складальники обробляють його як звичайний модуль.
  Наслідок: підключати модуль класичним `<script src>` або в класичному
  Web Worker (`importScripts`) не можна — потрібен `type="module"`.
- **CM-провайдер `cm-pkcs12` лінкується статично** — динамічне завантаження
  бібліотек у WASM недоступне (див. `common/loaders/cm-loader.cpp`,
  гілки `__EMSCRIPTEN__`). Провайдер `cm-pkcs11` не збирається.
- **HTTP через браузерний `fetch()`**: libcurl не збирається — `HttpHelper`
  (`common/pkix/http-helper.cpp`, гілка `__EMSCRIPTEN__`) виконує TSP/OCSP/CRL
  запити через `fetch()`. Бібліотека чекає синхронних відповідей, тому збірка
  використовує **Asyncify** (`-sASYNCIFY`): WASM-стек призупиняється на час
  очікування Promise. Наслідок для інтеграторів: `process()` треба викликати
  асинхронно — `Module.cwrap("process", …, { async: true })` — і чекати
  результат через `await` (SDK робить це за вас).
  **Обмеження CORS**: браузер дозволить запит лише якщо TSP/OCSP/CRL-сервер
  віддає CORS-заголовки; інакше запит блокується, і це не відрізнити від
  недоступного сервера — назовні буде `TSP_NOT_RESPONDING` (4209),
  `OCSP_NOT_RESPONDING` (4193) чи `CRL_NOT_DOWNLOADED` (4178). Публічні українські
  TSP-сервери CORS зазвичай не дозволяють, тож для CAdES-T у продакшні
  потрібен reverse-proxy на своєму домені. Без мережі (`"offline": true`)
  доступний CAdES-BES з `options.ignoreCertStatus: true`.
  Порада: TSP-URL із сертифіката підписувача має пріоритет над конфігом;
  щоб використати свій (проксі-)URL — `tsp: { url: "…", forced: true }`.
- **Файли не обов'язкові**: контейнер відкривається просто з пам'яті — `OPEN`
  зі `storage: "file://memory"` і байтами в `openParams.bytes` (base64), а
  порожній `path` у `certCache`/`crlCache` вимикає роботу з ФС. Саме так
  працює SDK. Альтернатива — віртуальна ФС Emscripten (MEMFS): записати файл
  у `/storage/key.p12` і передати цей шлях у `OPEN`; MEMFS живе в межах сесії
  сторінки (зручно для ручних експериментів у JSON-консолі).
- **Ентропія** — `uapkic/src/entropy.c` у гілці `__EMSCRIPTEN__` тягне
  випадкові байти з `Module.getRandomValue()` (реалізовано в `pre.js` через
  `crypto.getRandomValues`).
- `hostapp` і `test` для цієї платформи не збираються.

## Збірка

Компіляція завжди виконується інструментарієм Emscripten (Linux); скрипти
`build-wasm.ps1`/`build-wasm.sh` — лише обгортки, що запускають її в
Docker-образі `emscripten/emsdk`. Способи на вибір:

**Docker (Windows):**

```powershell
powershell -File library\wasm\build-wasm.ps1
```

**Docker (Linux/macOS):**

```sh
sh library/wasm/build-wasm.sh
```

**Локальний emsdk ≥ 3.1.x, без Docker (будь-яка ОС):**

```sh
emcmake cmake -S library -B build-wasm \
    -DCMAKE_BUILD_TYPE=MinSizeRel \
    -DUAPKI_LIBS_TYPE=STATIC \
    -DUAPKI_CM_PKCS12_LIB_TYPE=STATIC \
    -DUAPKI_DISABLE_COPY=ON
cmake --build build-wasm -j
```

**GitHub Actions:** workflow `.github/workflows/wasm-build.yml` збирає модуль
у контейнері `emscripten/emsdk` на кожен push/PR, що зачіпає `library/**` або
`integration/WebAssembly/**` (а також вручну через `workflow_dispatch`),
проганяє smoke-тест (`integration/WebAssembly/test-node.mjs`) і публікує
`uapki.mjs`/`uapki.wasm` як artifact `uapki-wasm` (зберігається до 90 днів).

**Реліз:** коли в репозиторії публікується реліз (тег `vX.Y.Z`), workflow
збирає модуль із тегнутих джерел і прикріплює до релізу асет
`uapki-vX.Y.Z-wasm.zip` — поруч із нативними платформними архівами. Склад
архіву повторює `integration/WebAssembly/`: `sdk/` (обгортка + зібраний
модуль), `console.html`, `README.md`, `INTEGRATION.md`, `LICENSE`, тож його
достатньо роздати по HTTP і відкрити консоль.

Модуль збирається **тільки для браузера** (`-sENVIRONMENT=web,worker`) —
для роботи з Node.js призначений нативний N-API-аддон `integration/Node.js`.
Smoke-тест виконується в Node лише як тестова обв'язка: він передає байти
`.wasm` через `Module.wasmBinary`, не потребуючи Node-гілок у завантажувачі.

## Результат

`uapki.mjs` (ES-модуль-завантажувач, згенерований Emscripten) + `uapki.wasm`
(скомпільований код). Після збірки копіюються у:

- `library/out/wasm/` — платформний вихідний каталог (як `out/windows-amd64`,
  `out/linux-…` для нативних збірок);
- `integration/WebAssembly/sdk/` — єдина «домівка» модуля для інтеграторів:
  SDK імпортує `./uapki.mjs` поруч із собою, а JSON-консоль і приклади
  працюють через SDK.
