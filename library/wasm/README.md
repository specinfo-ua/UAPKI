# uapki-wasm — збірка UAPKI у WebAssembly

Ціль збірки, що компілює бібліотеку UAPKI у WebAssembly-модуль для
веб-браузера (платформа `wasm`). Використання модуля, JSON-протокол і
консоль для тестування — див. `integration/WebAssembly/`.

## Склад

| Файл | Призначення |
|---|---|
| `CMakeLists.txt` | Лінкує `uapki` + `cm-pkcs12` у `uapki.js`/`uapki.wasm` |
| `main-wasm.c` | Порожня точка входу (модуль керується з JavaScript) |
| `pre.js` | Джерело ентропії: `Module.getRandomValue()` через Web Crypto |
| `build-wasm.ps1` / `build-wasm.sh` | Збірка через Docker (образ `emscripten/emsdk`) |

## Особливості платформи wasm

- **CM-провайдер `cm-pkcs12` лінкується статично** — динамічне завантаження
  бібліотек у WASM недоступне (див. `common/loaders/cm-loader.cpp`,
  гілки `__EMSCRIPTEN__`). Провайдер `cm-pkcs11` не збирається.
- **HTTP через браузерний `fetch()`**: libcurl не збирається — `HttpHelper`
  (`common/pkix/http-helper.cpp`, гілка `__EMSCRIPTEN__`) виконує TSP/OCSP/CRL
  запити через `fetch()`. Бібліотека чекає синхронних відповідей, тому збірка
  використовує **Asyncify** (`-sASYNCIFY`): WASM-стек призупиняється на час
  очікування Promise. Наслідок для інтеграторів: `process()` треба викликати
  асинхронно — `Module.cwrap("process", …, { async: true })` — і чекати
  результат через `await`.
  **Обмеження CORS**: браузер дозволить запит лише якщо TSP/OCSP/CRL-сервер
  віддає CORS-заголовки; інакше — `CONNECTION_ERROR`. Публічні українські
  TSP-сервери CORS зазвичай не дозволяють, тож для CAdES-T у продакшні
  потрібен reverse-proxy на своєму домені. Без мережі (`"offline": true`)
  доступний CAdES-BES з `options.ignoreCertStatus: true`.
  Порада: TSP-URL із сертифіката підписувача має пріоритет над конфігом;
  щоб використати свій (проксі-)URL — `tsp: { url: "…", forced: true }`.
- **Файли** — у віртуальній файловій системі Emscripten (MEMFS): файл
  контейнера записується у MEMFS (наприклад, `/storage/key.p12`), і цей шлях
  передається методу `OPEN`. MEMFS живе в межах сесії сторінки.
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
`uapki.js`/`uapki.wasm` як artifact `uapki-wasm` (зберігається до 90 днів).

**Реліз:** коли в репозиторії публікується реліз (тег `vX.Y.Z`), workflow
збирає модуль із тегнутих джерел і прикріплює до релізу асет
`uapki-vX.Y.Z-wasm.zip` (uapki.js, uapki.wasm, console.html, README, LICENSE) —
поруч із нативними платформними архівами.

Модуль збирається **тільки для браузера** (`-sENVIRONMENT=web,worker`) —
для роботи з Node.js призначений нативний N-API-аддон `integration/Node.js`.
Smoke-тест виконується в Node лише як тестова обв'язка: він передає байти
`.wasm` через `Module.wasmBinary`, не потребуючи Node-гілок у завантажувачі.

## Результат

`uapki.js` (JS-завантажувач, згенерований Emscripten) + `uapki.wasm`
(скомпільований код). Після збірки копіюються у:

- `library/out/wasm/` — платформний вихідний каталог (як `out/windows-amd64`,
  `out/linux-…` для нативних збірок);
- `integration/WebAssembly/` — поруч із JSON-консоллю для тестування.
