# UAPKI · WebAssembly (браузер)

Використання бібліотеки UAPKI, зібраної у WebAssembly, з JavaScript у
браузері: підписання CAdES, перевірка підпису, робота з контейнерами ключів
(PKCS#12/PFX, JKS, PKCS#8, ІІТ key-6.dat), сертифікатами, гешування,
шифрування/розшифрування CMS EnvelopedData — повністю на стороні клієнта,
ключ і пароль не покидають машину користувача.

Збірка модуля описана в `library/wasm/README.md`; після збірки `uapki.mjs` +
`uapki.wasm` з'являються в `sdk/`. Готовий модуль також публікує
GitHub Actions workflow `wasm-build` (artifact `uapki-wasm`).

WASM-модуль експонує той самий **JSON-протокол** (`process`/`json_free`),
що й нативна бібліотека — див. `doc/UAPKI-PM-*.pdf` і приклади задач у
`library/test/data/*.json`.

## Що тут є

| | |
|---|---|
| `sdk/` | Тонка ES-обгортка над протоколом (`index.mjs`, типи `index.d.ts`) і домівка зібраного модуля. Рекомендований спосіб інтеграції. |
| `INTEGRATION.md` | **Інструкція з інтеграції у веб-застосунок**: React, Vue, Angular, vanilla, складальники, CSP, мережа, діагностика. |
| `examples/` | Готові приклади: `vanilla.html` (зокрема міст до неESM-коду), `react-useUapki.jsx`, `vue-useUapki.js`, `angular-uapki.service.ts`. |
| `console.html` | JSON-консоль: довільний запит до `process()` без написання коду. |
| `test-node.mjs` | Смок-тест протоколу (виконується в CI). |

## Швидкий старт

Пакета в npm немає: скопіюйте файли модуля (`sdk/`) у свій проєкт — з асета
релізу `uapki-vX.Y.Z-wasm.zip` або з власної збірки.

```js
import { createUapki, toBase64 } from './lib/uapki/index.mjs';

//  звичайний імпорт: ні <script>-тегів, ні глобальних змінних
const uapki = await createUapki({ wasmUrl: '/uapki.wasm' });

//  об'єкт запиту -> об'єкт відповіді { errorCode, method, result?, error? }
const version = await uapki.process({ method: 'VERSION' });
```

Контейнер ключа відкривається з пам'яті (`storage: "file://memory"` +
`openParams.bytes`), усі дані — base64, файлова система не потрібна.
Повний цикл підпису/перевірки і решта деталей — в **`INTEGRATION.md`**.

## JSON-консоль (`console.html`)

Універсальний інструмент для тестування протоколу і вивчення API — довільний
запит до `process()` без написання коду (сама консоль побудована на тому ж
`sdk/index.mjs`). Файли треба віддавати по HTTP (через `file://` браузер не
завантажить .wasm):

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

Консоль лишає доступними обидва режими протоколу: файловий (`/storage/…`
у MEMFS — зручніше для ручних експериментів) і той, що використовують
застосунки (`file://memory` + base64, пресет «OPEN (з пам'яті)»).

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

Тест ходить через `sdk/index.mjs` — ту саму точку входу, що й застосунки,
тож зламана обгортка так само валить збірку.

```sh
node integration/WebAssembly/test-node.mjs            # модуль із sdk/
node integration/WebAssembly/test-node.mjs build-wasm/wasm/uapki.mjs
```

Цей самий тест виконується в CI (workflow `wasm-build`) після кожної збірки.
