# Інтеграція UAPKI (WebAssembly) у веб-застосунок

Покрокова інструкція, як під'єднати UAPKI до звичайного веб-застосунку —
Vanilla JS, React, Vue, будь-який складальник. Криптографія виконується
**на стороні клієнта**: ключ і пароль не покидають браузер користувача.

- Збірка модуля — `library/wasm/README.md`.
- JSON-консоль для ручних експериментів із протоколом — `console.html`.
- Опис методів протоколу — `doc/UAPKI-PM-*.pdf`, робочі приклади запитів —
  `library/test/data/*.json`.

## Що таке SDK і навіщо він

Модуль складається з двох файлів: `uapki.mjs` (завантажувач, згенерований
Emscripten) і `uapki.wasm` (сама бібліотека). Працювати з ними напряму
незручно: треба робити `cwrap` з `{async: true}` (модуль зібрано з Asyncify),
копіювати рядки в пам'ять WASM і не забувати звільняти результат через
`json_free`.

`sdk/index.mjs` — тонка ES-обгортка, яка бере на себе **тільки цю
інфраструктуру**. Вона не вигадує власного API поверх протоколу: ви
передаєте об'єкт запиту — отримуєте об'єкт відповіді, точно як у
програмерському мануалі.

```
ваш код  ──process({method, parameters})──►  sdk/index.mjs  ──►  uapki.mjs + uapki.wasm
         ◄──{errorCode, method, result}────
```

## Крок 1. Отримати файли

Пакета в npm-реєстрі **немає** — модуль розповсюджується файлами. Візьміть їх
одним зі способів:

- **реліз**: асет `uapki-vX.Y.Z-wasm.zip` — усередині тека `sdk/` з усім
  потрібним;
- **CI**: артефакт `uapki-wasm` workflow `wasm-build` — `uapki.mjs` +
  `uapki.wasm` (обгортку візьміть з `integration/WebAssembly/sdk/`);
- **самостійна збірка** — `library/wasm/README.md`.

Потрібні чотири файли:

| Файл | Що це |
|---|---|
| `index.mjs` | обгортка (те, що ви імпортуєте) |
| `index.d.ts` | типи для TypeScript |
| `uapki.mjs` | завантажувач, згенерований Emscripten |
| `uapki.wasm` | сама бібліотека (~1.4 МБ) |

## Крок 2. Покласти їх у проєкт

JS-частина — у джерела застосунку, наприклад `src/lib/uapki/`:

```
src/lib/uapki/
  index.mjs
  index.d.ts
  uapki.mjs
```

А `uapki.wasm` — у теку статики (`public/`, `static/`, `assets/` — залежно від
фреймворку), бо це runtime-ресурс, який вантажиться по HTTP:

```
public/
  uapki.wasm
```

`.wasm` має віддаватися з `Content-Type: application/wasm` (усі поширені
сервери роблять це самі). Через `file://` модуль не завантажиться — потрібен
HTTP.

> Якщо зручніше керувати цим як залежністю — покладіть теку з файлами
> (разом із `package.json`, що є в `sdk/`) кудись у репозиторій і поставте
> локально: `npm i ./vendor/uapki-wasm`. Тоді імпорт виглядатиме як
> `from '@uapki/wasm'`. Це та сама тека, лише через резолвер npm.

## Крок 3. Викликати `createUapki()`

Завантажувач — звичайний ES-модуль, тож жодних `<script>`-тегів і глобальних
змінних: обгортка імпортує його сама.

```js
import { createUapki, toBase64, fromBase64 } from './lib/uapki/index.mjs';

//  wasmUrl — бо складальник перенесе JS, а .wasm лишиться в статиці
const uapki = await createUapki({ wasmUrl: '/uapki.wasm' });

const version = await uapki.process({ method: 'VERSION' });
console.log(version.result);    //  { name: 'UAPKI', version: '2.0.16', … }
```

Модуль важить ~1.4 МБ, вантажиться один раз — створюйте екземпляр на весь
застосунок (ліниво, коли він справді потрібен), а не на кожну операцію.

Без `wasmUrl` завантажувач шукає `uapki.wasm` **поруч із собою** — це працює
лише там, де файли лежать разом (як у прикладах цього репозиторію). Альтернатива
для складальників, що вміють імпортувати asset-и — передати байти самому:
`createUapki({ wasmBinary })`.

## Контракт `process()`

Один виклик — один запит протоколу:

```js
const response = await uapki.process({ method: 'OPEN', parameters: { … } });
```

- Повертається **вся відповідь**: `{ errorCode, method, result?, error? }`.
- На помилку протоколу виняток **не кидається** — перевіряйте `errorCode`
  самі (`0` — успіх). Виняток буває лише на інфраструктурних збоях
  (`UapkiError`: не завантажився модуль, некоректний аргумент).
- Виклик асинхронний: `process()` може призупинитись на мережевому запиті
  (Asyncify + `fetch`).
- Виклики треба **серіалізувати**: бібліотека має глобальний стан
  (ініціалізація, відкрите сховище, обраний ключ), тож не запускайте два
  `process()` паралельно.

```js
const open = await uapki.process({ method: 'OPEN', parameters: { … } });
if (open.errorCode !== 0) {
    //  типові: 4121 STORAGE_NOT_OPEN, 2 INVALID_PARAM, невірний пароль
    throw new Error(`OPEN: ${open.error} (${open.errorCode})`);
}
```

## Дані — тільки base64, без файлової системи

Усі байти в протоколі — base64. SDK дає рівно два помічники: `toBase64()`
(приймає `Uint8Array | ArrayBuffer | TypedArray | string`) і `fromBase64()`.

Контейнер ключа відкривається **з пам'яті**: `storage` — літерал
`"file://memory"`, а байти йдуть у `openParams.bytes`. Файлова система
браузера при цьому не задіяна взагалі:

```js
const file = input.files[0];                      //  <input type="file">
await uapki.process({
    method: 'OPEN',
    parameters: {
        provider: 'PKCS12',
        storage: 'file://memory',
        password,
        mode: 'RO',
        openParams: { bytes: toBase64(await file.arrayBuffer()) }
    }
});
```

Так само і кеші сертифікатів/CRL: `path: ''` вимикає роботу з ФС.

## Повний цикл: підписати і перевірити

```js
//  1. Ініціалізація (один раз на сесію сторінки)
await uapki.process({
    method: 'INIT',
    parameters: {
        cmProviders: { dir: '', allowedProviders: [{ lib: 'cm-pkcs12' }] },
        certCache: { path: '', trustedCerts: [] },   //  порожній path — без ФС
        crlCache: { path: '' },
        offline: true                                //  false вмикає TSP/OCSP/CRL
    }
});

//  2. Сертифікат підписувача, якщо його немає всередині контейнера
await uapki.process({ method: 'ADD_CERT', parameters: { certificates: [ certB64 ] } });

//  3. Відкрити контейнер і обрати ключ
await uapki.process({ method: 'OPEN', parameters: {
    provider: 'PKCS12', storage: 'file://memory', password, mode: 'RO',
    openParams: { bytes: toBase64(keyBytes) }
} });

//  контейнер може містити кілька ключів — беремо той, що має сертифікат
const { keys } = (await uapki.process({ method: 'KEYS' })).result;
let selected = null;
for (const key of keys) {
    const sel = await uapki.process({ method: 'SELECT_KEY', parameters: { id: key.id } });
    if (sel.errorCode === 0 && sel.result.certId) { selected = key.id; break; }
}

//  4. Підпис
const signed = await uapki.process({ method: 'SIGN', parameters: {
    signParams: { signatureFormat: 'CAdES-BES', detachedData: false, includeCert: true },
    options: { ignoreCertStatus: true },
    dataTbs: [ { id: 'doc-0', bytes: toBase64(documentBytes) } ]
} });
const p7s = signed.result.signatures[0].bytes;      //  base64 CMS (.p7s)

//  5. Перевірка
const verified = await uapki.process({ method: 'VERIFY', parameters: { signature: { bytes: p7s } } });
verified.result.signatureInfos[0].status;           //  "TOTAL-VALID"
fromBase64(verified.result.content.bytes);          //  вкладені дані (attached)

//  6. Прибирання
await uapki.process({ method: 'CLOSE' });
await uapki.process({ method: 'DEINIT' });
```

Відкріплений (detached) підпис: `detachedData: true`, а на перевірці —
`signature: { bytes: p7s, content: toBase64(documentBytes) }`.

## Стан бібліотеки і життєвий цикл сторінки

Стан живе тільки в межах сесії сторінки і скидається на перезавантаженні:

| Помилка | Що означає |
|---|---|
| `4105 NOT_INITIALIZED` | не викликано `INIT` |
| `4106 ALREADY_INITIALIZED` | `INIT` уже виконано в цій сесії |
| `4108` | не обрано ключ (`SELECT_KEY` після `OPEN`/`KEYS`) |
| `4121 STORAGE_NOT_OPEN` | не виконано `OPEN` |
| `33 SELF_TEST_FAIL` на повторному `INIT` | самотестування за дизайном виконується один раз, при старті; для повторного `INIT` після `DEINIT` додайте `"skipSelfTest": true` |

Робіть `INIT` один раз при старті застосунку, а `OPEN`/`CLOSE` — навколо
операцій із ключем. Пароль тримайте в пам'яті рівно стільки, скільки треба
для `OPEN`.

## React

Готовий хук — `examples/react-useUapki.jsx` (покладіть його поруч зі своїм
кодом і виправте шлях імпорту на свій `src/lib/uapki/index.mjs`):

```jsx
import { useUapki } from './useUapki';
import { toBase64 } from './lib/uapki/index.mjs';

function SignButton() {
    const { uapki, ready, error } = useUapki();     //  { wasmUrl } за потреби
    if (error) return <p>UAPKI не завантажився: {String(error.message)}</p>;
    if (!ready) return <p>Завантаження UAPKI…</p>;
    …
}
```

Хук вантажить модуль один раз (`useEffect` із прапорцем `cancelled`).
У React 18 StrictMode ефект у dev-режимі виконується двічі — це створить
другий екземпляр модуля; для сталого застосунку тримайте його в контексті
або в модульній змінній, а не в кожному компоненті.

Vite/CRA віддають `public/` з кореня сайту, тож `wasmUrl: '/uapki.wasm'`.

## Vue 3

Готова composable — `examples/vue-useUapki.js`:

```vue
<script setup>
import { useUapki } from './vue-useUapki.js';
import { toBase64 } from './lib/uapki/index.mjs';

const { uapki, ready, error } = useUapki();
//  uapki — shallowRef: модуль великий і нереактивний, звертайтесь uapki.value
</script>
```

`uapki.wasm` — у `public/` (Vite), URL: `/uapki.wasm`.

## Angular

Готовий сервіс — `examples/angular-uapki.service.ts`. Модуль тримається в
DI-сінглтоні й вантажиться ліниво, при першому зверненні:

```ts
@Injectable({ providedIn: 'root' })
export class UapkiService {
    private instance?: Promise<Uapki>;

    load(): Promise<Uapki> {
        //  один екземпляр на застосунок
        return (this.instance ??= createUapki({ wasmUrl: '/uapki.wasm' }));
    }
}
```

`.wasm` віддається як asset — додайте його в `angular.json`:

```json
"assets": [
  { "glob": "uapki.wasm", "input": "src/lib/uapki", "output": "/" }
]
```

Так файл можна тримати поруч із рештою модуля в `src/lib/uapki/`, а зібраний
застосунок віддаватиме його з кореня. Типи підхоплюються з `index.d.ts`; якщо
TypeScript свариться на імпорт `.mjs`, увімкніть `"moduleResolution": "bundler"`
(або `"node16"`) у `tsconfig.json`.

## Vanilla (без складальника)

`examples/vanilla.html` — повний приклад «обрати ключ → підписати →
перевірити» без жодного інструментарію:

```html
<script type="module">
import { createUapki, toBase64 } from './sdk/index.mjs';
const uapki = await createUapki();
</script>
```

Подивитись локально:

```sh
python -m http.server 8000 --directory integration/WebAssembly
# http://localhost:8000/examples/vanilla.html
```

### Якщо ваш код — не ES-модуль

Модульним має бути лише **завантаження**; код використання може лишатися
звичайним скриптом (легасі-кодова база, інлайн-обробники тощо). Модульний
скрипт імпортує SDK і віддає сторінці проміс екземпляра:

```html
<script type="module">
import { createUapki, toBase64, fromBase64 } from './sdk/index.mjs';
window.UAPKI = { ready: createUapki(), toBase64, fromBase64 };
</script>

<script>
//  звичайний скрипт: ні import, ні await на верхньому рівні
window.addEventListener('DOMContentLoaded', function () {
    window.UAPKI.ready.then(async function (uapki) {
        const version = await uapki.process({ method: 'VERSION' });
    });
});
</script>
```

Два правила, які тут легко порушити:

- **порядок**: модульні скрипти неявно `defer`, тож класичний скрипт
  виконується **раніше** — на момент його виконання `window.UAPKI` ще немає.
  Тому робота починається на `DOMContentLoaded`: відкладені скрипти
  (включно з модульними) виконуються до нього;
- **без top-level `await`** у модульному скрипті: він відкладе
  `DOMContentLoaded` до завантаження всього модуля. Віддавайте **проміс**
  (`createUapki()` без `await`), а чекайте на нього вже в коді використання.

Так само робиться міст до будь-якого неESM-оточення: глобал — це свідоме
рішення вашої сторінки, а не вимога бібліотеки.

## Особливості складальників

- **Vite / webpack / CRA** — JS-частина працює сама собою (звичайний імпорт).
  Слідкуйте лише за `.wasm`: покладіть його в `public/` і передайте
  `createUapki({ wasmUrl: '/uapki.wasm' })`, або передайте байти
  (`wasmBinary`), якщо імпортуєте його як asset складальника.
- **Next.js / SSR / Nuxt** — модуль браузерний (`ENVIRONMENT=web,worker`).
  Викликайте `createUapki()` лише на клієнті (`useEffect`, `onMounted`,
  `dynamic(..., { ssr: false })`), не під час рендеру на сервері.
- **Content-Security-Policy** — потрібен `'wasm-unsafe-eval'` для компіляції
  WASM. Окремих дозволів для скриптів не треба: завантажувач — звичайний
  модуль, а не інжектований тег.
- **Web Worker** — модуль зібрано і для воркера; оскільки SDK і завантажувач
  є ES-модулями, воркер має бути модульним:
  `new Worker(url, { type: 'module' })`. Виносити крипту у воркер варто, щоб
  не блокувати UI на довгих операціях.
- **Свій завантажувач** — якщо треба взяти модуль нестандартно (власна схема
  кешування, чужий CDN), імпортуйте `uapki.mjs` самі й передайте фабрику:
  `createUapki({ moduleFactory })`.

## Мережа: TSP, OCSP, CRL

При `offline: false` бібліотека сама ходить у мережу (мітка часу для CAdES-T,
статус сертифіката через OCSP, завантаження CRL) — з боку вашого коду нічого
робити не треба, жодних колбеків: усе відбувається всередині `process()`.

Як це влаштовано: WASM не має мережі взагалі — ні сокетів, ні системних
викликів. Тому HTTP виконує **браузерний `fetch()`**, а C++-код бібліотеки
викликає його через JS-функцію, вшиту в модуль (`EM_ASYNC_JS` у
`common/pkix/http-helper.cpp`). Бібліотека при цьому лишається синхронною:
Asyncify призупиняє стек WASM до завершення промісу. Саме тому `process()`
асинхронний — SDK це вже враховує.

Наслідок, який неможливо обійти: діють **правила браузера**, тож цільовий
сервер мусить дозволяти CORS. Публічні українські TSP/OCSP зазвичай його не
дозволяють — ставте reverse-proxy на своєму домені й вказуйте його URL:

```js
tsp: { url: 'https://ваш-домен/tsp-proxy', forced: true, nonceLen: 8 }
```

`forced: true` потрібен, бо TSP-URL із сертифіката підписувача має пріоритет
над конфігом. Проксі з `HttpHelper::init(proxyUrl)` у WASM **не працює** —
`fetch()` не вміє явних проксі; це поле лишилось для діагностики.

Помилка при заблокованому CORS приходить не як «мережева», а як «сервер не
відповідає» — браузер не розрізняє для JS відмову CORS і недоступний хост:

| Ситуація | Що побачите |
|---|---|
| CORS заблокував / сервер недоступний | `4209 TSP_NOT_RESPONDING`, `4193 OCSP_NOT_RESPONDING`, `4178 CRL_NOT_DOWNLOADED` |
| Сервер відповів, але сміттям | `4212 TSP_RESPONSE_INVALID` тощо — тобто мережа працює, проблема в даних |
| `offline: true`, а метод потребує мережі | `4120 OFFLINE_MODE` |

У режимі `offline: true` мережевих запитів немає (CAdES-BES).

## TypeScript

Типи — у `sdk/index.d.ts`. `process()` узагальнений за типом результату:

```ts
import { createUapki, type UapkiResponse } from './lib/uapki/index.mjs';

interface KeysResult { keys: Array<{ id: string; mechanismId: string }> }
const keys: UapkiResponse<KeysResult> = await uapki.process<KeysResult>({ method: 'KEYS' });
```

Свідомо не типізовано кожен метод протоколу: перелік і форма параметрів —
у мануалі, обгортка лишається тонкою.

## Довідка API

| Експорт | Опис |
|---|---|
| `createUapki(options?)` | Завантажує модуль, повертає екземпляр `Uapki`. |
| `uapki.process(request)` | Один запит → повна відповідь. |
| `uapki.module` | Сам модуль Emscripten (запасний вихід, зокрема `FS`). |
| `toBase64(data)` | `Uint8Array \| ArrayBuffer \| TypedArray \| string` → base64. |
| `fromBase64(str)` | base64 → `Uint8Array`. |
| `UapkiError` | Помилки інфраструктури (не протоколу). |

`createUapki(options)`: `wasmUrl`, `wasmBinary`, `locateFile`,
`moduleFactory` — див. `sdk/README.md`.

## Діагностика

| Симптом | Причина |
|---|---|
| 404 на `uapki.wasm` | складальник переніс JS, а `.wasm` шукається поруч із ним — покладіть файл у `public/` і вкажіть `wasmUrl` |
| `.wasm` не компілюється | віддається не як `application/wasm`, або CSP без `'wasm-unsafe-eval'` |
| `Cannot use import statement outside a module` | скрипт підключено без `type="module"`, або класичний воркер замість `{ type: 'module' }` |
| помилка при рендері на сервері (Next/Nuxt) | `createUapki()` викликано на сервері — виносьте в клієнтський ефект |
| `TSP_NOT_RESPONDING` / `OCSP_NOT_RESPONDING` при живому сервері | CORS на цільовому сервері (див. «Мережа») |
| порожня відповідь / зависання | паралельні виклики `process()` — серіалізуйте їх |

Ручна перевірка будь-якого запиту без коду — `console.html` (пресети,
сценарії, історія). Смок-тест протоколу — `test-node.mjs`.
