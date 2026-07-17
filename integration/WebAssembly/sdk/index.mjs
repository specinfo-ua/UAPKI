/*
 * UAPKI · WebAssembly SDK
 *
 * A thin ES-module wrapper over the UAPKI WebAssembly module. It stays faithful
 * to the library's JSON protocol (see doc/UAPKI-PM-*.pdf): you pass a request
 * OBJECT and get the response OBJECT back — no high-level abstractions over the
 * methods themselves. The SDK only takes care of the infrastructure:
 *
 *   - loading the Emscripten loader + .wasm,
 *   - the async call bridge (the module is built with Asyncify, so process()
 *     returns a Promise),
 *   - string marshalling and freeing the returned buffer.
 *
 * No filesystem is involved: key containers are opened from memory (OPEN with
 * storage: "file://memory" + openParams.bytes) and every payload is base64,
 * exactly as the protocol allows. See sdk/README.md.
 */

/** Error thrown by the SDK infrastructure (module loading, bad arguments). */
export class UapkiError extends Error {
    constructor(message, details = {}) {
        super(message);
        this.name = 'UapkiError';
        this.code = details.code;
        this.method = details.method;
        this.response = details.response;
    }
}

/** Coerce Uint8Array | ArrayBuffer | TypedArray | string(utf-8) to Uint8Array. */
function toUint8Array(data) {
    if (data instanceof Uint8Array) return data;
    if (data instanceof ArrayBuffer) return new Uint8Array(data);
    if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    if (typeof data === 'string') return new TextEncoder().encode(data);
    throw new TypeError('Expected Uint8Array | ArrayBuffer | TypedArray | string');
}

/**
 * Encode bytes to a base64 string. Accepts Uint8Array | ArrayBuffer |
 * TypedArray | string (utf-8). For File/Blob, await file.arrayBuffer() first.
 */
export function toBase64(data) {
    const u8 = toUint8Array(data);
    let binary = '';
    const CHUNK = 0x8000;
    for (let i = 0; i < u8.length; i += CHUNK) {
        binary += String.fromCharCode.apply(null, u8.subarray(i, i + CHUNK));
    }
    return btoa(binary);
}

/** Decode a base64 string to a Uint8Array. */
export function fromBase64(base64) {
    const binary = atob(base64);
    const u8 = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) u8[i] = binary.charCodeAt(i);
    return u8;
}

class Uapki {
    #module;
    #proc;

    constructor(module) {
        this.#module = module;
        //  process() may suspend on network I/O (Asyncify) -> async binding
        this.#proc = module.cwrap('process', 'number', ['number'], { async: true });
    }

    /** The underlying Emscripten module (escape hatch; rarely needed). */
    get module() {
        return this.#module;
    }

    /**
     * Execute one UAPKI request.
     * @param {{method: string, parameters?: object}} request
     * @returns {Promise<object>} the full response object
     *          ({ errorCode, method, result?, error? }) — as documented.
     */
    async process(request) {
        if (!request || typeof request !== 'object' || typeof request.method !== 'string') {
            throw new UapkiError('request must be an object of the form { method, parameters }');
        }
        const reqPtr = this.#module.stringToNewUTF8(JSON.stringify(request));
        let resPtr = 0;
        try {
            resPtr = await this.#proc(reqPtr);
            return JSON.parse(this.#module.UTF8ToString(resPtr));
        } finally {
            this.#module._free(reqPtr);
            if (resPtr) this.#module._json_free(resPtr);
        }
    }
}

/**
 * Create and initialize a UAPKI SDK instance.
 *
 * The loader (uapki.mjs) is imported like any other module — no <script> tag,
 * no globals. Only uapki.wasm has to be reachable at runtime: by default the
 * loader looks for it next to itself, so point wasmUrl at it when your bundler
 * moves things around or the file is served from elsewhere:
 *
 *     await createUapki({ wasmUrl: '/uapki.wasm' })
 *
 * @param {object} [options]
 * @param {string}      [options.wasmUrl]        URL of uapki.wasm. Default:
 *        resolved relative to the loader.
 * @param {Uint8Array|ArrayBuffer} [options.wasmBinary] raw .wasm bytes, when the
 *        caller loads the file itself (Node, bundler asset import).
 * @param {(path:string)=>string}  [options.locateFile] custom asset locator
 *        (overrides wasmUrl).
 * @param {Function}   [options.moduleFactory]   an already loaded Emscripten
 *        factory, to bypass importing ./uapki.mjs (custom loading scheme).
 * @returns {Promise<Uapki>}
 */
export async function createUapki(options = {}) {
    const { wasmUrl, wasmBinary, locateFile, moduleFactory } = options;

    //  imported lazily: creating an instance is what needs the ~1.4 MB module,
    //  importing the SDK is not
    const factory = moduleFactory ?? (await import('./uapki.mjs')).default;

    const moduleArgs = {};
    if (wasmBinary) {
        moduleArgs.wasmBinary = wasmBinary instanceof Uint8Array ? wasmBinary : new Uint8Array(wasmBinary);
    }
    if (locateFile) {
        moduleArgs.locateFile = locateFile;
    } else if (wasmUrl) {
        moduleArgs.locateFile = (path) => (path.endsWith('.wasm') ? wasmUrl : path);
    }

    const module = await factory(moduleArgs);
    return new Uapki(module);
}

export { Uapki };
