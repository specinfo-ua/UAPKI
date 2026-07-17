/**
 * UAPKI · WebAssembly SDK — TypeScript declarations.
 *
 * Thin, faithful wrapper over the UAPKI JSON protocol. Request/response shapes
 * follow the programmer's manual (doc/UAPKI-PM-*.pdf); the SDK does not type
 * every method — process() is generic on purpose.
 */

/** Bytes accepted by the base64 helpers. */
export type BytesInput = Uint8Array | ArrayBuffer | ArrayBufferView | string;

/** A UAPKI request: a method name plus optional parameters (see the manual). */
export interface UapkiRequest {
    method: string;
    parameters?: Record<string, unknown>;
}

/** A UAPKI response: always carries errorCode and method; result on success. */
export interface UapkiResponse<TResult = Record<string, unknown>> {
    errorCode: number;
    method: string;
    result?: TResult;
    error?: string;
    [extra: string]: unknown;
}

/** Error thrown by the SDK infrastructure (module loading, bad arguments). */
export class UapkiError extends Error {
    name: 'UapkiError';
    code?: number;
    method?: string;
    response?: UapkiResponse;
    constructor(message: string, details?: { code?: number; method?: string; response?: UapkiResponse });
}

/** Encode bytes to base64. For File/Blob, await .arrayBuffer() first. */
export function toBase64(data: BytesInput): string;

/** Decode a base64 string to bytes. */
export function fromBase64(base64: string): Uint8Array;

export interface CreateUapkiOptions {
    /** URL of uapki.wasm. Default: resolved relative to the loader (uapki.mjs). */
    wasmUrl?: string;
    /** Raw .wasm bytes, when the caller loads the file itself (Node, bundler). */
    wasmBinary?: Uint8Array | ArrayBuffer;
    /** Custom Emscripten asset locator (overrides wasmUrl). */
    locateFile?: (path: string) => string;
    /** An already loaded Emscripten factory, to bypass importing ./uapki.mjs. */
    moduleFactory?: (moduleArg?: Record<string, unknown>) => Promise<UapkiModule>;
}

/** The underlying Emscripten module (escape hatch). */
export interface UapkiModule {
    cwrap(name: string, ret: string | null, args: string[], opts?: { async?: boolean }): (...a: unknown[]) => unknown;
    stringToNewUTF8(s: string): number;
    UTF8ToString(ptr: number): string;
    _free(ptr: number): void;
    _json_free(ptr: number): void;
    FS: unknown;
    [key: string]: unknown;
}

export class Uapki {
    /** The underlying Emscripten module (rarely needed). */
    readonly module: UapkiModule;
    /**
     * Execute one UAPKI request. Returns the full response object, exactly as
     * documented (check response.errorCode). Never throws on protocol errors —
     * only on invalid arguments.
     */
    process<TResult = Record<string, unknown>>(request: UapkiRequest): Promise<UapkiResponse<TResult>>;
}

/**
 * Create and initialize a UAPKI SDK instance. Imports the loader (./uapki.mjs)
 * and lets it fetch uapki.wasm from next to itself, unless told otherwise.
 */
export function createUapki(options?: CreateUapkiOptions): Promise<Uapki>;
