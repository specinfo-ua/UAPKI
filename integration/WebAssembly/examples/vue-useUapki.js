/*
 * Vue 3 composable for the UAPKI WASM SDK.
 *
 * Setup (Vite):
 *   1. Copy the module files into the app, e.g. src/lib/uapki/:
 *          index.mjs, index.d.ts, uapki.mjs
 *      (from the release asset uapki-vX.Y.Z-wasm.zip, or built yourself)
 *   2. Copy uapki.wasm into public/ and pass its URL below. The JS side is a
 *      plain import — index.html stays untouched.
 *
 * Adjust the import path below to where you put the files.
 *
 * Usage in a component:
 *
 *   <script setup>
 *   import { useUapki } from './vue-useUapki.js';
 *   import { toBase64, fromBase64 } from '../lib/uapki/index.mjs';
 *
 *   const { uapki, ready, error } = useUapki();
 *
 *   async function sign(file, password) {
 *     await uapki.value.process({ method: 'INIT', parameters: {
 *       cmProviders: { dir: '', allowedProviders: [{ lib: 'cm-pkcs12' }] },
 *       certCache: { path: '', trustedCerts: [] }, crlCache: { path: '' }, offline: true } });
 *     await uapki.value.process({ method: 'OPEN', parameters: {
 *       provider: 'PKCS12', storage: 'file://memory', password, mode: 'RO',
 *       openParams: { bytes: toBase64(await file.arrayBuffer()) } } });
 *     const keys = (await uapki.value.process({ method: 'KEYS' })).result.keys;
 *     await uapki.value.process({ method: 'SELECT_KEY', parameters: { id: keys[0].id } });
 *     const signed = await uapki.value.process({ method: 'SIGN', parameters: {
 *       signParams: { signatureFormat: 'CAdES-BES', detachedData: false, includeCert: true },
 *       options: { ignoreCertStatus: true },
 *       dataTbs: [{ id: 'doc-0', bytes: toBase64('hello') }] } });
 *     return signed.result.signatures[0].bytes;   // base64 CMS
 *   }
 *   </script>
 */
import { ref, shallowRef, onMounted } from 'vue';
import { createUapki } from '../lib/uapki/index.mjs';

/** Loads the UAPKI module once; returns { uapki, ready, error } refs. */
export function useUapki({ wasmUrl = '/uapki.wasm' } = {}) {
    //  shallowRef: the module is a large non-reactive object
    const uapki = shallowRef(null);
    const ready = ref(false);
    const error = ref(null);

    onMounted(async () => {
        try {
            uapki.value = await createUapki({ wasmUrl });
            ready.value = true;
        } catch (e) {
            error.value = e;
        }
    });

    return { uapki, ready, error };
}
