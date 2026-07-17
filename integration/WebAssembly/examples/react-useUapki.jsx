/*
 * React hook + example for the UAPKI WASM SDK.
 *
 * Setup (Vite/CRA/Next):
 *   1. Copy the module files into the app, e.g. src/lib/uapki/:
 *          index.mjs, index.d.ts, uapki.mjs
 *      (from the release asset uapki-vX.Y.Z-wasm.zip, or built yourself)
 *   2. Copy uapki.wasm into public/ (served at the site root) and pass its URL
 *      below. The JS side is a plain import — nothing to add to index.html.
 *
 * Adjust the import path below to where you put the files.
 */
import { useEffect, useState, useCallback } from 'react';
import { createUapki, toBase64, fromBase64 } from '../lib/uapki/index.mjs';

/** Loads the UAPKI module once; returns { uapki, ready, error }. */
export function useUapki({ wasmUrl = '/uapki.wasm' } = {}) {
    const [uapki, setUapki] = useState(null);
    const [error, setError] = useState(null);

    useEffect(() => {
        let cancelled = false;
        createUapki({ wasmUrl })
            .then((u) => { if (!cancelled) setUapki(u); })
            .catch((e) => { if (!cancelled) setError(e); });
        return () => { cancelled = true; };
    }, [wasmUrl]);

    return { uapki, ready: uapki !== null, error };
}

/** Example component: pick a key file + password, sign "hello", verify. */
export function SignDemo() {
    const { uapki, ready, error } = useUapki();
    const [status, setStatus] = useState('');

    const onSign = useCallback(async (event) => {
        event.preventDefault();
        const form = event.currentTarget;
        const file = form.key.files[0];
        const password = form.pass.value;
        if (!uapki || !file) return;

        //  Thin protocol: request object -> response object. Check errorCode.
        await uapki.process({
            method: 'INIT',
            parameters: {
                cmProviders: { dir: '', allowedProviders: [{ lib: 'cm-pkcs12' }] },
                certCache: { path: '', trustedCerts: [] },
                crlCache: { path: '' },
                offline: true
            }
        });

        const open = await uapki.process({
            method: 'OPEN',
            parameters: {
                provider: 'PKCS12',
                storage: 'file://memory',
                password,
                mode: 'RO',
                openParams: { bytes: toBase64(await file.arrayBuffer()) }
            }
        });
        if (open.errorCode !== 0) { setStatus('OPEN: ' + open.error); return; }

        const keys = (await uapki.process({ method: 'KEYS' })).result.keys;
        await uapki.process({ method: 'SELECT_KEY', parameters: { id: keys[0].id } });

        const signed = await uapki.process({
            method: 'SIGN',
            parameters: {
                signParams: { signatureFormat: 'CAdES-BES', detachedData: false, includeCert: true },
                options: { ignoreCertStatus: true },
                dataTbs: [{ id: 'doc-0', bytes: toBase64('hello') }]
            }
        });
        if (signed.errorCode !== 0) { setStatus('SIGN: ' + signed.error); return; }

        const verified = await uapki.process({
            method: 'VERIFY',
            parameters: { signature: { bytes: signed.result.signatures[0].bytes } }
        });
        setStatus('verify: ' + verified.result.signatureInfos[0].status +
            ', content: ' + new TextDecoder().decode(fromBase64(verified.result.content.bytes)));

        await uapki.process({ method: 'CLOSE' });
        await uapki.process({ method: 'DEINIT' });
    }, [uapki]);

    if (error) return <p>Помилка завантаження UAPKI: {String(error.message)}</p>;
    if (!ready) return <p>Завантаження UAPKI…</p>;

    return (
        <form onSubmit={onSign}>
            <input type="file" name="key" />
            <input type="password" name="pass" placeholder="пароль" />
            <button type="submit">Підписати "hello"</button>
            <pre>{status}</pre>
        </form>
    );
}
