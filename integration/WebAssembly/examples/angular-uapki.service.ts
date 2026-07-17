/*
 * Angular service for the UAPKI WASM module.
 *
 * Setup:
 *   1. Copy the module files into the app, e.g. src/lib/uapki/:
 *          index.mjs, index.d.ts, uapki.mjs, uapki.wasm
 *      (from the release asset uapki-vX.Y.Z-wasm.zip, or built yourself)
 *   2. Serve uapki.wasm as an asset - in angular.json:
 *          "assets": [
 *            { "glob": "uapki.wasm", "input": "src/lib/uapki", "output": "/" }
 *          ]
 *   3. Inject the service below. Nothing goes into index.html: the loader is
 *      a plain ES module.
 *
 * If TypeScript complains about the .mjs import, set
 * "moduleResolution": "bundler" (or "node16") in tsconfig.json.
 */
import { Injectable } from '@angular/core';
import { createUapki, toBase64, type Uapki } from '../lib/uapki/index.mjs';

@Injectable({ providedIn: 'root' })
export class UapkiService {
    //  the module is ~1.4 MB: load it once, on first use, and keep the promise
    private instance?: Promise<Uapki>;

    load(): Promise<Uapki> {
        this.instance ??= createUapki({ wasmUrl: '/uapki.wasm' });
        return this.instance;
    }

    /**
     * Sign data with a key container, then verify the result.
     * Returns the CAdES-BES signature (base64 CMS, .p7s).
     *
     * Thin protocol: every call is one request object -> one response object;
     * check errorCode yourself (see doc/UAPKI-PM-*.pdf).
     */
    async signAndVerify(keyFile: File, password: string, data: string): Promise<string> {
        const uapki = await this.load();

        await uapki.process({
            method: 'INIT',
            parameters: {
                cmProviders: { dir: '', allowedProviders: [{ lib: 'cm-pkcs12' }] },
                certCache: { path: '', trustedCerts: [] },   //  empty path -> no filesystem
                crlCache: { path: '' },
                offline: true
            }
        });

        //  the container is opened straight from memory - no filesystem at all
        const open = await uapki.process({
            method: 'OPEN',
            parameters: {
                provider: 'PKCS12',
                storage: 'file://memory',
                password,
                mode: 'RO',
                openParams: { bytes: toBase64(await keyFile.arrayBuffer()) }
            }
        });
        if (open.errorCode !== 0) throw new Error(`OPEN: ${open.error} (${open.errorCode})`);

        try {
            //  a container may hold several keys - take one that has a certificate
            const { keys } = (await uapki.process<{ keys: Array<{ id: string }> }>({ method: 'KEYS' })).result!;
            let selected: string | null = null;
            for (const key of keys) {
                const sel = await uapki.process<{ certId?: string }>({
                    method: 'SELECT_KEY', parameters: { id: key.id }
                });
                if (sel.errorCode === 0 && sel.result?.certId) { selected = key.id; break; }
            }
            if (!selected) throw new Error('no key with a certificate in the container');

            const signed = await uapki.process<{ signatures: Array<{ bytes: string }> }>({
                method: 'SIGN',
                parameters: {
                    signParams: { signatureFormat: 'CAdES-BES', detachedData: false, includeCert: true },
                    options: { ignoreCertStatus: true },
                    dataTbs: [{ id: 'doc-0', bytes: toBase64(data) }]
                }
            });
            if (signed.errorCode !== 0) throw new Error(`SIGN: ${signed.error} (${signed.errorCode})`);
            const p7s = signed.result!.signatures[0].bytes;

            const verified = await uapki.process<{ signatureInfos: Array<{ status: string }> }>({
                method: 'VERIFY', parameters: { signature: { bytes: p7s } }
            });
            const status = verified.result?.signatureInfos?.[0]?.status;
            if (status !== 'TOTAL-VALID') throw new Error(`VERIFY: ${status}`);

            return p7s;
        } finally {
            await uapki.process({ method: 'CLOSE' });
        }
    }
}

/*
 * Usage in a component:
 *
 *   export class SignComponent {
 *       status = '';
 *       constructor(private uapki: UapkiService) {}
 *
 *       async onSign(input: HTMLInputElement, password: string) {
 *           const file = input.files?.[0];
 *           if (!file) return;
 *           try {
 *               const p7s = await this.uapki.signAndVerify(file, password, 'hello');
 *               this.status = `signed, ${p7s.length} base64 chars`;
 *           } catch (e) {
 *               this.status = String((e as Error).message);
 *           }
 *       }
 *   }
 */
