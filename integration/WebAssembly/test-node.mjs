//  CI/local smoke test of the UAPKI WebAssembly module.
//
//  The module is built for browsers only (-sENVIRONMENT=web,worker); Node.js
//  here is just a test harness: the wasm bytes are injected via
//  Module.wasmBinary, so the browser-only loader never needs fetch() or any
//  Node-specific code path. For native Node.js usage of the library see
//  integration/Node.js (N-API addon).
//
//  Usage (from the repository root, after the WASM build):
//      node integration/WebAssembly/test-node.mjs [path/to/uapki.mjs]
//
//  Runs through the SDK (sdk/index.mjs) - the same entry point applications
//  use - so a broken wrapper fails the build too.
//
//  Exercises the JSON protocol end to end on the committed test data:
//  DIGEST with a known answer, JKS container open (regression for the
//  jks_pass_to_ba password fix), and a full CAdES-BES sign/verify cycle
//  with a DSTU-4145 key. Exits non-zero on the first failure.

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createUapki } from "./sdk/index.mjs";

//  pre.js expects the Web Crypto API; make it global on older Node (< 19)
if (typeof globalThis.crypto === "undefined") {
    globalThis.crypto = (await import("node:crypto")).webcrypto;
}

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, "..", "..");
const uapkiJsPath = path.resolve(process.argv[2] ?? path.join(scriptDir, "sdk", "uapki.mjs"));
const uapkiWasmPath = path.join(path.dirname(uapkiJsPath), "uapki.wasm");
const testData = (name) => path.join(repoRoot, "library", "test", "data", name);

//  One test suite - one summary line. Individual checks are listed only on
//  failure (everything passed so far + the failing one) or with VERBOSE=1.
let passed = 0;
const verbose = !!process.env.VERBOSE;
function check (name, cond, details) {
    if (!cond) {
        if (!verbose) console.error(`(checks passed before the failure: ${passed})`);
        console.error(`FAIL: ${name}${details ? " - " + details : ""}`);
        process.exit(1);
    }
    passed++;
    if (verbose) console.log(`ok: ${name}`);
}

//  the loader is browser-only, so hand it the wasm bytes instead of a URL;
//  moduleFactory lets the test point at a freshly built module (CI) rather
//  than the copy inside sdk/
const uapkiSdk = await createUapki({
    moduleFactory: (await import(pathToFileURL(uapkiJsPath).href)).default,
    wasmBinary: readFileSync(uapkiWasmPath)
});
const module_ = uapkiSdk.module;

async function uapki (method, parameters) {
    return uapkiSdk.process(parameters !== undefined ? { method, parameters } : { method });
}
async function uapkiOk (method, parameters) {
    const res = await uapki(method, parameters);
    check(`${method} errorCode=0`, res.errorCode === 0, `errorCode=${res.errorCode} ${res.error ?? ""}`);
    return res.result ?? {};
}

//  ---- VERSION / INIT ----
const version = await uapkiOk("VERSION");
check("VERSION reports UAPKI", version.name === "UAPKI", JSON.stringify(version));

for (const dir of ["/certs", "/crls", "/storage"]) module_.FS.mkdir(dir);
await uapkiOk("INIT", {
    cmProviders: { dir: "", allowedProviders: [ { lib: "cm-pkcs12" } ] },
    certCache: { path: "/certs/", trustedCerts: [] },
    crlCache: { path: "/crls/" },
    offline: true
});

//  ---- DIGEST with known answer (SHA-256 of the fox phrase) ----
const digest = await uapkiOk("DIGEST", {
    hashAlgo: "2.16.840.1.101.3.4.2.1",
    bytes: Buffer.from("The quick brown fox jumps over the lazy dog").toString("base64")
});
check("DIGEST known answer",
    Buffer.from(digest.bytes, "base64").toString("hex") ===
        "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
    digest.bytes);

//  ---- RANDOM_BYTES (entropy source wired through pre.js) ----
const random = await uapkiOk("RANDOM_BYTES", { length: 32 });
check("RANDOM_BYTES returns 32 bytes", Buffer.from(random.bytes, "base64").length === 32);

//  ---- JKS container (regression: password truncation in jks_pass_to_ba) ----
module_.FS.writeFile("/storage/test-jks.jks", readFileSync(testData("test-jks.jks")));
await uapkiOk("OPEN", { provider: "PKCS12", storage: "/storage/test-jks.jks", password: "testpassword", mode: "RO" });
const jksKeys = await uapkiOk("KEYS");
check("JKS lists one RSA key",
    jksKeys.keys?.length === 1 && jksKeys.keys[0].mechanismId === "1.2.840.113549.1.1.1",
    JSON.stringify(jksKeys));
await uapkiOk("CLOSE");
const jksWrongPass = await uapki("OPEN", { provider: "PKCS12", storage: "/storage/test-jks.jks", password: "wrongpassword", mode: "RO" });
check("JKS wrong password reports INVALID_PASSWORD", jksWrongPass.error === "INVALID_PASSWORD",
    `errorCode=${jksWrongPass.errorCode} ${jksWrongPass.error ?? ""}`);

//  ---- Full CAdES-BES sign/verify cycle (DSTU-4145 key) ----
await uapkiOk("ADD_CERT", {
    certificates: [ readFileSync(testData("certs/diia-test-sign-7775603.cer")).toString("base64") ]
});
module_.FS.writeFile("/storage/test-diia.p12", readFileSync(testData("test-diia.p12")));
await uapkiOk("OPEN", { provider: "PKCS12", storage: "/storage/test-diia.p12", password: "testpassword", mode: "RO" });

//  pick the key that pairs with the added certificate
let selected = null;
for (const key of (await uapkiOk("KEYS")).keys) {
    const sel = await uapki("SELECT_KEY", { id: key.id });
    if (sel.errorCode === 0 && sel.result.certId) { selected = sel.result; break; }
}
check("SELECT_KEY finds a key with certificate", selected !== null);

const tbs = "Node.js smoke test " + new Date().toISOString();
const signed = await uapkiOk("SIGN", {
    signParams: { signatureFormat: "CAdES-BES", detachedData: false, includeCert: true, includeTime: true },
    options: { ignoreCertStatus: true },
    dataTbs: [ { id: "doc-0", bytes: Buffer.from(tbs).toString("base64") } ]
});
check("SIGN returns a signature", !!signed.signatures?.[0]?.bytes);

const verified = await uapkiOk("VERIFY", { signature: { bytes: signed.signatures[0].bytes } });
const signerInfo = verified.signatureInfos?.[0] ?? {};
check("VERIFY: TOTAL-VALID", signerInfo.status === "TOTAL-VALID", JSON.stringify(signerInfo));
check("VERIFY: embedded content round-trips",
    Buffer.from(verified.content.bytes, "base64").toString() === tbs);

//  detached signature: correct content verifies, tampered content must not
const detached = await uapkiOk("SIGN", {
    signParams: { signatureFormat: "CAdES-BES", detachedData: true, includeCert: true },
    options: { ignoreCertStatus: true },
    dataTbs: [ { id: "doc-0", bytes: Buffer.from(tbs).toString("base64") } ]
});
const detachedOk = await uapkiOk("VERIFY", {
    signature: { bytes: detached.signatures[0].bytes, content: Buffer.from(tbs).toString("base64") }
});
check("VERIFY detached: TOTAL-VALID", detachedOk.signatureInfos?.[0]?.status === "TOTAL-VALID");
const tampered = await uapki("VERIFY", {
    signature: { bytes: detached.signatures[0].bytes, content: Buffer.from("tampered").toString("base64") }
});
check("VERIFY rejects tampered detached content",
    tampered.errorCode !== 0 || tampered.result.signatureInfos?.[0]?.status !== "TOTAL-VALID");

await uapkiOk("CLOSE");
await uapkiOk("DEINIT");

//  re-INIT after DEINIT: by design the self-test runs once at application
//  start, so repeated INIT must pass skipSelfTest=true (without it the
//  library intentionally reports SELF_TEST_FAIL)
await uapkiOk("INIT", {
    skipSelfTest: true,
    cmProviders: { dir: "", allowedProviders: [ { lib: "cm-pkcs12" } ] },
    certCache: { path: "/certs/", trustedCerts: [] },
    crlCache: { path: "/crls/" },
    offline: true
});
await uapkiOk("DEINIT");

console.log(`WASM smoke test: PASSED (${passed} checks)`);
