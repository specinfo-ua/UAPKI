/*
 * Copyright (c) 2026, The UAPKI Project Authors.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.specinfosystems.uapki;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The other methods of a session: certificates, keys, digest, CSR, CRLs, encryption
 */
class UapkiApiTest {
    private static final byte[] DATA = "The quick brown fox jumps over the lazy dog".getBytes(StandardCharsets.US_ASCII);

    private static TestEnv env;
    private static Uapki uapki;

    @BeforeAll
    static void setUp() throws Exception {
        env = TestEnv.create("api");
        uapki = new Uapki();
        uapki.init(env.config(env.certDir("certs"), true));
        uapki.openKeyStorage(env.storageCopy("storage"), TestEnv.P12_PASSWORD, KeyStorageOpenMode.RO);
    }

    @AfterAll
    static void tearDown() {
        if (uapki != null) {
            if (uapki.getOpenedKeyStorage() != null)
                uapki.closeKeyStorage();
            if (uapki.getUapkiInfo() != null)
                uapki.deinit();
            uapki.close();
        }
        if (env != null)
            env.deleteWork();
    }

    private static Key key(KeyUsage usage) {
        for (Key key : uapki.getOpenedKeyStorage().storage().keys()) {
            if (key.usage() == usage)
                return key;
        }
        throw new AssertionError("no key with usage " + usage);
    }

    @Test
    void storageAndKeys() {
        OpenedKeyStorageInfo storage = uapki.getOpenedKeyStorage();
        assertEquals(KeyStorageOpenMode.RO, storage.mode());
        assertEquals("PKCS12", storage.storage().providerId());
        assertFalse(storage.storageInfo().mechanisms().isEmpty());
        assertTrue(storage.storageInfo().mechanisms().get(0).keyParams().size() > 0);
        assertFalse(storage.storage().keys().isEmpty());

        Key key = key(KeyUsage.SIGNATURE);
        assertEquals(KeyAlgo.DSTU4145, key.keyAlgo());
        assertFalse(key.name().isEmpty());
        assertNotNull(key.dateTime());
        assertFalse(key.keyAlgoAndParamDisplay().isEmpty());

        assertThrows(UapkiException.class, () -> uapki.changePassword("new"), "the storage is read-only");
        assertEquals(1, uapki.getUapkiInfo().providers().size());
        assertTrue(uapki.getKeyStorages().isEmpty(), "PKCS12 does not list storages");
    }

    @Test
    void certificates() {
        Key key = key(KeyUsage.SIGNATURE);
        uapki.selectKey(key);
        Certificate cert = uapki.getSelectedKey().cert();
        assertNotNull(cert);
        assertEquals(uapki.getSelectedKey().key().certId(), cert.id());
        assertEquals(key.id(), uapki.getSelectedKey().key().id());
        assertFalse(cert.subject().asString().isEmpty());
        assertTrue(cert.keyUsage().digitalSignature());
        assertFalse(cert.isCa());
        assertFalse(cert.subjectKeyIdentifier().isEmpty());
        assertEquals(KeyAlgo.DSTU4145, cert.subjectPublicKeyInfo().algorithm());
        assertNotNull(cert.subjectPublicKeyInfo().parameters());
        assertTrue(cert.notAfter().isAfter(cert.notBefore()));
        //  derived from the extensions
        assertTrue(cert.isQualified());
        assertEquals("https://ca.informjust.ua/", cert.qualifiedStatementInfo());
        assertFalse(cert.ocsp().isEmpty());
        assertFalse(cert.crlDistributionPoints().isEmpty());
        assertFalse(cert.certificatePolicies().isEmpty());
        byte[] der = uapki.getCert(cert.id());
        assertTrue(der.length > 0);

        List<CertificateShortInfo> infos = uapki.getCertsShortInfoList();
        assertFalse(infos.isEmpty());
        assertEquals(infos.size(), uapki.getCerts().size());
        assertEquals(1, uapki.getCertsShortInfoList(false, 0, 1, null).size());

        CertValidation validation = uapki.verifyCert(cert.id());
        assertEquals(cert.id(), validation.subjectCertId());
        assertNotNull(validation.validateTime());

        AddedCert added = uapki.importCert(der, false, false);
        assertNotNull(added);
        assertEquals(cert.id(), added.certId());
        assertFalse(added.isUnique());

        assertTrue(uapki.getAllCrls().isEmpty());
    }

    @Test
    void digestRandomCsr() {
        assertEquals(32, uapki.getDigest(DATA, HashAlgo.GOST34311).length);
        assertEquals(64, uapki.getDigest(DATA, null, SignAlgo.DSTU4145_KUPYNA512).length);
        assertEquals(16, uapki.getRandomBytes(16).length);

        uapki.selectKey(key(KeyUsage.SIGNATURE));
        byte[] csr = uapki.getCsr();
        VerifyCsrInfo info = uapki.verifyCsr(csr);
        assertEquals("VALID", info.statusSignature());
        assertEquals(KeyAlgo.DSTU4145, info.subjectPublicKeyInfo().algorithm());
    }

    @Test
    void encryptDecrypt() {
        Key kep = key(KeyUsage.KEY_AGREEMENT);
        byte[] encrypted = uapki.encrypt(DATA, List.of(kep.certs().get(0).certId()));
        uapki.selectKey(kep);
        DecryptedData decrypted = uapki.decrypt(encrypted);
        assertArrayEquals(DATA, decrypted.content().bytes());
    }
}
