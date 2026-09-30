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
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * MODIFY_CMS: read-only options, remove, add content/certificates/signatures, legacy overload
 */
class UapkiModifyCmsTest {
    private static final byte[] DATA = "The quick brown fox jumps over the lazy dog".getBytes(StandardCharsets.US_ASCII);
    private static final String CA_CERT = "diia-CA-05E19E2CD92EA2990100000001000000E1000000.cer";

    private static TestEnv env;
    private static Uapki uapki;
    private static byte[] cms;          //  CAdES-BES with the content and the signer certificate
    private static byte[] cms2;         //  the second signature of the same content

    @BeforeAll
    static void setUp() throws Exception {
        env = TestEnv.create("modifycms");
        uapki = new Uapki();
        uapki.init(env.config(env.certDir("certs"), true));
        uapki.openKeyStorage(env.storageCopy("storage"), TestEnv.P12_PASSWORD, KeyStorageOpenMode.RO);
        uapki.selectKey(uapki.getOpenedKeyStorage().storage().keys().get(0));
        List<byte[]> signatures = uapki.sign(List.of(DATA, DATA), SignAlgo.DSTU4145_GOST34311, SignatureFormat.CADES_BES,
                false, true, true);
        cms = signatures.get(0);
        cms2 = signatures.get(1);
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

    private static ModifyCmsOptions allOptions() {
        return new ModifyCmsOptions().setReturnContent(true).setReturnCerts(true).setReturnCrls(true).setReturnEncodedSignerInfo(true);
    }

    private static ModifyCmsResult info(byte[] bytes) {
        return uapki.modifyCms(bytes, null, null, allOptions());
    }

    @Test
    void readOnlyOptions() {
        ModifyCmsResult r = info(cms);
        assertNull(r.bytes(), "nothing is modified");
        assertEquals("1.2.840.113549.1.7.1", r.content().type());
        assertArrayEquals(DATA, r.content().bytes());
        assertEquals(1, r.certificates().size());
        assertTrue(r.crls().isEmpty());
        assertEquals(1, r.signatureInfos().size());
        SignatureInfoEx si = r.signatureInfos().get(0);
        assertNotNull(si.bytes(), "returnEncodedSignerInfo");
        assertNotNull(si.messageDigest());
        assertEquals(SignAlgo.DSTU4145_GOST34311, SignAlgo.fromOid(si.signAlgo()));
        assertEquals(HashAlgo.GOST34311, HashAlgo.fromOid(si.digestAlgo()));
        assertFalse(r.digestAlgorithms().isEmpty());

        ModifyCmsResult minimal = uapki.modifyCms(cms, null);
        assertNull(minimal.content().bytes(), "the content is not returned without returnContent");
        assertTrue(minimal.certificates().isEmpty());
        assertNull(minimal.signatureInfos().get(0).bytes());
    }

    @Test
    void removeAndAdd() throws Exception {
        //  remove the certificates and the content
        ModifyCmsResult removed = uapki.modifyCms(cms, null,
                new ModifyCmsRemove().setCertificates(true).setContent(true), null);
        assertNotNull(removed.bytes());
        byte[] stripped = removed.bytes();
        ModifyCmsResult r = info(stripped);
        assertNull(r.content().bytes(), "the content is removed");
        assertTrue(r.certificates().isEmpty(), "the certificates are removed");
        assertEquals(1, r.signatureInfos().size());

        //  add the content and the CA certificate
        byte[] caCert = env.testCert(CA_CERT);
        ModifyCmsResult added = uapki.modifyCms(stripped,
                new AddSignature().setContent(DATA).setCertificates(List.of(caCert)));
        assertNotNull(added.bytes());
        r = info(added.bytes());
        assertArrayEquals(DATA, r.content().bytes());
        assertEquals(1, r.certificates().size());
        assertArrayEquals(caCert, r.certificates().get(0));

        //  the signer certificate is in the cache: the signature is still valid
        ValidationResult validation = uapki.verify(added.bytes(), null);
        assertTrue(validation.signatureInfos().get(0).validSignatures());

        //  a wrong content is rejected
        UapkiException e = assertThrows(UapkiException.class, () -> uapki.modifyCms(stripped,
                new AddSignature().setContent("wrong content".getBytes(StandardCharsets.US_ASCII))));
        assertEquals(0x1039, e.getErrorCode());
    }

    @Test
    void addSignerInfoAndRemoveBySignIndex() {
        byte[] signerInfo1 = info(cms).signatureInfos().get(0).bytes();
        byte[] signerInfo = info(cms2).signatureInfos().get(0).bytes();

        //  add the encoded SignerInfo of the second signature
        ModifyCmsResult added = uapki.modifyCms(cms, new AddSignature().setBytes(signerInfo).setIsSignerInfo(true));
        assertNotNull(added.bytes());
        ModifyCmsResult r = info(added.bytes());
        assertEquals(2, r.signatureInfos().size());
        //  signerInfos is a DER SET OF: the order of the encoded signatures is not the order of adding
        byte[] first = r.signatureInfos().get(0).bytes();
        byte[] second = r.signatureInfos().get(1).bytes();
        assertTrue((Arrays.equals(first, signerInfo1) && Arrays.equals(second, signerInfo))
                || (Arrays.equals(first, signerInfo) && Arrays.equals(second, signerInfo1)), "both signatures are present");

        ValidationResult validation = uapki.verify(added.bytes(), null);
        assertEquals(2, validation.signatureInfos().size());
        assertTrue(validation.signatureInfos().get(0).validSignatures());
        assertTrue(validation.signatureInfos().get(1).validSignatures());

        //  remove the first signature
        ModifyCmsResult removed = uapki.modifyCms(added.bytes(), null, new ModifyCmsRemove().setSignIndex(0), null);
        r = info(removed.bytes());
        assertEquals(1, r.signatureInfos().size());
        assertArrayEquals(second, r.signatureInfos().get(0).bytes(), "the signature with index 1 remains");

        //  the signature index is out of range
        assertThrows(UapkiException.class, () -> uapki.modifyCms(cms, null, new ModifyCmsRemove().setSignIndex(5), null));

        //  add the signature from a PKCS#7 by signIndex
        added = uapki.modifyCms(cms, new AddSignature().setBytes(cms2).setSignIndex(0));
        assertEquals(2, info(added.bytes()).signatureInfos().size());
    }

    @Test
    void legacyOverload() throws Exception {
        byte[] caCert = env.testCert(CA_CERT);
        ModifyCmsResult r = uapki.modifyCms(cms, cms2, List.of(caCert), true, true, false, false);
        assertNotNull(r.bytes(), "the signature and the certificate are added");
        assertArrayEquals(DATA, r.content().bytes(), "returnContent (of the input)");
        assertEquals(1, r.certificates().size(), "returnCerts (of the input)");

        ModifyCmsResult modified = info(r.bytes());
        assertEquals(2, modified.signatureInfos().size());
        assertEquals(2, modified.certificates().size());

        //  nothing to add: only the information
        r = uapki.modifyCms(cms, null, null, false, false, false, false);
        assertNull(r.bytes());
        assertEquals(1, r.signatureInfos().size());
    }
}
