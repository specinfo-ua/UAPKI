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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Trusted lists: the test lists of data/trust-list (signed by trust-list-signer.cer) name the certificates of
 * data/certs as trust services
 */
class UapkiTrustListTest {
    private static TestEnv env;
    private static byte[] signer;
    private static byte[] list;
    private static byte[] listOld;
    private static byte[] listWithdrawn;
    private static byte[] ca;

    @BeforeAll
    static void setUp() throws Exception {
        env = TestEnv.create("trust-list");
        Path dir = env.testData.resolve("trust-list");
        signer = Files.readAllBytes(dir.resolve("trust-list-signer.cer"));
        list = Files.readAllBytes(dir.resolve("trust-list.xml"));
        listOld = Files.readAllBytes(dir.resolve("trust-list-old.xml"));
        listWithdrawn = Files.readAllBytes(dir.resolve("trust-list-withdrawn.xml"));
        try (Stream<Path> certs = Files.list(env.testData.resolve("certs"))) {
            ca = Files.readAllBytes(certs.filter(p -> p.getFileName().toString().startsWith("diia-CA-")).findFirst().orElseThrow());
        }
    }

    @AfterAll
    static void tearDown() {
        if (env != null)
            env.deleteWork();
    }

    private static Config config(Path listsDir, boolean withSigner) {
        TrustListCacheParams lists = new TrustListCacheParams();
        if (listsDir != null)
            lists.setPath(listsDir.toString() + java.io.File.separator);
        if (withSigner)
            lists.setTrustListSignerCerts(List.of(Base64.getEncoder().encodeToString(signer)));
        return new Config().setOffline(true).setTrustListCache(lists);
    }

    private static int errorCode(Runnable action) {
        return assertThrows(UapkiException.class, action::run).getErrorCode();
    }

    @Test
    void listIsAcceptedStoredAndReadAgain() {
        Path listsDir = env.work.resolve("lists");
        try (Uapki uapki = new Uapki()) {
            uapki.init(config(listsDir, true));
            assertEquals(0, uapki.getUapkiInfo().trustListsCount());
            assertFalse(uapki.getCertInfo(ca).trusted());

            TrustListInfo info = uapki.addTrustList(list);
            assertEquals(2, info.sequenceNumber());
            assertEquals("UA", info.territory());
            assertEquals(4, info.countServices());
            assertEquals(4, info.countTrustedCerts());
            assertTrue(info.stored());
            assertTrue(info.warnings().isEmpty());

            Certificate caInfo = uapki.getCertInfo(ca);
            assertTrue(caInfo.trusted());
            assertEquals(1, caInfo.trustServices().size());
            TrustService service = caInfo.trustServices().get(0);
            assertEquals("National-CA/QC", service.type());
            assertTrue(service.forESignatures() && service.forESeals());
            assertEquals("granted", service.statuses().get(0).status());

            Certificate signerInfo = uapki.getCertInfo(signer);
            assertTrue(signerInfo.trustListSigner());
            assertFalse(signerInfo.trusted());

            assertEquals(2, uapki.addTrustListText(new String(list, StandardCharsets.UTF_8)).sequenceNumber());
            List<AcceptedTrustList> accepted = uapki.listTrustLists();
            assertEquals(1, accepted.size());
            assertEquals(2, accepted.get(0).sequenceNumber());
            assertEquals(info.listId(), accepted.get(0).listId());
            uapki.deinit();
        }
        try (Uapki next = new Uapki()) {
            next.init(config(listsDir, true));
            assertEquals(1, next.getUapkiInfo().trustListsCount());
            assertEquals(0, next.getUapkiInfo().refusedTrustListsCount());
            assertTrue(next.getCertInfo(ca).trusted());
            next.deinit();
        }
    }

    @Test
    void refusedLists() {
        try (Uapki uapki = new Uapki()) {
            uapki.init(config(null, true));
            uapki.addTrustList(list);
            assertEquals(0x107B, errorCode(() -> uapki.addTrustList(listOld)));
            String changed = new String(list, StandardCharsets.UTF_8).replace("/Svcstatus/granted", "/Svcstatus/grantee");
            assertEquals(0x1079, errorCode(() -> uapki.addTrustListText(changed)));
            assertEquals(0x1078, errorCode(() -> uapki.addTrustListText("not a list")));
            assertTrue(uapki.getCertInfo(ca).trusted());

            //  A newer list withdraws the service of the CA: its history stays, the trust does not
            assertEquals(3, uapki.addTrustList(listWithdrawn).countTrustedCerts());
            Certificate caInfo = uapki.getCertInfo(ca);
            assertFalse(caInfo.trusted());
            assertEquals("withdrawn", caInfo.trustServices().get(0).statuses().get(0).status());
            uapki.deinit();
        }
        try (Uapki noSigner = new Uapki()) {
            noSigner.init(config(null, false));
            assertEquals(0x107A, errorCode(() -> noSigner.addTrustList(list)));
            noSigner.deinit();
        }
    }
}
