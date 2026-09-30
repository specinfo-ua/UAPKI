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
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Sessions test (port of integration/Net.Tests/Program.cs): global instance, parallel sessions, shared memory, close
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class UapkiSessionsTest {
    private static final byte[] DATA = "The quick brown fox jumps over the lazy dog".getBytes(StandardCharsets.US_ASCII);
    private static TestEnv env;

    @BeforeAll
    static void setUp() throws Exception {
        env = TestEnv.create("sessions");
    }

    @AfterAll
    static void tearDown() {
        if (env == null)
            return;
        if (Uapki.global().getUapkiInfo() != null)
            Uapki.global().deinit();
        env.deleteWork();
    }

    @Test
    @Order(1)
    void globalInstance() throws Exception {
        Uapki global = Uapki.global();
        assertTrue(global.isGlobal());
        assertFalse(global.isSharedMemory());
        String version = global.getVersion();
        System.out.println("uapki version: " + version);
        assertFalse(version.isEmpty());

        global.init(env.config(env.certDir("global"), true));
        assertNotNull(global.getUapkiInfo());
        assertEquals(1, global.getUapkiInfo().providers().size(), "INIT with the cm-pkcs12 provider");
        assertEquals("PKCS12", global.getUapkiInfo().providers().get(0).id());
        assertEquals(version, global.getUapkiInfo().version());
    }

    @Test
    @Order(2)
    void parallelSessions() throws Exception {
        final int n = 4;
        final int signs = 5;
        Uapki[] sessions = new Uapki[n];
        List<List<byte[]>> signatures = new ArrayList<>();
        ExecutorService executor = Executors.newFixedThreadPool(n);
        try {
            List<Future<List<byte[]>>> futures = new ArrayList<>();
            for (int i = 0; i < n; i++) {
                final int idx = i;
                futures.add(executor.submit(() -> {
                    Uapki session = new Uapki();
                    sessions[idx] = session;
                    session.init(env.config(env.certDir("session-" + idx), true));
                    session.openKeyStorage(env.storageCopy("storage-" + idx), TestEnv.P12_PASSWORD, KeyStorageOpenMode.RO);
                    session.selectKey(session.getOpenedKeyStorage().storage().keys().get(0));
                    List<byte[]> list = new ArrayList<>();
                    for (int k = 0; k < signs; k++) {
                        //  ignoreCertStatus: the test certificate may be expired, the check is offline
                        list.addAll(session.sign(List.of(DATA), SignAlgo.DSTU4145_GOST34311, SignatureFormat.CADES_BES,
                                false, true, true));
                    }
                    return list;
                }));
            }
            for (Future<List<byte[]>> f : futures)
                signatures.add(f.get());

            for (List<byte[]> list : signatures)
                assertEquals(signs, list.size(), n + " parallel sessions signed " + signs + " times each");

            for (Uapki session : sessions) {
                assertNotNull(session.getOpenedKeyStorage(), "the storage state is per instance");
                assertNotNull(session.getSelectedKey());
                assertNotNull(session.getSelectedKey().cert());
            }
            assertNull(Uapki.global().getOpenedKeyStorage(), "the global instance has no opened storage");
            Key key = sessions[0].getOpenedKeyStorage().storage().keys().get(0);
            assertNotNull(key.certs(), "the keys are loaded with certificates");
            assertFalse(key.certs().isEmpty());
            assertEquals(KeyAlgo.DSTU4145, key.keyAlgo());

            ValidationResult validation = sessions[0].verify(signatures.get(n - 1).get(0), null);
            assertNotNull(validation.signatureInfos());
            assertEquals(1, validation.signatureInfos().size());
            assertTrue(validation.signatureInfos().get(0).validSignatures(), "a signature made in another session is valid");
            assertTrue(validation.signatureInfos().get(0).validDigests());
            assertEquals(SignAlgo.DSTU4145_GOST34311, validation.signatureInfos().get(0).signAlgo());
            assertEquals(DATA.length, validation.content().bytes().length);
        } finally {
            executor.shutdownNow();
            for (Uapki session : sessions) {
                if (session == null)
                    continue;
                if (session.getOpenedKeyStorage() != null)
                    session.closeKeyStorage();
                if (session.getUapkiInfo() != null)
                    session.deinit();
                session.close();
            }
        }
    }

    @Test
    @Order(3)
    void sharedMemory() throws Exception {
        try (Uapki shared = Uapki.createSharedMemory()) {
            assertTrue(shared.isSharedMemory());
            assertFalse(shared.isGlobal());
            shared.init(env.config(env.certDir("shared"), false));
            assertTrue(shared.getUapkiInfo().providers().isEmpty(), "the shared memory does not query PROVIDERS");
            int sharedCerts = shared.getCerts().size();
            assertTrue(sharedCerts > 0, "INIT with a certificate cache");

            try (Uapki session = new Uapki(shared)) {
                session.init(env.config(env.dir("empty-certs"), false));
                assertEquals(sharedCerts, session.getCerts().size(), "the session sees the shared certificates");
                session.deinit();
            }

            UapkiException e = assertThrows(UapkiException.class,
                    () -> shared.openKeyStorage(env.storageCopy("shared-storage"), TestEnv.P12_PASSWORD, KeyStorageOpenMode.RO),
                    "storage methods are not allowed");
            System.out.println("shared memory OPEN: " + e.getMessage() + " (0x" + Integer.toHexString(e.getErrorCode()) + ")");
            assertEquals(0x1017, e.getErrorCode());

            assertThrows(IllegalArgumentException.class, () -> new Uapki(Uapki.global()), "new Uapki(global()) is rejected");
            try (Uapki session = new Uapki()) {
                assertThrows(IllegalArgumentException.class, () -> new Uapki(session), "new Uapki(session) is rejected");
            }
            shared.deinit();
        }
    }

    @Test
    @Order(4)
    void close() throws Exception {
        Uapki closed = new Uapki();
        closed.close();
        UapkiException e = assertThrows(UapkiException.class, closed::getVersion, "a closed session rejects calls");
        assertEquals("Помилка. Сесію звільнено", e.getMessage());
        closed.close();     //  idempotent

        Uapki memory = Uapki.createSharedMemory();
        Uapki session = new Uapki(memory);
        assertFalse(session.getVersion().isEmpty());
        memory.close();
        e = assertThrows(UapkiException.class, memory::getVersion, "closed shared memory rejects calls");
        assertEquals("Помилка. Спільну пам'ять звільнено", e.getMessage());
        e = assertThrows(UapkiException.class, session::getVersion, "a session with closed shared memory rejects calls");
        assertEquals("Помилка. Спільну пам'ять звільнено", e.getMessage());
        session.close();

        //  close() from another thread waits until the call in progress is done
        Uapki busy = new Uapki();
        try {
            busy.init(env.config(env.certDir("busy"), false));
            Thread worker = new Thread(() -> {
                for (int i = 0; i < 200; i++) {
                    try {
                        busy.getRandomBytes(64);
                    } catch (UapkiException ex) {
                        return;     //  closed: expected
                    }
                }
            });
            worker.start();
            busy.close();
            worker.join();
            assertThrows(UapkiException.class, busy::getVersion);
        } finally {
            busy.close();
        }

        Uapki.global().close();
        assertFalse(Uapki.global().getVersion().isEmpty(), "global(): close does nothing");
    }
}
