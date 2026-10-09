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

import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Detached signing of files and data in memory, verification by a content file and by a pointer to memory
 */
class UapkiSignVerifyTest {
    private static TestEnv env;
    private static Uapki uapki;
    private static Path file;
    private static Path other;

    @BeforeAll
    static void setUp() throws Exception {
        env = TestEnv.create("sign-verify");
        uapki = new Uapki();
        uapki.init(env.config(env.certDir("certs"), true));
        uapki.openKeyStorage(env.storageCopy("storage"), TestEnv.P12_PASSWORD, KeyStorageOpenMode.RO);
        for (Key key : uapki.getOpenedKeyStorage().storage().keys()) {
            if (key.usage() == KeyUsage.SIGNATURE)
                uapki.selectKey(key);
        }

        file = env.work.resolve("document.txt");
        Files.writeString(file, "The quick brown fox jumps over the lazy dog".repeat(1000), StandardCharsets.US_ASCII);
        other = env.work.resolve("other.txt");
        Files.writeString(other, "Another document", StandardCharsets.US_ASCII);
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

    private static void assertDigestValid(ValidationResult result) {
        assertFalse(result.signatureInfos().isEmpty());
        for (SignatureData signature : result.signatureInfos()) {
            assertEquals("VALID", signature.statusMessageDigest());
            assertEquals("VALID", signature.statusSignature());
        }
        //  The content is never returned
        assertTrue(result.content() == null || result.content().bytes() == null || result.content().bytes().length == 0);
    }

    @Test
    void signFilesDetachedAndVerifyByFile() throws Exception {
        List<byte[]> signatures = uapki.signFilesDetached(new String[] { file.toString(), other.toString() },
                SignAlgo.DSTU4145_GOST34311, SignatureFormat.CADES_BES, true, true);
        assertEquals(2, signatures.size());

        assertDigestValid(uapki.verifyDetached(signatures.get(0), file.toString(), "STRUCT"));
        assertDigestValid(uapki.verifyDetached(signatures.get(1), other.toString(), "STRUCT"));
        //  Nothing is written next to the files
        assertFalse(Files.exists(Path.of(file + ".p7s")));

        ValidationResult wrong = uapki.verifyDetached(signatures.get(0), other.toString(), "STRUCT");
        assertEquals("INVALID", wrong.signatureInfos().get(0).statusMessageDigest());
    }

    @Test
    void signAndVerifyByPointer() throws Exception {
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ)) {
            MappedByteBuffer mapped = channel.map(FileChannel.MapMode.READ_ONLY, 0, channel.size());

            ByteBuffer direct = ByteBuffer.allocateDirect(16);
            direct.put("Another document".getBytes(StandardCharsets.US_ASCII)).flip();

            List<byte[]> signatures = uapki.signDetached(List.of(SignSource.ofBuffer(mapped), SignSource.ofBuffer(direct)),
                    SignAlgo.DSTU4145_GOST34311, SignatureFormat.CADES_BES, true, true);

            //  A signature of data in memory and of the same file are interchangeable
            assertDigestValid(uapki.verifyDetached(signatures.get(0), mapped, "STRUCT"));
            assertDigestValid(uapki.verifyDetached(signatures.get(0), file.toString(), "STRUCT"));
            assertDigestValid(uapki.verifyDetached(signatures.get(1), direct, "STRUCT"));
            assertDigestValid(uapki.verifyDetached(signatures.get(1), other.toString(), "STRUCT"));

            //  position..limit: a part of the buffer is a different content
            ByteBuffer part = mapped.duplicate().position(1);
            assertEquals("INVALID", uapki.verifyDetached(signatures.get(0), part, "STRUCT").signatureInfos().get(0).statusMessageDigest());
        }
    }

    @Test
    void sourceArguments() {
        assertThrows(IllegalArgumentException.class, () -> SignSource.ofBuffer(ByteBuffer.allocate(4)), "heap buffer");
        assertThrows(IllegalArgumentException.class, () -> new SignSource(null, null, 0));
    }
}
