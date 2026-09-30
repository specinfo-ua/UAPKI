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

import java.io.File;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Test environment: UAPKI_CM_PROVIDERS (directory with cm-pkcs12), UAPKI_TEST_DATA (library/test/data).
 * The native uapki library is found by JNA (jna.library.path, PATH, LD_LIBRARY_PATH).
 * The test data is never modified: certificates and key storages are copied into a temporary directory.
 */
final class TestEnv {
    static final String P12_PASSWORD = "testpassword";

    final String providersDir;
    final Path testData;
    final Path work;
    final String crlDir;

    private TestEnv(String providersDir, Path testData, Path work) throws IOException {
        this.providersDir = providersDir;
        this.testData = testData;
        this.work = work;
        this.crlDir = dir("crls");
    }

    /**
     * Skips the test (assumption) if the environment variables are not set
     */
    static TestEnv create(String name) throws IOException {
        String providers = System.getenv("UAPKI_CM_PROVIDERS");
        String data = System.getenv("UAPKI_TEST_DATA");
        assumeTrue(providers != null && !providers.isEmpty(), "UAPKI_CM_PROVIDERS is not set");
        assumeTrue(data != null && !data.isEmpty(), "UAPKI_TEST_DATA is not set");
        if (!providers.endsWith("/") && !providers.endsWith("\\"))
            providers += File.separator;     //  the library appends the platform file name to dir
        return new TestEnv(providers, Path.of(data), Files.createTempDirectory("uapki-java-" + name + "-"));
    }

    byte[] p12() throws IOException {
        return Files.readAllBytes(testData.resolve("test-diia.p12"));
    }

    byte[] testCert(String fileName) throws IOException {
        return Files.readAllBytes(testData.resolve("certs").resolve(fileName));
    }

    /**
     * Copies test-diia.p12 into the work directory
     */
    String storageCopy(String name) throws IOException {
        Path storage = work.resolve(name + ".p12");
        Files.write(storage, p12());
        return storage.toString();
    }

    String dir(String name) throws IOException {
        Path path = work.resolve(name);
        Files.createDirectories(path);
        return path + File.separator;
    }

    /**
     * The certificate cache renames files, so every instance gets its own copy
     */
    String certDir(String name) throws IOException {
        String path = dir(name);
        try (DirectoryStream<Path> files = Files.newDirectoryStream(testData.resolve("certs"), "*.cer")) {
            for (Path file : files)
                Files.copy(file, Path.of(path).resolve(file.getFileName()), StandardCopyOption.REPLACE_EXISTING);
        }
        return path;
    }

    Config config(String certDir, boolean withProviders) {
        Config config = new Config()
                .setCertCache(new CertCacheParams().setPath(certDir))
                .setCrlCache(new CrlCacheParams().setPath(crlDir))
                .setOffline(true);
        if (withProviders) {
            config.setCmProviders(new CmProvidersParams()
                    .setDir(providersDir)
                    .setAllowedProviders(List.of(new CmProviderParams("cm-pkcs12"))));
        }
        return config;
    }

    void deleteWork() {
        try (Stream<Path> paths = Files.walk(work)) {
            paths.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        } catch (IOException | RuntimeException e) {
            //  best effort
        }
    }
}
