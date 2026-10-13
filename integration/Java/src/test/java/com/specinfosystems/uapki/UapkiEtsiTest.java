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

import java.nio.file.Files;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * VERIFY with the validation type FULL-ETSI: the report and the validation policy. Offline: the root of the test
 * signatures is not trusted and the status of their certificates is not available
 */
class UapkiEtsiTest {
    private static TestEnv env;
    private static Uapki uapki;
    private static byte[] attached;
    private static byte[] detached;

    @BeforeAll
    static void setUp() throws Exception {
        env = TestEnv.create("etsi");
        uapki = new Uapki();
        uapki.init(env.config(env.certDir("certs"), false));
        attached = Files.readAllBytes(env.testData.resolve("atsv2-attached.p7s"));
        detached = Files.readAllBytes(env.testData.resolve("atsv2-detached.p7s"));
    }

    @AfterAll
    static void tearDown() {
        if (uapki != null) {
            if (uapki.getUapkiInfo() != null)
                uapki.deinit();
            uapki.close();
        }
        if (env != null)
            env.deleteWork();
    }

    @Test
    void reportOfAnIntactSignature() {
        EtsiValidationResult result = uapki.verifyEtsi(attached, null);
        assertEquals(1, result.signatureValidationReports().size());
        SignatureValidationReport report = result.signatureValidationReports().get(0);

        assertFalse(report.isTotalPassed());
        assertEquals("INDETERMINATE", report.signatureValidationStatus().mainIndication());
        assertTrue(report.signatureValidationStatus().subIndications().contains("NO_CERTIFICATE_CHAIN_FOUND"));
        assertTrue(report.signatureValidationStatus().associatedValidationReportData().stream()
                .anyMatch(d -> "NO_CERTIFICATE_CHAIN_FOUND".equals(d.subIndication()) && "INDETERMINATE".equals(d.mainIndication())));
        assertEquals(ValidationPolicy.UKRAINE_DEFAULT, report.validationConstraintsEvaluationReport().signatureValidationPolicy().policyName());
        assertEquals("LTA", report.signatureValidationProcess().signatureValidationProcessId());
        assertTrue(report.signatureIdentifier().digestAlgAndValue().digestValue().length > 0);
        assertNull(report.signatureQuality());

        ValidationConstraint crypto = report.validationConstraintsEvaluationReport().constraint("cryptographicVerification");
        assertNotNull(crypto);
        assertTrue(crypto.isApplied());
        assertEquals("PASSED", crypto.validationStatus().mainIndication());

        //  The time-stamps and the certificates are validation objects referenced from the report
        assertFalse(report.timeStamps().isEmpty());
        assertEquals("timestamp", result.findObject(report.timeStamps().get(0)).objectType());
        assertEquals("certificate", result.findObject(report.signerInformation().signerCertificate()).objectType());
        assertEquals(report.signerInformation().signerCertificate(), report.signatureValidationStatus().certificateChain().signingCertificate());
        assertNotNull(report.validationTimeInfo().bestSignatureTime().poeObject());
    }

    @Test
    void content() {
        SignatureValidationReport changed = uapki.verifyEtsi(detached, detached).signatureValidationReports().get(0);
        assertEquals("TOTAL-FAILED", changed.signatureValidationStatus().mainIndication());
        assertEquals("HASH_FAILURE", changed.signatureValidationStatus().subIndications().get(0));

        SignatureValidationReport byFile = uapki.verifyEtsiDetached(detached, env.testData.resolve("test-fox.txt").toString(), (String) null)
                .signatureValidationReports().get(0);
        assertFalse(byFile.signatureValidationStatus().subIndications().contains("HASH_FAILURE"));

        SignatureValidationReport absent = uapki.verifyEtsi(detached, null).signatureValidationReports().get(0);
        assertTrue(absent.signatureValidationStatus().subIndications().contains("SIGNED_DATA_NOT_FOUND"));
    }

    @Test
    void validationPolicy() {
        assertEquals(ValidationPolicy.ETSI_STRICT, uapki.verifyEtsi(attached, null, ValidationPolicy.ETSI_STRICT)
                .signatureValidationReports().get(0).validationConstraintsEvaluationReport().signatureValidationPolicy().policyName());

        ValidationConstraintsEvaluationReport custom = uapki.verifyEtsi(attached, null,
                        new ValidationPolicy(ValidationPolicy.ETSI_STRICT).setRevocationFreshness(60))
                .signatureValidationReports().get(0).validationConstraintsEvaluationReport();
        assertEquals(ValidationPolicy.CUSTOM, custom.signatureValidationPolicy().policyName());
        assertEquals(ValidationPolicy.ETSI_STRICT, custom.signatureValidationPolicy().basedOn());
        assertEquals("60", custom.constraint("revocationFreshnessChecker").validationConstraintParameter().value());

        //  What the library does not know is refused
        assertThrows(UapkiException.class, () -> uapki.verifyEtsi(attached, null, "Unknown"));
        assertThrows(UapkiException.class, () -> uapki.verifyEtsi(attached, null, new ValidationPolicy().setTsaExtendedKeyUsage("other")));
    }
}
