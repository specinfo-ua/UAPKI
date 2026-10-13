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

import com.google.gson.annotations.SerializedName;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Звіт валідації одного підпису (метод VERIFY, тип валідації "FULL-ETSI")
 */
public record SignatureValidationReport(
        int signerInfoIndex,
        SignatureIdentifier signatureIdentifier,
        ValidationStatus signatureValidationStatus,
        SignatureValidationProcess signatureValidationProcess,
        ValidationTimeInfo validationTimeInfo,
        SignersDocument signersDocument,
        SignerInformation signerInformation,
        SignatureQuality signatureQuality,
        ValidationConstraintsEvaluationReport validationConstraintsEvaluationReport,
        String signatureFormat,
        @SerializedName("signAlgo") String signAlgoOid,
        @SerializedName("signingTime") String signingTimeRaw,
        List<String> timeStamps,
        List<CertChainInfo> certificates,
        List<ExpectedCertInfo> expectedCerts,
        List<ExpectedCrlInfo> expectedCrls,
        List<AttributeInfo> signedAttributes,
        List<AttributeInfo> unsignedAttributes) {

    public Instant signingTime() {
        return (signingTimeRaw == null) ? null : Uapki.convertUtcTimeToInstant(signingTimeRaw);
    }

    /** Підпис можна приймати лише з цим статусом */
    public boolean isTotalPassed() {
        return signatureValidationStatus != null && "TOTAL-PASSED".equals(signatureValidationStatus.mainIndication());
    }

    /** Обмеження, що не пройдені і за політикою є зауваженнями */
    public List<ValidationConstraint> warnings() {
        List<ValidationConstraint> rv = new ArrayList<>();
        if (validationConstraintsEvaluationReport != null && validationConstraintsEvaluationReport.validationConstraints() != null) {
            for (ValidationConstraint item : validationConstraintsEvaluationReport.validationConstraints()) {
                if (item.isWarning())
                    rv.add(item);
            }
        }
        return rv;
    }
}
