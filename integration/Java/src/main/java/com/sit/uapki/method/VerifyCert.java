/*
 * Copyright (c) 2021, The UAPKI Project Authors.
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

package com.sit.uapki.method;

import com.sit.uapki.cert.CertId;
import com.sit.uapki.cert.Validity;
import com.sit.uapki.common.PkiData;
import com.sit.uapki.common.PkiTime;
import com.sit.uapki.common.ValidateRevocation.ValidateByCrl;
import com.sit.uapki.common.ValidateRevocation.ValidateByOcsp;
import com.sit.uapki.common.VerificationStatus;

/**
 * Classes for VERIFY_CERT-method
 */
public interface VerifyCert {
    static final String METHOD = "VERIFY_CERT";
    
    enum ValidationType {
        ISSUER_ONLY,
        ISSUER_AND_CRL,
        ISSUER_AND_OCSP
    }

    class Parameters {
        final String bytes;
        final String certId;
        final String validateTime;
        final String validationType;
        final boolean reportTime = true;

        public Parameters (PkiData bytes, CertId certId, ValidationType validationType) {
            this.bytes = (bytes != null) ? bytes.toString() : null;
            this.certId = (certId != null) ? certId.toString() : null;
            this.validateTime = null;
            switch (validationType) {
                case ISSUER_AND_CRL:
                    this.validationType = "CRL";
                    break;
                case ISSUER_AND_OCSP:
                    this.validationType = "OCSP";
                    break;
                case ISSUER_ONLY:
                default:
                    this.validationType = null;
                    break;
            }
        }
        
        public Parameters (PkiData bytes, PkiTime validateTime) {
            this.bytes = bytes.toString();
            this.certId = null;
            this.validateTime = validateTime.toString();
            this.validationType = "CRL";
        }

        public Parameters (CertId certId, PkiTime validateTime) {
            this.bytes = null;
            this.certId = certId.toString();
            this.validateTime = validateTime.toString();
            this.validationType = "CRL";
        }
    }   //  end class Parameters

    class Result {
        String validateTime;
        String subjectCertId;
        Validity validity;
        boolean expired;
        boolean selfSigned;
        String statusSignature;
        String issuerCertId;
        ValidateByCrl validateByCRL;    //  Optional, nullable
        ValidateByOcsp validateByOCSP;  //  Optional, nullable
        String reportTime;              //  Optional, nullable
        
        public PkiTime getValidateTime () {
            return new PkiTime(validateTime);
        }

        public CertId getSubjectCertId () {
            return new CertId(subjectCertId);
        }
        
        public Validity getValidity () {
            return validity;
        }

        public boolean isExpired () {
            return expired;
        }

        public boolean isSelfSigned () {
            return selfSigned;
        }

        public VerificationStatus getStatusSignature () {
            return VerificationStatus.fromString(statusSignature);
        }

        public CertId getIssuerCertId () {
            return new CertId(issuerCertId);
        }

        public ValidateByCrl getValidateByCrl () {
            return validateByCRL;
        }

        public ValidateByOcsp getValidateByOcsp () {
            return validateByOCSP;
        }

        public PkiTime getReportTime () {
            return new PkiTime(reportTime);
        }
    }   //  end class Result

}
