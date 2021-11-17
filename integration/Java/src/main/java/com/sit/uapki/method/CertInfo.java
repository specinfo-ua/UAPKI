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
import com.sit.uapki.cert.KeyUsage;
import com.sit.uapki.cert.SubjectPublicKeyInfo;
import com.sit.uapki.cert.Validity;
import com.sit.uapki.common.DistinguishedName;
import com.sit.uapki.common.PkiData;
import com.sit.uapki.common.PkiNumber;
import com.sit.uapki.common.PkiOid;
import java.util.ArrayList;

/**
 * Classes for CERT_INFO-method
 */
public interface CertInfo {
    static final String METHOD = "CERT_INFO";

    class Parameters {
        final String bytes;
        final String certId;

        public Parameters (PkiData bytes) {
            this.bytes = bytes.toString();
            this.certId = null;
        }

        public Parameters (CertId certId) {
            this.bytes = null;
            this.certId = certId.toString();
        }
    }   //  end class Parameters
   
    class Extension {
        String extnId;
        boolean critical;   //  Optional, nullable
        String extnValue;

        public PkiOid getExtnId () {
            return new PkiOid(extnId);
        }

        public boolean isCritical () {
            return critical;
        }

        public PkiData getExtnValue () {
            return new PkiData(extnValue);
        }
    }   //  end class Extension

    class SignatureInfo {
        String algorithm;
        String parameters;  //  Optional, nullable
        String signature;

        public String getAlgorithm () {
            return algorithm;
        }

        public PkiData getParameters () {
            return new PkiData(parameters);
        }

        public PkiData getSignature () {
            return new PkiData(signature);
        }
    }   //  end class SignatureInfo

    class Result {
        String serialNumber;
        DistinguishedName issuer;
        Validity validity;
        DistinguishedName subject;
        SubjectPublicKeyInfo subjectPublicKeyInfo;
        ArrayList<Extension> extensions;
        SignatureInfo signatureInfo;
        boolean selfSigned;

        public PkiNumber getSerialNumber () {
            return new PkiNumber(serialNumber);
        }

        public DistinguishedName getIssuer () {
            return issuer;
        }

        public Validity getValidity () {
            return validity;
        }

        public DistinguishedName getSubject () {
            return subject;
        }

        public SubjectPublicKeyInfo getSpki () {
            return subjectPublicKeyInfo;
        }

        public ArrayList<Extension> getExtensions () {
            return extensions;
        }

        public SignatureInfo getSignatureInfo () {
            return signatureInfo;
        }

        public boolean isSelfSigned () {
            return selfSigned;
        }
    }   //  end class Result

}
