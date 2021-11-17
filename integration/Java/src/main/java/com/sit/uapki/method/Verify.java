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
import com.sit.uapki.common.Attribute;
import com.sit.uapki.common.PkiData;
import com.sit.uapki.common.PkiOid;
import com.sit.uapki.common.PkiTime;
import com.sit.uapki.common.SignatureValidationStatus;
import com.sit.uapki.common.VerificationStatus;
import java.util.ArrayList;

/**
 * Classes for VERIFY-method
 */
public interface Verify {
    static final String METHOD = "VERIFY";

    class Signature {
        final String bytes;
        final String content;
        final boolean isDigest;

        public Signature (PkiData signedData, PkiData content, boolean isDigest) {
            this.bytes = signedData.toString();
            this.content = (content != null) ? content.toString() : null;
            this.isDigest = isDigest;
        }
    }   //  end class Signature

    class SignParams {
        final String signAlgo;
        final boolean isHash;

        public SignParams (PkiOid signAlgo) {
            this.signAlgo = signAlgo.toString();
            this.isHash = false;
        }

        public SignParams (PkiOid signAlgo, boolean isHash) {
            this.signAlgo = signAlgo.toString();
            this.isHash = isHash;
        }
    }   //  end class SignParams

    class SignerPubkey {
        final String certId;
        final String certificate;
        final String spki;

        public SignerPubkey (CertId certId) {
            this.certId = certId.toString();
            this.certificate = null;
            this.spki = null;
        }
        
        public SignerPubkey (PkiData bytes, boolean isCertificate) {
            this.certId = null;
            this.certificate = (isCertificate) ? bytes.toString() : null;
            this.spki = (isCertificate) ? null : bytes.toString();
        }
    }   //  end class SignerPubkey

    class Parameters {
        final Signature signature;
        final SignParams signParams;
        final SignerPubkey signerPubkey;
        final boolean reportTime = true;

        public Parameters (PkiData signedData, PkiData content, boolean isDigest) {
            this.signature = new Signature(signedData, content, isDigest);
            this.signParams = null;
            this.signerPubkey = null;
        }

        public Parameters (Signature signature, SignParams signParams, SignerPubkey signerPubkey) {
            this.signature = signature;
            this.signParams = signParams;
            this.signerPubkey = signerPubkey;
        }
    }   //  end class Parameters

    class Content {
        String type;
        String bytes;   //  Optional, nullable

        public PkiOid getType () {
            return new PkiOid(type);
        }

        public PkiData getBytes () {
            return new PkiData(bytes);
        }
    }   //  end class Content

    class TimestampInfo {
        String genTime;
        String policy;
        String statusDigest;
        //String statusSign;
        String hashAlgo;        //  Optional, nullable
        String hashedMessage;   //  Optional, nullable

        public PkiTime getGenTime () {
            return new PkiTime(genTime);
        }

        public PkiOid getPolicy () {
            return new PkiOid(policy);
        }

        public VerificationStatus getStatusDigest () {
            return VerificationStatus.fromString(statusDigest);
        }

        public PkiOid getHashAlgo () {
            return new PkiOid(hashAlgo);
        }

        public PkiData getHashedMessage () {
            return new PkiData(hashedMessage);
        }
    }   //  end class TimestampInfo
    
    class SignatureInfo {
        String signerCertId;
        String status;
        String statusSignature;
        String statusMessageDigest;
        String statusEssCert;                   //  Optional, nullable
        String signingTime;                     //  Optional, nullable
        TimestampInfo contentTS;                //  Optional, nullable
        TimestampInfo signatureTS;              //  Optional, nullable
        ArrayList<Attribute> signedAttributes;  //  Optional, nullable
        ArrayList<Attribute> unsignedAttributes;//  Optional, nullable

        public CertId getSignerCertId () {
            return new CertId(signerCertId);
        }

        public SignatureValidationStatus getStatus () {
            return SignatureValidationStatus.fromString(status);
        }

        public VerificationStatus getStatusSignature () {
            return VerificationStatus.fromString(statusSignature);
        }

        public VerificationStatus getStatusMessageDigest () {
            return VerificationStatus.fromString(statusMessageDigest);
        }

        public VerificationStatus getStatusEssCert () {
            return VerificationStatus.fromString(statusEssCert, VerificationStatus.NOT_PRESENT);
        }

        public PkiTime getSigningTime () {
            return new PkiTime(signingTime);
        }
        
        public TimestampInfo getContentTS () {
            return contentTS;
        }

        public TimestampInfo getSignatureTS () {
            return signatureTS;
        }

        public ArrayList<Attribute> getSignedAttributes () {
            return signedAttributes;
        }

        public ArrayList<Attribute> getUnsignedAttributes () {
            return unsignedAttributes;
        }
    }

    class Result {
        Content content;
        ArrayList<String> certIds;  //  Optional, nullable
        ArrayList<SignatureInfo> signatureInfos;
        String reportTime;          //  Optional, nullable

        public Content getContent () {
            return content;
        }

        public ArrayList<CertId> getCertIds () {
            ArrayList<CertId> rv_list = new ArrayList<>();
            for (String it : certIds) {
                rv_list.add(new CertId(it));
            }
            return rv_list;
        }

        public SignatureInfo getSignatureInfo () {
            if (signatureInfos != null)
                return signatureInfos.get(0);
            else
                return null;
        }

        public ArrayList<SignatureInfo> getSignatureInfos () {
            return signatureInfos;
        }

        public PkiTime getReportTime () {
            return new PkiTime(reportTime);
        }
    }   //  end class Result

}
