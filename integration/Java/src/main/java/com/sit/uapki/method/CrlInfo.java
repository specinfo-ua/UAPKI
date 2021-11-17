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

import com.sit.uapki.common.RevocationReason;
import com.sit.uapki.common.DistinguishedName;
import com.sit.uapki.common.PkiData;
import com.sit.uapki.common.PkiNumber;
import com.sit.uapki.common.PkiTime;
import com.sit.uapki.crl.CrlId;
import java.util.ArrayList;

/**
 * Classes for CRL_INFO-method
 */
public interface CrlInfo {
    static final String METHOD = "CRL_INFO";

    class Parameters {
        final String bytes;
        final String crlId;

        public Parameters (PkiData bytes) {
            this.bytes = bytes.toString();
            this.crlId = null;
        }

        public Parameters (CrlId crlId) {
            this.bytes = null;
            this.crlId = crlId.toString();
        }
    }   //  end class Parameters

    public class RevokedCert {
        String userCertificate;
	String revocationDate;
        String crlReason;       //  Optional, nullable
        String invalidityDate;  //  Optional, nullable
        
        public PkiNumber getUserCertificate () {
            return new PkiNumber(userCertificate);
        }

        public PkiTime getRevocationDate () {
            return new PkiTime(revocationDate);
        }

        public RevocationReason getCrlReason () {
            return RevocationReason.fromString(crlReason);
        }

        public PkiTime getInvalidityDate () {
            return new PkiTime(invalidityDate);
        }
    }   //  end class RevokedCert

    class Result {
        DistinguishedName issuer;
        String thisUpdate;
        String nextUpdate;
        int countRevokedCerts;
        String authorityKeyId;
        String crlNumber;
        String deltaCrlIndicator;       //  Optional, default: null
        ArrayList<RevokedCert> revokedCerts;
    
        public DistinguishedName getIssuer () {
            return issuer;
        }

        public PkiTime getThisUpdate () {
            return new PkiTime(thisUpdate);
        }

        public PkiTime getNextUpdate () {
            return new PkiTime(nextUpdate);
        }

        public int getCountRevokedCerts () {
            return countRevokedCerts;
        }

        public PkiNumber getAuthorityKeyId () {
            return new PkiNumber(authorityKeyId);
        }

        public PkiNumber getCrlNumber () {
            return new PkiNumber(crlNumber);
        }

        public PkiNumber getDeltaCrlIndicator () {
            return new PkiNumber(deltaCrlIndicator);
        }

        public boolean isDeltaCrl () {
            return (deltaCrlIndicator != null);
        }

        public ArrayList<RevokedCert> getRevokedCerts () {
            return revokedCerts;
        }
    }   //  end class Result

}
