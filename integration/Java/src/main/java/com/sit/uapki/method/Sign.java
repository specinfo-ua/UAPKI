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

import com.sit.uapki.common.Attribute;
import com.sit.uapki.common.PkiData;
import com.sit.uapki.common.Document;
import com.sit.uapki.common.PkiOid;
import com.sit.uapki.common.SignatureFormat;
import java.util.ArrayList;

/**
 * Classes for SIGN-method
 */
public interface Sign {
    static final String METHOD = "SIGN";

    class SignParams {
        String signatureFormat;
        String signAlgo;
        String digestAlgo;
        boolean detachedData;
        boolean includeCert;
        boolean includeTime;
        boolean includeContentTS;

        public SignParams (SignatureFormat signatureFormat) {
            this.signatureFormat = signatureFormat.toString();
            this.signAlgo = null;
            this.digestAlgo = null;
            this.detachedData = true;
            this.includeCert = false;
            this.includeTime = false;
            this.includeContentTS = false;
        }

        public void SetSignAlgo (PkiOid signAlgo) {
            this.signAlgo = signAlgo.toString();
        }

        public void SetDigestAlgo (PkiOid digestAlgo) {
            this.digestAlgo = digestAlgo.toString();
        }

        public void SetDetachedData (boolean detachedData) {
            this.detachedData = detachedData;
        }

        public void SetIncludeCert (boolean includeCert) {
            this.includeCert = includeCert;
        }

        public void SetIncludeTime (boolean includeTime) {
            this.includeTime = includeTime;
        }

        public void SetIncludeContentTS (boolean includeContentTS) {
            this.includeContentTS = includeContentTS;
        }
    }   //  end class SignParams

    class DataTbs extends Document {
        boolean isDigest;
        ArrayList<Attribute> signedAttributes;
        ArrayList<Attribute> unsignedAttributes;

        public DataTbs (String id, PkiData bytes) {
            super(id, bytes);
            this.isDigest = false;
        }

        public DataTbs (String id, PkiData bytes, boolean isDigest) {
            super(id, bytes);
            this.isDigest = isDigest;
        }

        public void addSignedAttribute (Attribute attribute) {
            if (this.signedAttributes == null) {
                this.signedAttributes = new ArrayList<>();
            }
            this.signedAttributes.add(attribute);
        }

        public void addUnsignedAttribute (Attribute attribute) {
            if (this.unsignedAttributes == null) {
                this.unsignedAttributes = new ArrayList<>();
            }
            this.unsignedAttributes.add(attribute);
        }

        public ArrayList<Attribute> getSignedAttributes () {
            return signedAttributes;
        }

        public ArrayList<Attribute> getUnsignedAttributes () {
            return unsignedAttributes;
        }
    }   //  end class DataTbs

    class KeyParams {
        public String permission;
        public String provider;
        public String storage;
        public String keyId;
        public String username;
        public String password;
        public String PIN;
        public String OTP;
        public String serial;
        public String tokenLabel;
    }   //  end class KeyParams

    class Parameters {
        SignParams signParams;
        ArrayList<DataTbs> dataTbs;
        KeyParams keyParams;

        public Parameters (SignatureFormat signatureFormat) {
            this.signParams = new SignParams(signatureFormat);
            this.dataTbs = new ArrayList<>();
        }

        public Parameters (SignParams signParams, ArrayList<DataTbs> dataTbs) {
            this.signParams = signParams;
            this.dataTbs = dataTbs;
        }

        public boolean addDocument (DataTbs dataTbs) {
            return this.dataTbs.add(dataTbs);
        }

        public boolean addDocument (String docId, PkiData content) {
            return this.dataTbs.add(new DataTbs(docId, content));
        }

        public KeyParams getKeyParams () {
            return keyParams;
        }

        public SignParams getSignParams () {
            return signParams;
        }
    }   //  end class Parameters

    class Result {
        private ArrayList<Document> signatures;
    
        public ArrayList<Document> getSignatures() {
            return signatures;
        }
    }   //  end class Result

}
