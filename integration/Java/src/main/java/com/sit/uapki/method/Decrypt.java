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

import com.sit.uapki.common.PkiData;
import com.sit.uapki.common.PkiOid;

/**
 * Classes for SIGN-method
 */
public interface Decrypt {
    static final String METHOD = "DECRYPT";

    class DecryptParams {
    	final String bytes;

        public DecryptParams (PkiData envelopedData) {
        	this.bytes = envelopedData.toString();
        }
    }   //  end class DecryptParams

    class Parameters {
        DecryptParams decryptParams;

        public Parameters (PkiData envelopedData) {
            this.decryptParams = new DecryptParams(envelopedData);
        }

        public DecryptParams getDecryptParams () {
            return decryptParams;
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
    
    class Result {
        Content content;
        String originatorCertId;

        public Content getContent () {
            return content;
        }
        
        public String getOriginatorCertId () {
        	return originatorCertId;
        }
    }   //  end class Result

}
