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
 * Classes for DIGEST-method
 */
public interface Digest {
    static final String METHOD = "DIGEST";

    class Parameters {
        final String hashAlgo;
        final String signAlgo;
        final String bytes;
        final String file;

        public Parameters (PkiOid hashAlgo, PkiData bytes, String file) {
            this.hashAlgo = hashAlgo.toString();
            this.signAlgo = null;
            this.bytes = (bytes != null) ? bytes.toString() : null;
            this.file = file;
        }

        public Parameters (PkiData bytes, String file, PkiOid signAlgo) {
            this.hashAlgo = null;
            this.signAlgo = signAlgo.toString();
            this.bytes = (bytes != null) ? bytes.toString() : null;
            this.file = file;
        }
    }   //  end class Parameters

    class Result {
        String hashAlgo;
        String bytes;

        public PkiOid getHashAlgo () {
            return new PkiOid(hashAlgo);
        }

        public PkiData getBytes () {
            return new PkiData(bytes);
        }
    }   //  end class Result
}
