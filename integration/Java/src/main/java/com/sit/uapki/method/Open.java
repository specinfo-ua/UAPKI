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

import com.google.gson.Gson;
import com.sit.uapki.key.StorageInfo;

/**
 * Classes for OPEN-method
 */
public interface Open {
    static final String METHOD = "OPEN";
    
    public enum Mode {
        RO, RW, CREATE
    }
    
    class Parameters {
        class OpenParams {
            class CreatePfx {
                String bagCipher;
                String bagKdf;
                int iterations;
                String macAlgo;
            }
            String bytes;
            CreatePfx createPfx;
        }
        String provider;
        String storage;
        String username;
        String password;
        String mode;
        OpenParams openParams;

        public Parameters (String providerId, String storageId, String username, String password, Mode openMode, String openParams) {
            this.provider = providerId;
            this.storage = storageId;
            this.username = username;
            this.password = password;
            this.mode = "RO";
            switch(openMode) {
                case RW: this.mode = "RW"; break;
                case CREATE: this.mode = "CREATE"; break;
                default: this.mode = "RO";
            }
            if (openParams != null) {
                Gson gson = new Gson();
                this.openParams = gson.fromJson(openParams, OpenParams.class);
            }
        }
    }   //  end class Parameters

    class Result extends StorageInfo {
    }   //  end class Result

}
