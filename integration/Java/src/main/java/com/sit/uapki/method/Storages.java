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

import java.util.ArrayList;

/**
 * Classes for STORAGES-method
 */
public interface Storages {
    static final String METHOD = "STORAGES";

    class Parameters {
        final String provider;

        public Parameters (String providerId) {
            provider = providerId;
        }

        public String getProvider () { 
            return provider; 
        }
    }   //  end class Parameters

    public class StorageInfo {
        private String id;
        private String manufacturer;
        private String description;
        private String serial;
        private String label;

        public String getId () {
            return id;
        }

        public String getManufacturer () {
            return manufacturer;
        }

        public String getDescription () {
            return description;
        }

        public String getSerial () {
            return serial;
        }

        public String getLabel () {
            return label;
        }
    }   //  end class StorageInfo

    class Result {
        private ArrayList<StorageInfo> storages;

        public ArrayList<StorageInfo> getStorages () {
            return storages;
        }
    }   //  end class Result

}
