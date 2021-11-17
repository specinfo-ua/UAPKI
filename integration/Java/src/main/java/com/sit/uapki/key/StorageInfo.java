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

package com.sit.uapki.key;

import java.util.ArrayList;

public class StorageInfo {
    public class MechanismInfo {
        private String id;
        private String name;
        private ArrayList<String> keyParam;
        private ArrayList<String> signAlgo;
        private ArrayList<String> keyAlgo;
        private ArrayList<String> dhKdf;
        
        public String getId() { return id; }
        public String getName() { return name; }
        public ArrayList<String> getKeyParams() { return keyParam; }
        public ArrayList<String> getSignAlgos() { return signAlgo; }
        public ArrayList<String> getKeyAlgos() { return keyAlgo; }
        public ArrayList<String> getDhKdfs() { return dhKdf; }
    }

    private String description;
    private String manufacturer;
    private String label;
    private String model;
    private String serial;
    private ArrayList<MechanismInfo> mechanisms;
    
    public String getDescription() { return description; }
    public String getManufacturer() { return manufacturer; }
    public String getLabel() { return label; }
    public String getModel() { return model; }
    public String getSerial() { return serial; }
    public ArrayList<MechanismInfo> getSupportedMechanisms() { return mechanisms; }
}
