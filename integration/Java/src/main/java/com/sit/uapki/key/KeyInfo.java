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

import com.sit.uapki.common.PkiOid;
import java.util.ArrayList;

public class KeyInfo {
    private String id;
    private String mechanismId;
    private String parameterId;
    private String application;
    private String label;
    private ArrayList<String> signAlgo;

    public KeyId getId () {
        return new KeyId(id);
    }

    public PkiOid getMechanismId () {
        return new PkiOid(mechanismId);
    }

    public PkiOid getParameterId () {
        return new PkiOid(parameterId);
    }

    public String getApplication () {
        return application;
    }

    public String getLabel () {
        return label;
    }

    public ArrayList<PkiOid> getSignAlgo () {
        ArrayList<PkiOid> rv_list = new ArrayList<>();
        for (int i = 0; i < signAlgo.size(); i++) {
            rv_list.add(new PkiOid(signAlgo.get(i)));
        }
        return rv_list;
    }
}
