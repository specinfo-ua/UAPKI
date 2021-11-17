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

package com.sit.uapki.common;

/**
 * Enumeration RevocationReason
 */
public enum RevocationReason {
    UNDEFINED               ("UNDEFINED"),
    UNSPECIFIED             ("UNSPECIFIED"),
    KEY_COMPROMISE          ("KEY_COMPROMISE"),
    CA_COMPROMISE           ("CA_COMPROMISE"),
    AFFILIATION_CHANGED     ("AFFILIATION_CHANGED"),
    SUPERSEDED              ("SUPERSEDED"),
    CESSATION_OF_OPERATION  ("CESSATION_OF_OPERATION"),
    CERTIFICATE_HOLD        ("CERTIFICATE_HOLD"),
    REMOVE_FROM_CRL         ("REMOVE_FROM_CRL"),
    PRIVILEGE_WITHDRAWN     ("PRIVILEGE_WITHDRAWN"),
    AA_COMPROMISE           ("AA_COMPROMISE");

    String value;
    
    RevocationReason (String value) {
        this.value = value;
    }

    @Override
    public String toString () {
        return value;
    }

    public static RevocationReason fromString (String str) {
        try {
            return RevocationReason.valueOf(str);
        } catch (Exception e) {
            return RevocationReason.UNDEFINED;
        }
    }
}
