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
import java.util.ArrayList;

/**
 * Classes for LIST_CERTS-method
 */
public interface ListCerts {
    static final String METHOD = "LIST_CERTS";

    class Parameters {
        final Integer offset;
        final Integer pageSize;

        public Parameters () {
            this.offset = null;
            this.pageSize = null;
        }

        public Parameters (Integer offset, Integer pageSize) {
            this.offset = offset;
            this.pageSize = pageSize;
        }
    }   //  end class Parameters

    class Result {
        ArrayList<String> certIds;
        Integer count;
        Integer offset;
        Integer pageSize;

        public ArrayList<CertId> getCertIds () {
            ArrayList<CertId> rv_list = new ArrayList<>();
            for (String it : certIds) {
                rv_list.add(new CertId(it));
            }
            return rv_list;
        }

        public Integer getCount () {
            return count;
        }

        public Integer getOffset () {
            return offset;
        }

        public Integer getPageSize () {
            return pageSize;
        }
    }   //  end class Result

}
