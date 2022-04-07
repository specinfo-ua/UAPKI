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

import java.lang.reflect.Type;

import com.google.gson.*;
import com.sit.uapki.crl.CrlId;

/**
 * Classes for ValidateRevocation by CRL/OCSP
 */
public interface ValidateRevocation {

    class ValidateByBase {
        String status;
        String revocationReason;    //  Optional, RevocationReason.UNDEFINED
        String revocationTime;      //  Optional, nullable

        public CertificateRevocationStatus getStatus () {
            return CertificateRevocationStatus.fromString(status);
        }

        public RevocationReason getRevocationReason () {
            return RevocationReason.fromString(revocationReason);
        }

        public PkiTime getRevocationTime () {
            return new PkiTime(revocationTime);
        }
    }   //  end class ValidateRevocationByBase

    class CrlInfo {
        String url;
        String crlId;
        String statusSignature;

        public String getUrl () {
            return url;
        }

        public CrlId getCrlId () {
            return new CrlId(crlId);
        }

        public VerificationStatus getStatusSignature () {
            return VerificationStatus.fromString(statusSignature);
        }
    }   //  end class CrlInfo

    class ValidateByCrl extends ValidateByBase {
        CrlInfo full;
        CrlInfo delta;

        public CrlInfo getFull () {
            return full;
        }

        public CrlInfo getDelta () {
            return delta;
        }
    }   //  end class ValidateByCrl

    class ValidateByOcsp extends ValidateByBase {
        String responseStatus;
        ResponderId responderId;
        String statusSignature;
        String producedAt;
        String thisUpdate;
        String nextUpdate;      //  Optional, nullable

        public OcspResponseStatus getResponseStatus () {
            return OcspResponseStatus.fromString(responseStatus);
        }

        public ResponderId getResponderId () {
            return responderId;
        }

        public VerificationStatus getStatusSignature () {
            return VerificationStatus.fromString(statusSignature);
        }

        public PkiTime getProducedAt () {
            return new PkiTime(producedAt);
        }

        public PkiTime getThisUpdate () {
            return new PkiTime(thisUpdate);
        }

        public PkiTime getNextUpdate () {
            return new PkiTime(nextUpdate);
        }
    }   //  end class ValidateByOcsp

    class ResponderId {
        String responderId;
        DistinguishedName name;

        public ResponderId(String responderId) {
            this.responderId = responderId;
        }

        public ResponderId(DistinguishedName name) {
            this.name = name;
        }

        public PkiNumber getResponderId () {
            return new PkiNumber(responderId);
        }

        public DistinguishedName getName () {
            return name;
        }
    }   //  end class ResponderId


    public class ResponderIdDeserializer implements JsonDeserializer<ResponderId> {
        @Override
        public ResponderId deserialize(JsonElement jElement, Type typeOfT, JsonDeserializationContext context)
                throws JsonParseException {
            if (jElement.isJsonObject()) {
                JsonObject jObject = jElement.getAsJsonObject();
                Gson gson = new Gson();
                return new ResponderId(gson.fromJson(jObject, DistinguishedName.class));
            } else {
                return new ResponderId(jElement.getAsString());
            }
        }
    }   //  end class ResponderIdDeserializer

}
