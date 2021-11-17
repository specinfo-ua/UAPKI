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
 * Constants OIDs
 */
public interface Oids {
    public interface CipherAlgo {
        public interface Aes {
            static final PkiOid AES128_ECB      = new PkiOid("2.16.840.1.101.3.4.1.1");
            static final PkiOid AES128_CBC_PAD  = new PkiOid("2.16.840.1.101.3.4.1.2");
            static final PkiOid AES128_OFB      = new PkiOid("2.16.840.1.101.3.4.1.3");
            static final PkiOid AES128_CFB      = new PkiOid("2.16.840.1.101.3.4.1.4");
            static final PkiOid AES128_WRAP     = new PkiOid("2.16.840.1.101.3.4.1.5");
            static final PkiOid AES128_GCM      = new PkiOid("2.16.840.1.101.3.4.1.6");
            static final PkiOid AES128_CCM      = new PkiOid("2.16.840.1.101.3.4.1.7");
            static final PkiOid AES128_WRAP_PAD = new PkiOid("2.16.840.1.101.3.4.1.8");
            //TODO:
        }

        public interface Des {
            static final PkiOid TDES_CBC        = new PkiOid("1.2.840.113549.3.7");
        }
        
        public interface Dstu7624 {
            static final PkiOid DSTU7624        = new PkiOid("1.2.804.2.1.1.1.1.1.3");
            static final PkiOid DSTU7624_ECB    = new PkiOid("1.2.804.2.1.1.1.1.1.3.1");
            //TODO:
        }
        public interface Kalyna extends Dstu7624 {};
        
        public interface Gost28147 {
            static final PkiOid GOST28147_ECB   = new PkiOid("1.2.804.2.1.1.1.1.1.1.1");
            static final PkiOid GOST28147_CTR   = new PkiOid("1.2.804.2.1.1.1.1.1.1.2");
            static final PkiOid GOST28147_CFB   = new PkiOid("1.2.804.2.1.1.1.1.1.1.3");
            static final PkiOid GOST28147_CMAC  = new PkiOid("1.2.804.2.1.1.1.1.1.1.4");
            static final PkiOid GOST28147_WRAP  = new PkiOid("1.2.804.2.1.1.1.1.1.1.5");
        }
    }

    public interface HashAlgo {
        public interface Gost34311 {
            static final PkiOid GOST34311       = new PkiOid("1.2.804.2.1.1.1.1.2.1");
            static final PkiOid HMAC_GOST34311  = new PkiOid("1.2.804.2.1.1.1.1.1.2");
        }
        
        public interface Dstu7564 {
            static final PkiOid DSTU7564_256        = new PkiOid("1.2.804.2.1.1.1.1.2.2.1");
            static final PkiOid DSTU7564_384        = new PkiOid("1.2.804.2.1.1.1.1.2.2.2");
            static final PkiOid DSTU7564_512        = new PkiOid("1.2.804.2.1.1.1.1.2.2.3");
            static final PkiOid DSTU7564_256_MAC    = new PkiOid("1.2.804.2.1.1.1.1.2.2.4");
            static final PkiOid DSTU7564_384_MAC    = new PkiOid("1.2.804.2.1.1.1.1.2.2.5");
            static final PkiOid DSTU7564_512_MAC    = new PkiOid("1.2.804.2.1.1.1.1.2.2.6");
        }
        public interface Kupyna extends Dstu7564 {};

        public interface Sha1 {
            static final PkiOid SHA1        = new PkiOid("1.3.14.3.2.26");
            static final PkiOid HMAC_SHA1   = new PkiOid("1.2.840.113549.2.7");
        }
        
        public interface Sha2 {
            static final PkiOid SHA256      = new PkiOid("2.16.840.1.101.3.4.2.1");
            static final PkiOid SHA384      = new PkiOid("2.16.840.1.101.3.4.2.2");
            static final PkiOid SHA512      = new PkiOid("2.16.840.1.101.3.4.2.3");
            static final PkiOid HMAC_SHA256 = new PkiOid("1.2.840.113549.2.9");
            static final PkiOid HMAC_SHA384 = new PkiOid("1.2.840.113549.2.10");
            static final PkiOid HMAC_SHA512 = new PkiOid("1.2.840.113549.2.11");
        }
        
        public interface Sha3 {
            static final PkiOid SHA3_256        = new PkiOid("2.16.840.1.101.3.4.2.8");
            static final PkiOid SHA3_384        = new PkiOid("2.16.840.1.101.3.4.2.9");
            static final PkiOid SHA3_512        = new PkiOid("2.16.840.1.101.3.4.2.10");
            static final PkiOid HMAC_SHA3_256   = new PkiOid("2.16.840.1.101.3.4.2.14");
            static final PkiOid HMAC_SHA3_384   = new PkiOid("2.16.840.1.101.3.4.2.15");
            static final PkiOid HMAC_SHA3_512   = new PkiOid("2.16.840.1.101.3.4.2.16");
        }
    }

    public interface KeyAlgo {
        /**
        * DSTU-4145 family
        */
        public interface Dstu4145 {
            static final PkiOid DSTU4145_WITH_GOST3411      = new PkiOid("1.2.804.2.1.1.1.1.3.1");
            static final PkiOid DSTU4145_WITH_DSTU7564      = new PkiOid("1.2.804.2.1.1.1.1.3.6");
            static final PkiOid DSTU4145_WITH_DSTU7564_256  = new PkiOid("1.2.804.2.1.1.1.1.3.6.1");
            static final PkiOid DSTU4145_WITH_DSTU7564_384  = new PkiOid("1.2.804.2.1.1.1.1.3.6.2");
            static final PkiOid DSTU4145_WITH_DSTU7564_512  = new PkiOid("1.2.804.2.1.1.1.1.3.6.3");
        }
        //  EC-family
        static final PkiOid ECDSA   = new PkiOid("1.2.840.10045.2.1");
        //  RSA-family
        static final PkiOid RSA     = new PkiOid("1.2.840.113549.1.1.1");
        
        //TODO:
    }
    
    public interface KeyParam {
        /**
        * DSTU-4145 specific curves
        */
        public interface Dstu4145 {
            static final PkiOid M257_PB     = new PkiOid("1.2.804.2.1.1.1.1.3.1.1.2.6");
            static final PkiOid M307_PB     = new PkiOid("1.2.804.2.1.1.1.1.3.1.1.2.7");
            static final PkiOid M367_PB     = new PkiOid("1.2.804.2.1.1.1.1.3.1.1.2.8");
            static final PkiOid M431_PB     = new PkiOid("1.2.804.2.1.1.1.1.3.1.1.2.9");
            //TODO:
        }

        /**
        * ECDSA specific curves
        */
        public interface Ecdsa {
            static final PkiOid NIST_P256   = new PkiOid("1.2.840.10045.3.1.7");
            static final PkiOid PRIME_256V1 = NIST_P256;
            static final PkiOid SECP_256R1  = NIST_P256;
            static final PkiOid NIST_P384   = new PkiOid("1.3.132.0.34");
            static final PkiOid SECP_384R1  = NIST_P384;
            static final PkiOid NIST_P521   = new PkiOid("1.3.132.0.35");
            static final PkiOid SECP_521R1  = NIST_P521;
            //TODO:
        }
    }
    
    public interface SignAlgo {
        /**
        * DSTU-4145 signatures
        */
        public interface Dstu4145 {
            static final PkiOid DSTU4145_WITH_GOST3411      = new PkiOid("1.2.804.2.1.1.1.1.3.1.1");
            static final PkiOid DSTU4145_WITH_DSTU7564_256  = new PkiOid("1.2.804.2.1.1.1.1.3.6.1");
            static final PkiOid DSTU4145_WITH_DSTU7564_384  = new PkiOid("1.2.804.2.1.1.1.1.3.6.2");
            static final PkiOid DSTU4145_WITH_DSTU7564_512  = new PkiOid("1.2.804.2.1.1.1.1.3.6.3");
        }

        /**
        * ECDSA signatures
        */
        public interface Ecdsa {
            static final PkiOid ECDSA_WITH_SHA256   = new PkiOid("1.2.840.10045.4.3.2");
            static final PkiOid ECDSA_WITH_SHA384   = new PkiOid("1.2.840.10045.4.3.3");
            static final PkiOid ECDSA_WITH_SHA512   = new PkiOid("1.2.840.10045.4.3.4");
            static final PkiOid ECDSA_WITH_SHA3_256 = new PkiOid("2.16.840.1.101.3.4.3.10");
            static final PkiOid ECDSA_WITH_SHA3_384 = new PkiOid("2.16.840.1.101.3.4.3.11");
            static final PkiOid ECDSA_WITH_SHA3_512 = new PkiOid("2.16.840.1.101.3.4.3.12");
            //TODO:
        }
        
        /**
        * RSA signatures
        */
        public interface Rsa {
            static final PkiOid RSA_WITH_SHA256     = new PkiOid("1.2.840.113549.1.1.11");
            static final PkiOid RSA_WITH_SHA384     = new PkiOid("1.2.840.113549.1.1.12");
            static final PkiOid RSA_WITH_SHA512     = new PkiOid("1.2.840.113549.1.1.13");
            static final PkiOid RSA_WITH_SHA3_256   = new PkiOid("2.16.840.1.101.3.4.3.14");
            static final PkiOid RSA_WITH_SHA3_384   = new PkiOid("2.16.840.1.101.3.4.3.15");
            static final PkiOid RSA_WITH_SHA3_512   = new PkiOid("2.16.840.1.101.3.4.3.16");
            //TODO:
        }
    }
}
