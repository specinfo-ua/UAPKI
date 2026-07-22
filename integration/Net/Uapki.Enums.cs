/*
 * Copyright (c) 2025, The UAPKI Project Authors.
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

namespace UapkiNet;

public static partial class Uapki
{
    public enum SignatureFormat
    {
        CAdES_BES,
        CAdES_T,
        CAdES_C,
        CAdES_XL,
        CAdES_LT,
        CAdES_A,
        CAdES_LTA,
        CMS,
        RAW
    }

    public enum KeyUsage
    {
        Signature = 1,
        KeyAgreement = 2,
        KeyEncipherment = 3,
        Any = 4
    }

    public enum KeyStorageOpenMode
    {
        RO = 0,
        RW = 1,
        CREATE = 2
    }

    public enum KeyAlgo
    {
        Dstu4145,
        Ecdsa,
        Rsa,
        Unsupported = 100
    }

    public enum KeyParameter
    {
        M233_PB,
        M257_PB,
        M307_PB,
        M367_PB,
        M431_PB,
        P256,
        P384,
        P521,
        RSA1024,
        RSA1536,
        RSA2048,
        RSA3072,
        RSA4096,
        Unsupported = 100
    }

    public enum SignAlgo
    {
        Dstu4145_Gost34311,
        Dstu4145_Kupyna256,
        Dstu4145_Kupyna384,
        Dstu4145_Kupyna512,
        Ecdsa_Sha,
        Ecdsa_Sha224,
        Ecdsa_Sha256,
        Ecdsa_Sha384,
        Ecdsa_Sha512,
        RsaPkcs_Sha,
        RsaPkcs_Sha224,
        RsaPkcs_Sha256,
        RsaPkcs_Sha384,
        RsaPkcs_Sha512,
        RsaPss,
        Unsupported = 100
    }

    public enum HashAlgo
    {
        Gost34311,
        Kupyna256,
        Kupyna384,
        Kupyna512,
        Sha,
        Sha224,
        Sha256,
        Sha384,
        Sha512,
        Sha3_224,
        Sha3_256,
        Sha3_384,
        Sha3_512,
        Unsupported = 100
    }
}
