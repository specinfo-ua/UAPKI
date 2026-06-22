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

#ifndef CRYPTOKI_CONST_UKR_H
#define CRYPTOKI_CONST_UKR_H


#include "pkcs11.h"


namespace Cryptoki {


namespace CKA {
    namespace UKR {
        constexpr CK_ATTRIBUTE_TYPE GOST_SBOX       = CKA_SBOX;
        constexpr CK_ATTRIBUTE_TYPE KEY_ATTESTATE   = CKA_SIS_KEY_ATTESTATE;
    }
};  //  end namespace CKA::UKR

namespace CKD {
    namespace UKR {
        constexpr CK_ULONG GOST34311_KDF    = CKD_GOST34311_KDF;
        constexpr CK_ULONG KUPYNA256_KDF    = CKD_KUPYNA256_KDF;
    }
};  //  end namespace CKD::UKR

namespace CKK {
    namespace UKR {
        constexpr CK_KEY_TYPE GOST28147     = CKK_GOST28147;
        constexpr CK_KEY_TYPE KALYNA128     = CKK_KALYNA_BLOCK128;
        constexpr CK_KEY_TYPE KALYNA256     = CKK_KALYNA_BLOCK256;
        constexpr CK_KEY_TYPE KALYNA512     = CKK_KALYNA_BLOCK512;
        constexpr CK_KEY_TYPE DSTU4145      = CKK_DSTU4145;
    }
};  //  end namespace CKK::UKR

namespace CKM {
    namespace UKR {
        constexpr CK_MECHANISM_TYPE GOST28147_ECB   = CKM_GOST28147_ECB;
        constexpr CK_MECHANISM_TYPE GOST28147_CNT   = CKM_GOST28147_CNT;
        constexpr CK_MECHANISM_TYPE GOST28147_CFB   = CKM_GOST28147_CFB;
        constexpr CK_MECHANISM_TYPE GOST28147_MAC   = CKM_GOST28147_MAC;
        constexpr CK_MECHANISM_TYPE GOST28147_MAC_GENERAL   = CKM_GOST28147_MAC_GENERAL;
        constexpr CK_MECHANISM_TYPE GOST28147_WRAP          = CKM_GOST28147_WRAP;
        constexpr CK_MECHANISM_TYPE KALYNA256_WRAP          = CKM_KALYNA_WRAP;
        constexpr CK_MECHANISM_TYPE GOST28147_KEY_GEN       = CKM_GOST28147_KEY_GEN;
        constexpr CK_MECHANISM_TYPE GOST34311       = CKM_GOST34311;
        constexpr CK_MECHANISM_TYPE KUPYNA256       = CKM_KUPYNA256;
        constexpr CK_MECHANISM_TYPE KUPYNA384       = CKM_KUPYNA384;
        constexpr CK_MECHANISM_TYPE KUPYNA512       = CKM_KUPYNA512;
        constexpr CK_MECHANISM_TYPE DSTU4145                = CKM_DSTU4145;
        constexpr CK_MECHANISM_TYPE DSTU4145_WITH_GOST34311 = CKM_DSTU4145_WITH_GOST34311;
        constexpr CK_MECHANISM_TYPE DSTU4145_WITH_KUPYNA256 = CKM_DSTU4145_WITH_KUPYNA256;
        constexpr CK_MECHANISM_TYPE DSTU4145_WITH_KUPYNA384 = CKM_DSTU4145_WITH_KUPYNA384;
        constexpr CK_MECHANISM_TYPE DSTU4145_WITH_KUPYNA512 = CKM_DSTU4145_WITH_KUPYNA512;
        constexpr CK_MECHANISM_TYPE DSTU4145_KEY_PAIR_GEN   = CKM_DSTU4145_KEY_PAIR_GEN;
        constexpr CK_MECHANISM_TYPE DSTU4145_ECDH_DERIVE            = CKM_DSTU4145_ECDH_DERIVE;
        constexpr CK_MECHANISM_TYPE DSTU4145_ECDH_COFACTOR_DERIVE   = CKM_DSTU4145_ECDH_COFACTOR_DERIVE;
    }
};  //  end namespace CKM::UKR

namespace CKR {
    namespace UKR {
        constexpr CK_RV SBOX_NOT_FOUND          = CKR_SBOX_NOT_FOUND;
        constexpr CK_RV EC_PARAMS_NOT_FOUND     = CKR_EC_PARAMS_NOT_FOUND;
        constexpr CK_RV EC_PARAMS_INVALID       = CKR_EC_PARAMS_INVALID;
        constexpr CK_RV PRIVATE_KEY_NOT_FOUND   = CKR_PRIVATE_KEY_NOT_FOUND;
        constexpr CK_RV PUBLIC_KEY_NOT_FOUND    = CKR_PUBLIC_KEY_NOT_FOUND;
        constexpr CK_RV EC_POINT_INVALID        = CKR_EC_POINT_INVALID;
        constexpr CK_RV EC_KEY_INVALID          = CKR_EC_KEY_INVALID;
        constexpr CK_RV ID_ALREADY_EXIST        = CKR_ID_ALREADY_EXIST;
        constexpr CK_RV OID_INCORRECT           = CKR_OID_INCORRECT;
        constexpr CK_RV DIAGNOSTIC_ERROR        = CKR_DIAGNOSTIC_ERROR;
    }

};  //  end namespace CKR::UKR


}   //  end namespace Cryptoki

#endif
