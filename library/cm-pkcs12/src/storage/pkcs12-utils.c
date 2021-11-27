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

#include "pkcs12-utils.h"
#include "uapkif.h"
#include "content-info.h"
#include "macros-internal.h"
#include "oids.h"
#include "oid-utils.h"
#include "pkcs5.h"
#include "cm-errors.h"


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
    #define DEBUG_OUTCON(expression) expression
#endif


int pkcs12_calc_hmac(const HashAlg hash_alg, const ByteArray * key, const ByteArray * msg, ByteArray ** hmac)
{
    int ret = RET_OK;
    HmacCtx *ctx = NULL;

    CHECK_PARAM(key != NULL);
    CHECK_PARAM(msg != NULL);
    CHECK_PARAM(hmac != NULL);

    DEBUG_OUTCON( printf("pkcs12_calc_hmac()\n key: "); ba_print(stdout, key); printf("\n msg: "); ba_print(stdout, msg); )
    CHECK_NOT_NULL(ctx = hmac_alloc(hash_alg));
    DO(hmac_init(ctx, key));
    DO(hmac_update(ctx, msg));
    DO(hmac_final(ctx, hmac));

cleanup:
    hmac_free(ctx);
    return ret;
}

int pkcs12_get_data_and_calc_mac (const PFX_t * pfx, const char * pass,
        const char ** macAlgo, size_t * iterations,  ByteArray ** baAuthsafe, ByteArray ** baMacValue)
{
    int ret = RET_OK;
    ByteArray *salt = NULL;
    ByteArray *dk = NULL;
    unsigned long iter = 0;
    HashAlg hash_algo = HASH_ALG_UNDEFINED;

    CHECK_PARAM(pfx != NULL);
    CHECK_PARAM(pass != NULL);
    CHECK_PARAM(baAuthsafe != NULL);
    CHECK_PARAM(baMacValue != NULL);

    hash_algo = hash_from_OID(&pfx->macData->mac.digestAlgorithm.algorithm);
    if (hash_algo == HASH_ALG_UNDEFINED) {
        SET_ERROR(RET_CM_UNSUPPORTED_ALG);
    }
    DO(asn_OCTSTRING2ba(&pfx->macData->macSalt, &salt));
    DO(asn_INTEGER2ulong(pfx->macData->iterations, &iter));

    DO(pbkdf1(pass, salt, 3, iter, 0, hash_algo, &dk));
    DO(cinfo_get_data(&pfx->authSafe, baAuthsafe));
    DO(pkcs12_calc_hmac(hash_algo, dk, *baAuthsafe, baMacValue));

    *macAlgo = hash_to_oid(hash_algo);
    *iterations = (size_t)iter;

cleanup:
    ba_free(salt);
    ba_free(dk);
    return ret;
}   //  pkcs12_get_data_and_calc_mac

int pkcs12_read_encrypted_content (const ContentInfo_t * content, const char * pass, ByteArray ** data)
{
    int ret = RET_OK;
    EncryptedData_t *encr_data = NULL;
    ContentEncryptionAlgorithmIdentifier_t * p_content_aid;
    char* oid = NULL;
    ByteArray *ba_encrypted = NULL;
    PBES2_params_t *pbes2 = NULL;
    PBKDF2_params_t *pbkdf2 = NULL;

    DO(cinfo_get_encrypted_data(content, &encr_data));
    if (!OID_is_equal_oid(&encr_data->encryptedContentInfo.contentType, OID_PKCS7_DATA)) {
        SET_ERROR(RET_CM_INVALID_CONTENT_INFO);
    }

    p_content_aid = &encr_data->encryptedContentInfo.contentEncryptionAlgorithm;
    DO(asn_oid_to_text(&p_content_aid->algorithm, &oid));

    DO(asn_OCTSTRING2ba(encr_data->encryptedContentInfo.encryptedContent, &ba_encrypted));

    if (oid_is_equal(OID_PKCS5_PBES2, oid)) {
        CHECK_NOT_NULL(pbes2 = asn_any2type(p_content_aid->parameters, get_PBES2_params_desc()));
        DO(pbes2_crypt(DIRECTION_DECRYPT, pbes2, pass, ba_encrypted, data));
    } else if (oid_is_equal(OID_PBE_WITH_SHA1_TDES_CBC, oid)) {
        CHECK_NOT_NULL(pbkdf2 = asn_any2type(p_content_aid->parameters, get_PBKDF2_params_desc()));
        DO(pbes1_crypt(DIRECTION_DECRYPT, pbkdf2, pass, ba_encrypted, data));
    } else {
        SET_ERROR(RET_CM_UNSUPPORTED_CIPHER_ALG);
    }

cleanup:
    free(oid);
    ba_free(ba_encrypted);
    asn_free(get_EncryptedData_desc(), encr_data);
    asn_free(get_PBES2_params_desc(), pbes2);
    asn_free(get_PBKDF2_params_desc(), pbkdf2);
    return ret;
}   //  pkcs12_read_encrypted_content

int pkcs12_read_cert_bag (const ANY_t * bagValue, ByteArray ** baCert, bool * isSdsiCert)
{
    int ret = RET_OK;
    CertBag_t *cert_bag = NULL;
    OCTET_STRING_t *octet_string = NULL;

    CHECK_PARAM(bagValue != NULL);
    CHECK_PARAM(baCert != NULL);
    CHECK_PARAM(isSdsiCert != NULL);

    CHECK_NOT_NULL(cert_bag = asn_any2type(bagValue, get_CertBag_desc()));

    if (OID_is_equal_oid(&cert_bag->certId, OID_PKCS9_X509_CERTIFICATE)) {
        *isSdsiCert = false;
        CHECK_NOT_NULL(octet_string = asn_any2type(&cert_bag->certValue, get_OCTET_STRING_desc()));
        DO(asn_OCTSTRING2ba(octet_string, baCert));
    }
    else if (OID_is_equal_oid(&cert_bag->certId, OID_PKCS9_SDSI_CERTIFICATE)) {
        *isSdsiCert = true;
    }
    else {
        SET_ERROR(RET_CM_INVALID_SAFE_BAG);
    }

cleanup:
    asn_free(get_OCTET_STRING_desc(), octet_string);
    asn_free(get_CertBag_desc(), cert_bag);
    return ret;
}   //  pkcs12_read_cert_bag

int pkcs12_read_shrouded_key_bag (const ANY_t * bagValue, const char * pass, ByteArray ** baPrivateKeyInfo, char ** oidKdf, char ** oidCipher)
{
    int ret = RET_OK;
    ByteArray * ba_data = NULL;

    CHECK_PARAM(bagValue != NULL);
    CHECK_PARAM(pass != NULL);
    CHECK_PARAM(baPrivateKeyInfo != NULL);

    DO(asn_encode_ba(get_ANY_desc(), bagValue, &ba_data));
    DO(pkcs8_decrypt(ba_data, pass, baPrivateKeyInfo, oidKdf, oidCipher));

cleanup:
    ba_free(ba_data);
    return ret;
}   //  pkcs12_read_shrouded_key_bag

int pkcs12_write_cert_bag (const ByteArray * baCert, ByteArray ** baEncoded)
{
    int ret = RET_OK;
    CertBag_t *cert_bag = NULL;
    OCTET_STRING_t *octet_string = NULL;

    CHECK_PARAM(baCert != NULL);
    CHECK_PARAM(baEncoded != NULL);

    DO(asn_create_octstring_from_ba(baCert, &octet_string));

    ASN_ALLOC(cert_bag);
    DO(asn_set_oid_from_text(OID_PKCS9_X509_CERTIFICATE, &cert_bag->certId));
    DO(asn_set_any(get_OCTET_STRING_desc(), octet_string, &cert_bag->certValue));
    DO(asn_encode_ba(get_CertBag_desc(), cert_bag, baEncoded));

cleanup:
    asn_free(get_OCTET_STRING_desc(), octet_string);
    asn_free(get_CertBag_desc(), cert_bag);
    return ret;
}   //  pkcs12_write_cert_bag 

int pkcs12_write_safecontents (const ByteArray ** baEncodedBags, const size_t count, ByteArray ** baEncoded)
{
    if (count == 0) return RET_OK;

    int ret = RET_OK;
    SafeBag_t *safe_bag = NULL;
    SafeContents_t *safe_contents = NULL;

    CHECK_PARAM(baEncodedBags != NULL);
    CHECK_PARAM(baEncoded != NULL);
    for (size_t i = 0; i < count; i++) {
        CHECK_PARAM(baEncodedBags[i] != NULL);
    }

    ASN_ALLOC(safe_contents);
    for (size_t i = 0; i < count; i++) {
        CHECK_NOT_NULL(safe_bag = (SafeBag_t*)asn_decode_ba_with_alloc(get_SafeBag_desc(), baEncodedBags[i]));
        ASN_SEQUENCE_ADD(&safe_contents->list, safe_bag);
        safe_bag = NULL;
    }

    DO(asn_encode_ba(get_SafeContents_desc(), safe_contents, baEncoded));

cleanup:
    asn_free(get_SafeBag_desc(), safe_bag);
    asn_free(get_SafeContents_desc(), safe_contents);
    return ret;
}   //  pkcs12_write_safecontents

int pkcs12_add_p7data_single_safecontent (AuthenticatedSafe_t * authentSafe, const ByteArray * baEncodedBag)
{
    int ret = RET_OK;
    SafeBag_t *safe_bag = NULL;
    SafeContents_t *safe_contents = NULL;
    ContentInfo_t *cinfo = NULL;
    ByteArray *ba_data = NULL;

    CHECK_PARAM(authentSafe != NULL);
    CHECK_PARAM(baEncodedBag != NULL);

    CHECK_NOT_NULL(safe_bag = asn_decode_ba_with_alloc(get_SafeBag_desc(), baEncodedBag));

    ASN_ALLOC(safe_contents);
    ASN_SEQUENCE_ADD(&safe_contents->list, safe_bag);
    safe_bag = NULL;

    DO(asn_encode_ba(get_SafeContents_desc(), safe_contents, &ba_data));

    ASN_ALLOC(cinfo);
    DO(cinfo_init_by_data(cinfo, ba_data));
    ba_data = NULL;

    ASN_SEQUENCE_ADD(&authentSafe->list, cinfo);
    cinfo = NULL;

cleanup:
    asn_free(get_SafeBag_desc(), safe_bag);
    asn_free(get_SafeContents_desc(), safe_contents);
    asn_free(get_ContentInfo_desc(), cinfo);
    ba_free(ba_data);
    return ret;
}   //  pkcs12_p7data_add_single_safecontent

int pkcs12_add_p7encrypteddata (AuthenticatedSafe_t * authentSafe, const ByteArray * baEncryptedBytes)
{
    int ret = RET_OK;
    EncryptedPrivateKeyInfo_t* encrypted_pkinfo = NULL;//but stored in struct EncryptedPrivateKeyInfo
    EncryptedData_t* encrypted_data = NULL;
    ContentInfo_t* cinfo = NULL;

    CHECK_PARAM(authentSafe != NULL);
    CHECK_PARAM(baEncryptedBytes != NULL);

    CHECK_NOT_NULL(encrypted_pkinfo = asn_decode_ba_with_alloc(get_EncryptedPrivateKeyInfo_desc(), baEncryptedBytes));

    ASN_ALLOC(encrypted_data);
    DO(asn_ulong2INTEGER(&encrypted_data->version, Version_v1));
    EncryptedContentInfo_t* encr_content = &encrypted_data->encryptedContentInfo;
    DO(asn_set_oid_from_text(OID_PKCS7_DATA, &encr_content->contentType));
    DO(asn_copy(get_AlgorithmIdentifier_desc(), &encrypted_pkinfo->encryptionAlgorithm, &encr_content->contentEncryptionAlgorithm));
    encr_content->encryptedContent = asn_copy_with_alloc(get_OCTET_STRING_desc(), &encrypted_pkinfo->encryptedData);
    CHECK_NOT_NULL(encr_content->encryptedContent);

    ASN_ALLOC(cinfo);
    DO(cinfo_init_by_encrypted_data(cinfo, encrypted_data));
    encrypted_data = NULL;

    ASN_SEQUENCE_ADD(&authentSafe->list, cinfo);
    cinfo = NULL;

cleanup:
    asn_free(get_EncryptedPrivateKeyInfo_desc(), encrypted_pkinfo);
    asn_free(get_EncryptedData_desc(), encrypted_data);
    asn_free(get_ContentInfo_desc(), cinfo);
    return ret;
}   //  pkcs12_add_p7encrypteddata

int pkcs12_gen_macdata (const char * password, const char * hash, const size_t iterations,
        const ByteArray * baData, MacData_t ** macData)
{
    DEBUG_OUTCON( printf("pkcs12_gen_macdata(), password: '%s', hash: '%s', iterations: %d\n", password, hash, (int)iterations); );
    int ret = RET_OK;
    HashAlg hash_alg = HASH_ALG_UNDEFINED;
    ByteArray* ba_salt = NULL;
    ByteArray* ba_dk = NULL;
    ByteArray* ba_macvalue = NULL;
    MacData_t* mac_data = NULL;
    NULL_t* null_params = NULL;

    CHECK_PARAM(password != NULL);
    CHECK_PARAM(hash != NULL);
    CHECK_PARAM(iterations != 0);
    CHECK_PARAM(baData != NULL);
    CHECK_PARAM(macData != NULL);

    hash_alg = hash_from_oid(hash);
    if (hash_alg == HASH_ALG_UNDEFINED) {
        SET_ERROR(RET_CM_UNSUPPORTED_ALG);
    }

    CHECK_NOT_NULL(ba_salt = ba_alloc_by_len(20));
    DO(drbg_random(ba_salt));
    DEBUG_OUTCON( printf("pkcs12_gen_macdata(), ba_salt: \n"); ba_print(stdout, ba_salt); );

    DO(pbkdf1(password, ba_salt, 3, iterations, 0, hash_alg, &ba_dk));
    DO(pkcs12_calc_hmac(hash_alg, ba_dk, baData, &ba_macvalue));
    DEBUG_OUTCON( printf("pkcs12_gen_macdata(), ba_macvalue: \n"); ba_print(stdout, ba_macvalue); );

    ASN_ALLOC(mac_data);
    ASN_ALLOC(mac_data->iterations);
    ASN_ALLOC(null_params);
    DO(asn_set_oid_from_text(hash, &mac_data->mac.digestAlgorithm.algorithm));
    DO(asn_create_any(get_NULL_desc(), null_params, &mac_data->mac.digestAlgorithm.parameters));
    DO(asn_ba2OCTSTRING(ba_macvalue, &mac_data->mac.digest));
    DO(asn_ba2OCTSTRING(ba_salt, &mac_data->macSalt));
    DO(asn_ulong2INTEGER(mac_data->iterations, (unsigned long)iterations));

    *macData = mac_data;
    mac_data = NULL;

cleanup:
    ba_free(ba_salt);
    ba_free(ba_dk);
    ba_free(ba_macvalue);
    asn_free(get_MacData_desc(), mac_data);
    asn_free(get_NULL_desc(), null_params);
    return ret;
}   //  pkcs12_gen_macdata

int pkcs12_write_pfx (const ByteArray * baAuthsafe, const MacData_t * macData, ByteArray ** baEncoded)
{
    int ret = RET_OK;
    PFX_t* pfx = NULL;

    CHECK_PARAM(baAuthsafe != NULL);
    CHECK_PARAM(macData != NULL);
    CHECK_PARAM(baEncoded != NULL);

    ASN_ALLOC(pfx);
    DO(asn_ulong2INTEGER(&pfx->version, 3));
    DO(cinfo_init_by_data(&pfx->authSafe, baAuthsafe));
    CHECK_NOT_NULL(pfx->macData = asn_copy_with_alloc(get_MacData_desc(), macData));

    DO(asn_encode_ba(get_PFX_desc(), pfx, baEncoded));

cleanup:
    asn_free(get_PFX_desc(), pfx);
    return ret;
}   //  pkcs12_write_pfx

static int os_swap (OCTET_STRING_t* os)
{
    int ret = RET_OK;
    uint8_t tmp;

    CHECK_PARAM(os != NULL);
    
    for (int i = 0, j = os->size - 1; i < j; i++, j--) {
        tmp = os->buf[i];
        os->buf[i] = os->buf[j];
        os->buf[j] = tmp;
    }

cleanup:
    return ret;
}

static int os_swap_bits (OCTET_STRING_t* os)
{
    int ret = RET_OK;
    uint8_t byte;
    uint8_t swapped_byte;

    CHECK_PARAM(os != NULL);

    for (size_t i = 0; i < os->size; i++) {
        byte = os->buf[i];
        swapped_byte = 0;
        for (uint8_t j = 0; j < 8; j++) {
            swapped_byte |= ((byte >> j) & 0x01) << (7 - j);
        }
        os->buf[i] = swapped_byte;
    }

cleanup:
    return ret;
}

static const Attribute_t* pkcs12_attrs_get_attr_by_oid(const Attributes_t* attrs, const char* oidType)
{
    if ((attrs != NULL) && (oidType != NULL)) {
        for (int i = 0; i < attrs->list.count; i++) {
            const Attribute_t* attr = attrs->list.array[i];
            if (OID_is_equal_oid(&attr->type, oidType))
                return attr;
        }
    }
    return NULL;
}

int pkcs12_iit_read_kep_key (const ByteArray * baPrivkey, ByteArray ** baKepPrivkey)
{
    int ret = RET_OK;
    PrivateKeyInfo_t* src_privkey = NULL;
    PrivateKeyInfo_t* dst_privkey = NULL;
    KepDSTU4145Params_t* kep_dstu4145params = NULL;
    DSTU4145Params_t* dstu4145_params = NULL;
    DSTUEllipticCurve_t* dstu_ecparam = NULL;
    BIT_STRING_t* bs_kep_privkey = NULL;
    const Attribute_t* attr = NULL;

    CHECK_PARAM(baPrivkey != NULL);
    CHECK_PARAM(baKepPrivkey != NULL);

    CHECK_NOT_NULL(src_privkey = (PrivateKeyInfo_t*)asn_decode_ba_with_alloc(get_PrivateKeyInfo_desc(), baPrivkey));

    CHECK_NOT_NULL(attr = pkcs12_attrs_get_attr_by_oid(src_privkey->attributes, OID_IIT_KEYSTORE_ATTR_KEP_PRIVKEY));
    CHECK_NOT_NULL(bs_kep_privkey = asn_any2type(attr->value.list.array[0], get_BIT_STRING_desc()));

    CHECK_NOT_NULL(attr = pkcs12_attrs_get_attr_by_oid(src_privkey->attributes, OID_IIT_KEYSTORE_ATTR_KEP_SPKI));
    CHECK_NOT_NULL(kep_dstu4145params = asn_any2type(attr->value.list.array[0], get_KepDSTU4145Params_desc()));

    ASN_ALLOC(dstu4145_params);
    CHECK_NOT_NULL(dstu_ecparam = asn_any2type(&kep_dstu4145params->params, get_DSTUEllipticCurve_desc()));
    DO(asn_copy(get_DSTUEllipticCurve_desc(), dstu_ecparam, &dstu4145_params->ellipticCurve));
    CHECK_NOT_NULL(dstu4145_params->dke = asn_copy_with_alloc(get_OCTET_STRING_desc(), &kep_dstu4145params->kekDke));
    
    if (dstu4145_params->ellipticCurve.present == DSTUEllipticCurve_PR_ecbinary) {
        ECBinary_t* ec_binary = &dstu4145_params->ellipticCurve.choice.ecbinary;
        if (ec_binary->f.member->present == member_PR_pentanomial) {
            Pentanomial_t* penta = &ec_binary->f.member->choice.pentanomial;
            unsigned long penta_K, penta_L;
            DO(asn_INTEGER2ulong(&penta->k, &penta_K));
            DO(asn_INTEGER2ulong(&penta->l, &penta_L));
            DO(asn_ulong2INTEGER(&penta->k, penta_L));
            DO(asn_ulong2INTEGER(&penta->l, penta_K));
        }
        DO(os_swap(&ec_binary->b));
        DO(os_swap(&ec_binary->bp));
    }

    ASN_ALLOC(dst_privkey);
    DO(asn_copy(get_OBJECT_IDENTIFIER_desc(), &src_privkey->privateKeyAlgorithm.algorithm, &dst_privkey->privateKeyAlgorithm.algorithm));
    DO(asn_create_any(get_DSTU4145Params_desc(), dstu4145_params, &dst_privkey->privateKeyAlgorithm.parameters));
    DO(asn_bytes2OCTSTRING(&dst_privkey->privateKey, bs_kep_privkey->buf, bs_kep_privkey->size));
    DO(os_swap_bits(&dst_privkey->privateKey));

    DO(asn_encode_ba(get_PrivateKeyInfo_desc(), dst_privkey, baKepPrivkey));

cleanup:
    asn_free(get_PrivateKeyInfo_desc(), src_privkey);
    asn_free(get_PrivateKeyInfo_desc(), dst_privkey);
    asn_free(get_KepDSTU4145Params_desc(), kep_dstu4145params);
    asn_free(get_DSTU4145Params_desc(), dstu4145_params);
    asn_free(get_DSTUEllipticCurve_desc(), dstu_ecparam);
    asn_free(get_BIT_STRING_desc(), bs_kep_privkey);

    return ret;
}   //  pkcs12_iit_read_kep_key

