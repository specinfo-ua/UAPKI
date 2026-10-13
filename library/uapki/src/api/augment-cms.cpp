/*
 * Copyright (c) 2026, The UAPKI Project Authors.
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

#include "api-json-internal.h"
#include "archive-timestamp-v3.h"
#include "cms-augment.h"
#include "der-helper.h"
#include "doc-sign.h"
#include "http-helper.h"
#include "oid-utils.h"
#include "parson-helper.h"
#include "signeddata-helper.h"
#include "time-util.h"
#include "tsp-helper.h"
#include "uapki-errors.h"
#include "uapki-ns-util.h"
#include <algorithm>


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


using namespace std;
using namespace UapkiNS;


namespace UapkiNS {

namespace Doc {

namespace Augment {


static const char* OID_RI_OCSP_RESPONSE = "1.3.6.1.5.5.7.16.2";   //  RFC 5940


static bool has_attr (
        const vector<Attribute>& attrs,
        const char* type
)
{
    for (const auto& it : attrs) {
        if (it.type == string(type)) return true;
    }
    return false;
}

template <typename T>
static bool contains (
        const T& items,
        const ByteArray* item
)
{
    for (const auto& it : items) {
        if (ba_cmp(it, item) == 0) return true;
    }
    return false;
}

static void add_unique (
        VectorBA& items,
        const vector<const ByteArray*>& present,
        const ByteArray* item
)
{
    if (!item || contains(present, item) || contains(items, item)) return;
    ByteArray* ba = ba_copy_with_alloc(item, 0, 0);
    if (ba) {
        items.push_back(ba);
    }
}

static vector<uint8_t> to_vector (
        const ByteArray* ba
)
{
    return vector<uint8_t>(ba_get_buf_const(ba), ba_get_buf_const(ba) + ba_get_len(ba));
}

//  Attribute ::= SEQUENCE { attrType, attrValues SET OF AttributeValue } with one value, DER
static int encode_attribute (
        const char* type,
        const ByteArray* baValue,
        vector<uint8_t>& encoded
)
{
    SmartBA sba_oid;
    const int ret = Util::encodeOid(type, &sba_oid);
    if (ret != RET_OK) return ret;

    vector<uint8_t> body = to_vector(sba_oid.get());
    const vector<uint8_t> values = Der::wrap(0x31, to_vector(baValue));
    body.insert(body.end(), values.begin(), values.end());
    encoded = Der::wrap(0x30, body);
    return RET_OK;
}

//  RevocationInfoChoice other [1] IMPLICIT OtherRevocationInfoFormat { id-ri-ocsp-response, OCSPResponse }
static ByteArray* ri_ocsp_response (
        const ByteArray* baOcspResponse
)
{
    SmartBA sba_oid;
    if (Util::encodeOid(OID_RI_OCSP_RESPONSE, &sba_oid) != RET_OK) return nullptr;
    vector<uint8_t> body = to_vector(sba_oid.get());
    const vector<uint8_t> resp = to_vector(baOcspResponse);
    body.insert(body.end(), resp.begin(), resp.end());
    const vector<uint8_t> rv = Der::wrap(0xA1, body);
    return ba_alloc_from_uint8(rv.data(), rv.size());
}

//  An unsigned attribute added to an encoded SignerInfo, the other bytes kept as they are
static int signer_info_add_unsigned_attr (
        const ByteArray* baSignerInfo,
        const vector<uint8_t>& encodedAttr,
        ByteArray** baResult
)
{
    vector<vector<uint8_t>> sinfo;
    if (!Der::children(ba_get_buf_const(baSignerInfo), ba_get_len(baSignerInfo), sinfo) || sinfo.empty()) {
        return RET_UAPKI_INVALID_STRUCT;
    }

    vector<uint8_t> unsigned_attrs;
    if (sinfo.back()[0] == 0xA1) {
        size_t lh = 0, lb = 0;
        (void)Der::read(sinfo.back().data(), sinfo.back().size(), lh, lb);
        unsigned_attrs.assign(sinfo.back().begin() + lh, sinfo.back().end());
        sinfo.pop_back();
    }
    unsigned_attrs.insert(unsigned_attrs.end(), encodedAttr.begin(), encodedAttr.end());
    sinfo.push_back(Der::wrap(0xA1, unsigned_attrs));

    vector<uint8_t> body;
    for (const auto& it : sinfo) {
        body.insert(body.end(), it.begin(), it.end());
    }
    const vector<uint8_t> rv = Der::wrap(0x30, body);
    *baResult = ba_alloc_from_uint8(rv.data(), rv.size());
    return (*baResult) ? RET_OK : RET_UAPKI_GENERAL_ERROR;
}

//  Unsigned attributes added to the token of the last archive-time-stamp-v3 of an encoded SignerInfo, the other
//  bytes kept as they are
static int signer_info_add_attrs_to_last_archive_token (
        const ByteArray* baSignerInfo,
        const vector<vector<uint8_t>>& encodedAttrs,
        ByteArray** baResult
)
{
    vector<vector<uint8_t>> sinfo, attrs;
    if (
        !Der::children(ba_get_buf_const(baSignerInfo), ba_get_len(baSignerInfo), sinfo) || sinfo.empty() ||
        (sinfo.back()[0] != 0xA1) || !Der::children(sinfo.back().data(), sinfo.back().size(), attrs)
    ) return RET_UAPKI_INVALID_STRUCT;

    SmartBA sba_oid;
    int ret = Util::encodeOid(OID_ETSI_ARCHIVE_TIMESTAMP_V3, &sba_oid);
    if (ret != RET_OK) return ret;
    const vector<uint8_t> oid = to_vector(sba_oid.get());

    size_t idx = attrs.size();
    vector<vector<uint8_t>> type_values, values;
    for (size_t i = attrs.size(); i > 0; i--) {
        type_values.clear();
        if (!Der::children(attrs[i - 1].data(), attrs[i - 1].size(), type_values) || (type_values.size() != 2)) return RET_UAPKI_INVALID_STRUCT;
        if (type_values[0] == oid) {
            idx = i - 1;
            break;
        }
    }
    if ((idx == attrs.size()) || !Der::children(type_values[1].data(), type_values[1].size(), values) || (values.size() != 1)) {
        return RET_UAPKI_INVALID_STRUCT;
    }

    SmartBA sba_token, sba_newtoken;
    ByteArray* ba_newtoken = nullptr;
    if (!sba_token.set(ba_alloc_from_uint8(values[0].data(), values[0].size()))) return RET_UAPKI_GENERAL_ERROR;
    ret = Doc::Sign::addUnsignedAttrsToToken(sba_token.get(), encodedAttrs, &ba_newtoken);
    (void)sba_newtoken.set(ba_newtoken);
    if (ret != RET_OK) return ret;

    vector<uint8_t> attr_body = oid;
    const vector<uint8_t> new_values = Der::wrap(0x31, to_vector(sba_newtoken.get()));
    attr_body.insert(attr_body.end(), new_values.begin(), new_values.end());
    attrs[idx] = Der::wrap(0x30, attr_body);

    vector<uint8_t> unsigned_attrs, body;
    for (const auto& it : attrs) {
        unsigned_attrs.insert(unsigned_attrs.end(), it.begin(), it.end());
    }
    sinfo.back() = Der::wrap(0xA1, unsigned_attrs);
    for (const auto& it : sinfo) {
        body.insert(body.end(), it.begin(), it.end());
    }
    const vector<uint8_t> rv = Der::wrap(0x30, body);
    *baResult = ba_alloc_from_uint8(rv.data(), rv.size());
    return (*baResult) ? RET_OK : RET_UAPKI_GENERAL_ERROR;
}

//  The SignedData with the certificates and the revocation data added and, for the SignerInfo idxSigner,
//  an unsigned attribute added (encodedAttr is not empty) or attributes added to the token of its last
//  archive time-stamp (tokenAttrs is not empty). The encoding of the SignerInfos is kept
static int rebuild_signed_data (
        const ByteArray* baSignature,
        const VectorBA& addCerts,
        const VectorBA& addCrls,
        const size_t idxSigner,
        const vector<uint8_t>& encodedAttr,
        SmartBA& sbaResult,
        const vector<vector<uint8_t>>& tokenAttrs = vector<vector<uint8_t>>()
)
{
    int ret = RET_OK;
    Pkcs7::SignedDataParser sdata_parser;
    Pkcs7::SignedDataBuilder sdata_builder;
    uint32_t version = 0;
    bool has_other = false;

    DO(sdata_parser.parse(baSignature));
    DO(sdata_builder.init());

    for (const auto& it : sdata_parser.getCerts()) {
        DO(sdata_builder.addCertificate(it));
    }
    for (const auto& it : addCerts) {
        DO(sdata_builder.addCertificate(it));
    }
    {
        const VectorBA* crl_lists[] = { &sdata_parser.getCrls(), &addCrls };
        for (const VectorBA* crls : crl_lists) {
            for (const auto& it : *crls) {
                DO(sdata_builder.addCrl(it));
                has_other |= (ba_get_len(it) > 0) && (ba_get_buf_const(it)[0] == 0xA1);
            }
        }
    }

    for (size_t i = 0; i < sdata_parser.getCountSignerInfos(); i++) {
        SmartBA sba_signerinfo, sba_modified;
        DO(sdata_parser.encodeSignerInfo(i, &sba_signerinfo));
        if ((i == idxSigner) && !encodedAttr.empty()) {
            DO(signer_info_add_unsigned_attr(sba_signerinfo.get(), encodedAttr, &sba_modified));
            (void)sba_signerinfo.set(sba_modified.pop());
        }
        if ((i == idxSigner) && !tokenAttrs.empty()) {
            DO(signer_info_add_attrs_to_last_archive_token(sba_signerinfo.get(), tokenAttrs, &sba_modified));
            (void)sba_signerinfo.set(sba_modified.pop());
        }
        DO(sdata_builder.addSignerInfo());
        DO(sdata_builder.getSignerInfo(sdata_builder.getCountSignerInfos() - 1)->fillFromEncoded(sba_signerinfo.get()));
    }

    //  RFC 5652, 5.1: the version is 5 if crls contain the other revocation info format
    version = sdata_parser.getVersion();
    if (has_other) {
        version = 5;
    }
    DO(sdata_builder.setVersion(version));
    DO(sdata_builder.setEncapContentInfo(sdata_parser.getEncapContentInfo()));
    DO(sdata_builder.encode());
    (void)sbaResult.set(sdata_builder.getEncoded(true));

cleanup:
    return ret;
}

//  The TSA of the signer as SIGN does (Doc::Sign::tspUris)
struct TspUris {
    vector<string> uris;
    vector<string> fallbackUris;
};

static TspUris tsp_uris (
        LibraryConfig* libConfig,
        Cert::CerStore* cerStore,
        const Pkcs7::SignedDataParser& sdataParser,
        const Pkcs7::SignedDataParser::SignerInfo& signerInfo
)
{
    TspUris rv;
    vector<Cert::CerStore::AddedCerItem> added_ceritems;
    Cert::CerItem* cer_signer = nullptr;
    (void)cerStore->addCerts(Cert::NOT_TRUSTED, Cert::NOT_PERMANENT, sdataParser.getCerts(), added_ceritems);
    (void)cerStore->getCertBySID(signerInfo.getSidEncoded(), &cer_signer);
    Doc::Sign::tspUris(libConfig->getTsp(), cer_signer, rv.uris, rv.fallbackUris);
    return rv;
}

//  A time-stamp token of the hash (RFC 3161) from the TSA of the signer
static int request_timestamp (
        LibraryConfig* libConfig,
        Cert::CerStore* cerStore,
        Crl::CrlStore* crlStore,
        const TspUris& uris,
        const AlgorithmIdentifier& aidDigest,
        const ByteArray* baHash,
        SmartBA& sbaToken
)
{
    int ret = RET_OK;
    const LibraryConfig::TspParams& tsp_params = libConfig->getTsp();
    CertValidator::CertValidator cert_validator;
    Tsp::TspHelper tsp_helper;
    SmartBA sba_resp;
    Cert::CerItem* cer_signer = nullptr;

    string tsp_uri;
    if (libConfig->getOffline()) return RET_UAPKI_OFFLINE_MODE;
    if (uris.uris.empty() && uris.fallbackUris.empty()) return RET_UAPKI_TSP_URL_NOT_PRESENT;
    if (!cert_validator.init(libConfig, cerStore, crlStore)) return RET_UAPKI_GENERAL_ERROR;

    DO(tsp_helper.init());
    DO(tsp_helper.setMessageImprint(aidDigest, baHash));
    if (tsp_params.nonceLen > 0) {
        DO(tsp_helper.genNonce(tsp_params.nonceLen));
    }
    DO(tsp_helper.setCertReq(tsp_params.certReq));
    DO(tsp_helper.setReqPolicy(tsp_params.policyId));
    DO(tsp_helper.encodeRequest());

    DO(Doc::Sign::requestTimestamp(libConfig->getHttp(), uris.uris, uris.fallbackUris, tsp_helper, tsp_uri));
    DO(Doc::Sign::verifySignedData(cert_validator, tsp_helper.getTsToken(), &cer_signer));
    DO(tsp_helper.tstInfoIsEqualRequest());

    (void)sbaToken.set(tsp_helper.getTsToken(true));

cleanup:
    return ret;
}

int addArchiveTimeStamp (
        LibraryConfig* libConfig,
        Cert::CerStore* cerStore,
        Crl::CrlStore* crlStore,
        const ByteArray* baSignature,
        const size_t idxSigner,
        const Pkcs7::AtsV3::IndexType indexType,
        ByteArray** baResult
)
{
    int ret = RET_OK;
    Pkcs7::SignedDataParser sdata_parser;
    Pkcs7::SignedDataParser::SignerInfo signer_info;
    SmartBA sba_hashindex, sba_hash, sba_token, sba_tokenindex, sba_next;
    vector<uint8_t> encoded_index, encoded_attr;
    ByteArray* ba_token = nullptr;

    if (!baSignature || !baResult) return RET_UAPKI_INVALID_PARAMETER;

    DO(sdata_parser.parse(baSignature));
    if (idxSigner >= sdata_parser.getCountSignerInfos()) {
        SET_ERROR(RET_UAPKI_INDEX_OUT_OF_RANGE);
    }
    DO(sdata_parser.parseSignerInfo(idxSigner, signer_info));
    {
        //  The hash algorithm of the index and of the message imprint: the digest algorithm of the signature
        const AlgorithmIdentifier& aid_digest = signer_info.getDigestAlgorithm();
        const HashAlg hash_alg = hash_from_oid(aid_digest.algorithm.c_str());
        if (hash_alg == HASH_ALG_UNDEFINED) {
            SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
        }
        DO(Pkcs7::AtsV3::buildHashIndex(
            indexType,
            aid_digest.algorithm,
            sdata_parser.getCerts(),
            sdata_parser.getCrls(),
            signer_info.getAsn1Data(),
            &sba_hashindex
        ));
        //  The hash of the signed data by the digest algorithm of the signature: its message-digest
        DO(Pkcs7::AtsV3::calcMessageImprint(
            hash_alg,
            signer_info.getContentType(),
            signer_info.getMessageDigest(),
            signer_info.getAsn1Data(),
            sba_hashindex.get(),
            &sba_hash
        ));
        DO(request_timestamp(libConfig, cerStore, crlStore, tsp_uris(libConfig, cerStore, sdata_parser, signer_info),
            aid_digest, sba_hash.get(), sba_token));
    }

    DO(encode_attribute(Pkcs7::AtsV3::indexAttrType(indexType), sba_hashindex.get(), encoded_index));
    DO(Doc::Sign::addUnsignedAttrsToToken(sba_token.get(), { encoded_index }, &ba_token));
    (void)sba_tokenindex.set(ba_token);

    DO(encode_attribute(OID_ETSI_ARCHIVE_TIMESTAMP_V3, sba_tokenindex.get(), encoded_attr));
    DO(rebuild_signed_data(baSignature, VectorBA(), VectorBA(), idxSigner, encoded_attr, sba_next));
    *baResult = sba_next.pop();

cleanup:
    return ret;
}

int augmentCms (
        LibraryConfig* libConfig,
        Cert::CerStore* cerStore,
        Crl::CrlStore* crlStore,
        const ByteArray* baSignature,
        ContentHasher& contentHasher,
        const bool isDigest,
        const Params& params,
        ByteArray** baAugmented,
        JSON_Object* joResult,
        vector<string>* warnings
)
{
    if (!libConfig || !cerStore || !crlStore || !baSignature || !baAugmented) return RET_UAPKI_INVALID_PARAMETER;
    switch (params.signatureFormat) {
    case SignatureFormat::CADES_T:
    case SignatureFormat::CADES_B_LT:
    case SignatureFormat::CADES_B_LTA:
    case SignatureFormat::CADES_A:
        break;
    default:
        return RET_UAPKI_INVALID_PARAMETER;
    }
    //  CAdES-A: a new archive-time-stamp-v3 on a signature with the attributes of TS 101 733 (C, X-L, A)
    const bool is_target_a = (params.signatureFormat == SignatureFormat::CADES_A);

    int ret = RET_OK;
    SmartBA sba_current;
    vector<size_t> signer_indexes;
    vector<string> augment_warnings;
    bool has_archive_ts_noindex = false;
    VectorBA add_certs, add_crls, add_ocsp_basics;
    Verify::VerifyOptions verify_options;

    if (!sba_current.set(ba_copy_with_alloc(baSignature, 0, 0))) return RET_UAPKI_GENERAL_ERROR;

    {   //  The signers to augment: the attributes of the validation data of TS 101 733 (C, X-L) are not in
        //  B-LT/B-LTA (EN 319 122-1, table 1). A new archive-time-stamp on B-LTA: re-archiving (EN 319 102-1, 4.3.5)
        Pkcs7::SignedDataParser sdata_parser;
        DO(sdata_parser.parse(sba_current.get()));
        const size_t cnt_signers = sdata_parser.getCountSignerInfos();
        if (cnt_signers == 0) {
            SET_ERROR(RET_UAPKI_INVALID_STRUCT);
        }
        if ((params.signerInfoIndex >= 0) && ((size_t)params.signerInfoIndex >= cnt_signers)) {
            SET_ERROR(RET_UAPKI_INDEX_OUT_OF_RANGE);
        }
        for (size_t i = 0; i < cnt_signers; i++) {
            Pkcs7::SignedDataParser::SignerInfo signer_info;
            DO(sdata_parser.parseSignerInfo(i, signer_info));
            const vector<Attribute>& attrs = signer_info.getUnsignedAttrs();
            //  An archive time-stamp without its hash index (an earlier CAdES-A of the library) protects the
            //  certificates and crls as they are: they are not changed
            for (const auto& it : attrs) {
                //  archive-time-stamp of TS 101 733, 6.4.1 covers the SignedData as it is encoded
                if (it.type == string(OID_PKCS9_ARCHIVE_TIMESTAMP_V2)) {
                    SET_ERROR(RET_UAPKI_NOT_SUPPORTED);
                }
                if (it.type != string(OID_ETSI_ARCHIVE_TIMESTAMP_V3)) continue;
                Verify::AttrTimeStamp archive_ts;
                Pkcs7::AtsV3::IndexType index_type;
                if ((archive_ts.parse(it.baValues) != RET_OK) || !archive_ts.getAtsHashIndex(index_type)) {
                    has_archive_ts_noindex = true;
                }
            }
            if ((params.signerInfoIndex >= 0) && ((size_t)params.signerInfoIndex != i)) continue;

            bool has_ts101733_attrs = false;
            for (const char* oid : {
                OID_PKCS9_CERTIFICATE_REFS, OID_PKCS9_REVOCATION_REFS, OID_PKCS9_CERT_VALUES,
                OID_PKCS9_REVOCATION_VALUES, OID_PKCS9_CADES_C_TIMESTAMP, OID_PKCS9_CERT_CRL_TIMESTAMP
            }) {
                if (has_attr(attrs, oid)) {
                    has_ts101733_attrs = true;
                    if (!is_target_a) {
                        SET_ERROR(RET_UAPKI_NOT_SUPPORTED);
                    }
                }
            }
            if (is_target_a && !has_ts101733_attrs) {
                SET_ERROR(RET_UAPKI_NOT_SUPPORTED);
            }
            signer_indexes.push_back(i);
        }
    }

    //  T: a signature-time-stamp of the signature value (EN 319 122-1, 5.3)
    for (const auto idx : signer_indexes) {
        Pkcs7::SignedDataParser sdata_parser;
        Pkcs7::SignedDataParser::SignerInfo signer_info;
        DO(sdata_parser.parse(sba_current.get()));
        DO(sdata_parser.parseSignerInfo(idx, signer_info));
        if (has_attr(signer_info.getUnsignedAttrs(), OID_PKCS9_TIMESTAMP_TOKEN)) continue;

        const AlgorithmIdentifier& aid_digest = signer_info.getDigestAlgorithm();
        const HashAlg hash_alg = hash_from_oid(aid_digest.algorithm.c_str());
        SmartBA sba_hash, sba_token, sba_next;
        vector<uint8_t> encoded_attr;
        if (hash_alg == HASH_ALG_UNDEFINED) {
            SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
        }
        DO(::hash(hash_alg, signer_info.getSignature(), &sba_hash));
        DO(request_timestamp(libConfig, cerStore, crlStore, tsp_uris(libConfig, cerStore, sdata_parser, signer_info),
            aid_digest, sba_hash.get(), sba_token));
        DO(encode_attribute(OID_PKCS9_TIMESTAMP_TOKEN, sba_token.get(), encoded_attr));
        DO(rebuild_signed_data(sba_current.get(), VectorBA(), VectorBA(), idx, encoded_attr, sba_next));
        (void)sba_current.set(sba_next.pop());
    }

    if (params.signatureFormat == SignatureFormat::CADES_T) {
        *baAugmented = sba_current.pop();
        return RET_OK;
    }

    {   //  LT: the validation of the signature in its current state (EN 319 102-1, 4.3.4.4), then all the data
        //  used by it that the signature has not (EN 319 122-1, table 1, a - e, o - r)
        verify_options = params.verifyOptions;
        verify_options.validationType = Verify::VerifyOptions::ValidationType::FULL;
        verify_options.verifySignerInfoIndex = params.signerInfoIndex;
        Verify::VerifySignedDoc verify_sdoc(libConfig, cerStore, crlStore, verify_options);
        if (!verify_sdoc.isInitialized()) {
            SET_ERROR(RET_UAPKI_GENERAL_ERROR);
        }
        DO(Verify::verifySignedDocument(verify_sdoc, sba_current.get(), contentHasher, isDigest));

        JSON_Array* ja_signinfos = nullptr;
        if (joResult) {
            DO_JSON(json_object_set_value(joResult, "signatureInfos", json_value_init_array()));
            ja_signinfos = json_object_get_array(joResult, "signatureInfos");
        }
        bool all_valid = true;
        for (const auto idx : signer_indexes) {
            Verify::VerifiedSignerInfo& verified_sinfo = verify_sdoc.verifiedSignerInfos[idx];
            if (ja_signinfos) {
                DO_JSON(json_array_append_value(ja_signinfos, json_value_init_object()));
                DO(Verify::verifiedSignerInfoToJson(
                    json_array_get_object(ja_signinfos, json_array_get_count(ja_signinfos) - 1),
                    verified_sinfo,
                    verify_options
                ));
            }
            all_valid &= verified_sinfo.isTotalValid();
        }
        //  TOTAL-FAILED, or INDETERMINATE (e.g. no revocation data): not augmented
        if (!all_valid) {
            SET_ERROR(RET_UAPKI_NOT_ALLOWED);
        }

        //  What the signature has: in the SignedData and, for CAdES-A, in its attributes certificate-values and
        //  revocation-values
        vector<const ByteArray*> present_certs(verify_sdoc.sdataParser.getCerts().begin(), verify_sdoc.sdataParser.getCerts().end());
        vector<const ByteArray*> present_crls(verify_sdoc.sdataParser.getCrls().begin(), verify_sdoc.sdataParser.getCrls().end());
        if (is_target_a) {
            for (const auto idx : signer_indexes) {
                Verify::CadesXlInfo& xl_info = verify_sdoc.verifiedSignerInfos[idx].getCadesXlInfo();
                present_certs.insert(present_certs.end(), xl_info.certValues.begin(), xl_info.certValues.end());
                const VectorBA& crl_vals = xl_info.revocationValuesParser.getCrlVals();
                present_crls.insert(present_crls.end(), crl_vals.begin(), crl_vals.end());
                const VectorBA& ts_crls = verify_sdoc.verifiedSignerInfos[idx].getTsCrls();
                present_crls.insert(present_crls.end(), ts_crls.begin(), ts_crls.end());
            }
        }
        for (const auto idx : signer_indexes) {
            Verify::VerifiedSignerInfo& verified_sinfo = verify_sdoc.verifiedSignerInfos[idx];
            for (const auto& it : verified_sinfo.getCertChainItems()) {
                //  The certificates, the trust anchor included (EN 319 122-1, table 1, d). CAdES-A: not the ones
                //  the signature has in its time-stamp tokens
                if (!is_target_a || (it->getDataSource() != CertValidator::DataSource::SIGNATURE)) {
                    add_unique(add_certs, present_certs, it->getSubject()->getEncoded());
                }
                if (it->getIssuer() && !is_target_a) {
                    add_unique(add_certs, present_certs, it->getIssuer()->getEncoded());
                }
                switch (it->getValidationType()) {
                case Cert::ValidationType::CRL: {
                    const CertValidator::ResultValidationByCrl& result = it->getResultValidationByCrl();
                    //  The CRL of an OCSP responder (a CRL signer) without id-pkix-ocsp-nocheck: embedded only up to
                    //  INIT ocsp.responderCrlEmbedMaxSize - the size of the signature. A bigger one is not embedded,
                    //  the signature is then not a complete B-LT (EN 319 122-1, table 1, o): a warning
                    if (
                        ((it->getCertEntity() == CertValidator::CertEntity::OCSP) || (it->getCertEntity() == CertValidator::CertEntity::CRL)) && (
                            (result.crlFull && (ba_get_len(result.crlFull->getEncoded()) > libConfig->getOcsp().responderCrlEmbedMaxSize)) ||
                            (result.crlItem && (ba_get_len(result.crlItem->getEncoded()) > libConfig->getOcsp().responderCrlEmbedMaxSize))
                        )
                    ) {
                        const string s_warn = "THE CRL OF THE OCSP RESPONDER IS NOT EMBEDDED (SIZE LIMIT)";
                        if (std::find(augment_warnings.begin(), augment_warnings.end(), s_warn) == augment_warnings.end()) {
                            augment_warnings.push_back(s_warn);
                        }
                        break;
                    }
                    //  A delta CRL with its full CRL (EN 319 122-1, 5.5.3)
                    if (result.crlFull) {
                        add_unique(add_crls, present_crls, result.crlFull->getEncoded());
                    }
                    if (result.crlItem) {
                        add_unique(add_crls, present_crls, result.crlItem->getEncoded());
                    }
                    if (result.cerIssuer) {
                        add_unique(add_certs, present_certs, result.cerIssuer->getEncoded());
                    }
                    break;
                }
                case Cert::ValidationType::OCSP: {
                    const CertValidator::ResultValidationByOcsp& result = it->getResultValidationByOcsp();
                    if (result.dataSource != CertValidator::DataSource::SIGNATURE) {
                        SmartBA sba_resp, sba_ri;
                        if (!result.ocspResponse.empty()) {
                            (void)sba_resp.set(ba_copy_with_alloc(result.ocspResponse.get(), 0, 0));
                        }
                        else {
                            (void)sba_resp.set(Verify::ocspResponseFromBasic(result.basicOcspResponse.get()));
                        }
                        if (!sba_ri.set(ri_ocsp_response(sba_resp.get()))) {
                            SET_ERROR(RET_UAPKI_GENERAL_ERROR);
                        }
                        if (!contains(present_crls, sba_ri.get()) && !contains(add_crls, sba_ri.get())) {
                            add_unique(add_ocsp_basics, vector<const ByteArray*>(), result.basicOcspResponse.get());
                        }
                        add_unique(add_crls, present_crls, sba_ri.get());
                    }
                    if (result.cerResponder) {
                        add_unique(add_certs, present_certs, result.cerResponder->getEncoded());
                    }
                    break;
                }
                default:
                    break;
                }
            }
        }
    }

    if (!add_certs.empty() || !add_crls.empty()) {
        SmartBA sba_next;
        if (!has_archive_ts_noindex) {
            DO(rebuild_signed_data(sba_current.get(), add_certs, add_crls, SIZE_MAX, vector<uint8_t>(), sba_next));
        }
        else {
            //  An earlier form of archive time-stamp (without its hash index) protects the certificates and crls
            //  of the SignedData as they are: they are not changed, the new validation material goes into the
            //  token of the latest archive time-stamp as the attributes certificate-values and revocation-values
            //  (EN 319 122-1, 5.5.3)
            if (!is_target_a || (signer_indexes.size() != 1)) {
                SET_ERROR(RET_UAPKI_NOT_SUPPORTED);
            }
            vector<vector<uint8_t>> token_attrs;
            if (!add_certs.empty()) {
                SmartBA sba_values;
                vector<uint8_t> encoded_attr;
                DO(AttributeHelper::encodeCertValues(vector<const ByteArray*>(add_certs.begin(), add_certs.end()), &sba_values));
                DO(encode_attribute(OID_PKCS9_CERT_VALUES, sba_values.get(), encoded_attr));
                token_attrs.push_back(encoded_attr);
            }
            if (!add_crls.empty()) {
                AttributeHelper::RevocationValuesBuilder revvals_builder;
                vector<const ByteArray*> crl_vals;
                vector<uint8_t> encoded_attr;
                size_t cnt_ocsp = 0;
                for (const auto& it : add_crls) {
                    if (ba_get_buf_const(it)[0] == 0xA1) {
                        cnt_ocsp++;
                    }
                    else {
                        crl_vals.push_back(it);
                    }
                }
                //  Every OCSP response is needed as BasicOCSPResponse
                if (cnt_ocsp != add_ocsp_basics.size()) {
                    SET_ERROR(RET_UAPKI_NOT_SUPPORTED);
                }
                DO(revvals_builder.init());
                if (!crl_vals.empty()) {
                    DO(revvals_builder.setCrlValues(crl_vals));
                }
                if (!add_ocsp_basics.empty()) {
                    DO(revvals_builder.setOcspValues(vector<const ByteArray*>(add_ocsp_basics.begin(), add_ocsp_basics.end())));
                }
                DO(revvals_builder.encode());
                DO(encode_attribute(OID_PKCS9_REVOCATION_VALUES, revvals_builder.getEncoded(), encoded_attr));
                token_attrs.push_back(encoded_attr);
            }
            DO(rebuild_signed_data(sba_current.get(), VectorBA(), VectorBA(), signer_indexes[0], vector<uint8_t>(), sba_next, token_attrs));
        }
        (void)sba_current.set(sba_next.pop());
    }

    //  LTA, A: archive-time-stamp-v3 with ats-hash-index-v3 in its token (EN 319 122-1, 5.5.2, 5.5.3); it covers
    //  the earlier archive time-stamps too (re-archiving)
    if ((params.signatureFormat == SignatureFormat::CADES_B_LTA) || is_target_a) {
        for (const auto idx : signer_indexes) {
            ByteArray* ba_next = nullptr;
            ret = addArchiveTimeStamp(libConfig, cerStore, crlStore, sba_current.get(), idx,
                Pkcs7::AtsV3::IndexType::EN_319_122, &ba_next);
            (void)sba_current.set(ba_next);
            DO(ret);
        }
    }

    *baAugmented = sba_current.pop();

cleanup:
    if (joResult && !augment_warnings.empty()) {
        json_object_set_value(joResult, "warnings", json_value_init_array());
        JSON_Array* ja_warns = json_object_get_array(joResult, "warnings");
        for (const auto& it : augment_warnings) {
            (void)json_array_append_string(ja_warns, it.c_str());
        }
    }
    if (warnings) {
        *warnings = augment_warnings;
    }
    return ret;
}


}   //  end namespace Augment

}   //  end namespace Doc

}   //  end namespace UapkiNS


static int parse_content (
        JSON_Object* joSignature,
        ContentHasher& contentHasher
)
{
    int ret = RET_OK;

    if (ParsonHelper::jsonObjectHasValue(joSignature, "content", JSONString)) {
        DO(contentHasher.setContent(json_object_get_base64(joSignature, "content"), true));
    }
    else if (ParsonHelper::jsonObjectHasValue(joSignature, "file", JSONString)) {
        DO(contentHasher.setContent(json_object_get_string(joSignature, "file")));
    }
    else if (
        ParsonHelper::jsonObjectHasValue(joSignature, "ptr", JSONString) &&
        ParsonHelper::jsonObjectHasValue(joSignature, "size", JSONNumber)
    ) {
        SmartBA sba_ptr;
        (void)sba_ptr.set(json_object_get_hex(joSignature, "ptr"));
        const uint8_t* ptr = ContentHasher::baToPtr(sba_ptr.get());
        size_t size = 0;
        if (!ptr || !ContentHasher::numberToSize(json_object_get_number(joSignature, "size"), size)) {
            SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        }
        DO(contentHasher.setContent(ptr, size));
    }

cleanup:
    return ret;
}

int uapki_augment_cms (
        Context& context,
        JSON_Object* joParams,
        JSON_Object* joResult
)
{
    int ret = RET_OK;
    LibraryConfig* config = context.config();
    JSON_Object* jo_signature = json_object_get_object(joParams, "signature");
    JSON_Object* jo_options = json_object_get_object(joParams, "options");
    SmartBA sba_signature, sba_augmented;
    ContentHasher content_hasher;
    Doc::Augment::Params params;
    ByteArray* ba_augmented = nullptr;

    if (!config || !config->isInitialized()) return RET_UAPKI_NOT_INITIALIZED;

    if (!sba_signature.set(json_object_get_base64(jo_signature, "bytes"))) {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }
    DO(parse_content(jo_signature, content_hasher));

    params.signatureFormat = signatureFormatFromString(ParsonHelper::jsonObjectGetString(joParams, "signatureFormat"));
    params.signerInfoIndex = ParsonHelper::jsonObjectGetInt32(joParams, "signerInfoIndex", -1);
    if (params.signerInfoIndex < 0) {
        params.signerInfoIndex = -1;
    }

    //  The validation as VERIFY (FULL); revocationFreshness: the cached and stored revocation data not issued
    //  within these minutes is obtained again (0 - always new), for a signature without revocation data
    params.verifyOptions.onlyCrl = ParsonHelper::jsonObjectGetBoolean(jo_options, "onlyCrl", config->getValidationByCrl());
    params.verifyOptions.checkCriticalExtensions = ParsonHelper::jsonObjectGetBoolean(jo_options, "checkCriticalExtensions", false);
    params.verifyOptions.caRemovesExpiredCerts = ParsonHelper::jsonObjectGetBoolean(jo_options, "caRemovesExpiredCerts", false);
    {
        const uint32_t freshness = ParsonHelper::jsonObjectGetUint32(
            jo_options, "revocationFreshness", Doc::Augment::REVOCATION_FRESHNESS_MAX
        );
        if (freshness > Doc::Augment::REVOCATION_FRESHNESS_MAX) {
            SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        }
        params.verifyOptions.revocationMinThisUpdate = TimeUtil::mtimeNow() - (uint64_t)freshness * 60000;
    }

    ret = Doc::Augment::augmentCms(
        config,
        context.cerStore(),
        context.crlStore(),
        sba_signature.get(),
        content_hasher,
        ParsonHelper::jsonObjectGetBoolean(jo_signature, "isDigest", false),
        params,
        &ba_augmented,
        joResult
    );
    (void)sba_augmented.set(ba_augmented);
    DO(ret);

    DO(json_object_set_base64(joResult, "bytes", sba_augmented.get()));

cleanup:
    return ret;
}
