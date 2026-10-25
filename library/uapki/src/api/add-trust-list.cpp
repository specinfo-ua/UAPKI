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

#define FILE_MARKER "uapki/api/add-trust-list.cpp"

#include "api-json-internal.h"
#include "cer-store.h"
#include "extension-helper.h"
#include "global-objects.h"
#include "oid-utils.h"
#include "parson-helper.h"
#include "store-json.h"
#include "time-util.h"
#include "uapki-errors.h"
#include "uapki-ns-util.h"
#include "uapki-ns-verify.h"
#include "xml-strict.h"
#include <algorithm>
#include <map>
#include <set>


using namespace std;
using namespace UapkiNS;


namespace {

//  A trusted list of ETSI TS 119 612 (XML, signed with XAdES): the list is accepted when it is signed by a
//  certificate the library is configured to trust (the trusted certificates of INIT, not the ones of another list)
//  and its sequence number is not less than the one of the list accepted before. The certificates of its services
//  go to the certificate cache with what the list says about them.

const char* NS_TSL      = "http://uri.etsi.org/02231/v2#";
const char* NS_DS       = "http://www.w3.org/2000/09/xmldsig#";
const char* NS_XADES    = "http://uri.etsi.org/01903/v1.3.2#";
const char* URI_EXC_C14N        = "http://www.w3.org/2001/10/xml-exc-c14n#";
const char* URI_ENVELOPED       = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const char* URI_SIGNED_PROPS    = "http://uri.etsi.org/01903#SignedProperties";
const char* SVCTYPE_MARK        = "/Svctype/";
//  id-tsl-kp-tslSigning (ETSI TS 119 612)
const char* OID_ETSI_KP_TSL_SIGNING = "0.4.0.2231.3.0";

struct SignatureMethod {
    const char* uriSuffix;      //  after '#' of the SignatureMethod algorithm
    const char* signAlgo;
    bool        ecdsa;          //  the value is r | s (XML Signature), the library takes ECDSA-Sig-Value
};
const SignatureMethod SIGNATURE_METHODS[] = {
    { "dstu4145-dstu7564-256",  OID_DSTU4145_WITH_DSTU7564_256_PB,        false },
    { "dstu4145-dstu7564-384",  OID_DSTU4145_WITH_DSTU7564_384_PB,        false },
    { "dstu4145-dstu7564-512",  OID_DSTU4145_WITH_DSTU7564_512_PB,        false },
    { "rsa-sha256",             "1.2.840.113549.1.1.11",        false },
    { "rsa-sha384",             "1.2.840.113549.1.1.12",        false },
    { "rsa-sha512",             "1.2.840.113549.1.1.13",        false },
    { "ecdsa-sha256",           "1.2.840.10045.4.3.2",        true },
    { "ecdsa-sha384",           "1.2.840.10045.4.3.3",        true },
    { "ecdsa-sha512",           "1.2.840.10045.4.3.4",        true },
};

struct DigestMethod {
    const char* uriSuffix;
    const char* hashAlgo;
};
const DigestMethod DIGEST_METHODS[] = {
    { "sha256",         OID_SHA256 },
    { "sha384",         OID_SHA384 },
    { "sha512",         OID_SHA512 },
    { "dstu7564-256",   OID_DSTU7564_256 },
    { "dstu7564-384",   OID_DSTU7564_384 },
    { "dstu7564-512",   OID_DSTU7564_512 }
};


//  What exactly a list is refused for: goes to the result next to the error
thread_local string tl_detail;

int refused (const int errorCode, const string& detail)
{
    if (tl_detail.empty()) tl_detail = detail;
    return errorCode;
}

string uri_suffix (const string& uri, const char separator = '#')
{
    const size_t pos = uri.rfind(separator);
    return (pos == string::npos) ? uri : uri.substr(pos + 1);
}

string trimmed (const string& text)
{
    const char* WS = " \t\r\n";
    const size_t first = text.find_first_not_of(WS);
    if (first == string::npos) return string();
    return text.substr(first, text.find_last_not_of(WS) - first + 1);
}

//  The character data of a child element, trimmed; false if the child is absent or has child elements
bool child_text (const Xml::Node* parent, const char* nsUri, const char* local, string& value)
{
    value.clear();
    const Xml::Node* node = parent ? parent->child(nsUri, local) : nullptr;
    string text;
    if (!node || !node->textContent(text)) return false;
    value = trimmed(text);
    return true;
}

//  xs:dateTime in UTC ("2026-09-17T13:33:00Z", optional fraction of a second) to milliseconds; 0 if it is not one
uint64_t parse_datetime (const string& text)
{
    int y, mo, d, h, mi, s;
    char tail[8] = { 0 };
    if (sscanf(text.c_str(), "%4d-%2d-%2dT%2d:%2d:%2d%7s", &y, &mo, &d, &h, &mi, &s, tail) < 6) return 0;
    string s_tail = tail;
    if (!s_tail.empty() && (s_tail[0] == '.')) {
        const size_t pos = s_tail.find_first_not_of("0123456789", 1);
        s_tail = (pos == string::npos) ? string() : s_tail.substr(pos);
    }
    if ((s_tail != "Z") || (y < 1970) || (mo < 1) || (mo > 12) || (d < 1) || (d > 31) || (h > 23) || (mi > 59) || (s > 60)) return 0;
    //  Days from 1970-01-01 (the civil calendar)
    y -= (mo <= 2) ? 1 : 0;
    const int64_t era = y / 400;
    const int64_t yoe = y - era * 400;
    const int64_t doy = (153 * (mo + ((mo > 2) ? -3 : 9)) + 2) / 5 + d - 1;
    const int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    const int64_t days = era * 146097 + doe - 719468;
    return (uint64_t)(((days * 24 + h) * 60 + mi) * 60 + s) * 1000;
}

int base64_text_to_ba (const string& text, SmartBA& sba)
{
    string compact;
    for (const char c : text) {
        if ((c != ' ') && (c != '\t') && (c != '\r') && (c != '\n')) compact += c;
    }
    //  The value replaces the one the caller had (a loop over the references)
    return sba.reset(ba_alloc_from_base64(compact.c_str())) ? RET_OK : RET_UAPKI_TRUST_LIST_INVALID;
}

int digest_of (const string& digestMethodUri, const string& data, SmartBA& sbaHash)
{
    const string suffix = uri_suffix(digestMethodUri);
    for (const auto& it : DIGEST_METHODS) {
        if (suffix != it.uriSuffix) continue;
        SmartBA sba_data;
        if (!sba_data.set(ba_alloc_from_uint8((const uint8_t*)data.data(), data.size()))) return RET_UAPKI_GENERAL_ERROR;
        sbaHash.clear();
        return ::hash(hash_from_oid(it.hashAlgo), sba_data.get(), &sbaHash);
    }
    return RET_UAPKI_UNSUPPORTED_ALG;
}

//  r | s of XML Signature (two integers of equal length) as ECDSA-Sig-Value: SEQUENCE { r INTEGER, s INTEGER }
int ecdsa_value_to_der (const ByteArray* baValue, SmartBA& sbaDer)
{
    const size_t len = ba_get_len(baValue);
    const uint8_t* buf = ba_get_buf_const(baValue);
    if (!buf || (len < 2) || (len % 2 != 0)) return RET_UAPKI_TRUST_LIST_INVALID;

    vector<uint8_t> body;
    for (size_t half = 0; half < 2; half++) {
        const uint8_t* p = buf + half * (len / 2);
        size_t n = len / 2;
        while ((n > 1) && (*p == 0)) { p++; n--; }
        const bool pad = (*p & 0x80) != 0;
        const size_t int_len = n + (pad ? 1 : 0);
        if (int_len > 127) return RET_UAPKI_TRUST_LIST_INVALID;
        body.push_back(0x02);
        body.push_back((uint8_t)int_len);
        if (pad) body.push_back(0x00);
        body.insert(body.end(), p, p + n);
    }
    vector<uint8_t> der;
    der.push_back(0x30);
    if (body.size() > 127) {
        der.push_back(0x81);
    }
    der.push_back((uint8_t)body.size());
    der.insert(der.end(), body.begin(), body.end());
    return sbaDer.reset(ba_alloc_from_uint8(der.data(), der.size())) ? RET_OK : RET_UAPKI_GENERAL_ERROR;
}

//  Every ds:Signature of the document, wherever it is
void count_signatures (const Xml::Node* node, size_t& count)
{
    vector<const Xml::Node*> stack;
    stack.push_back(node);
    while (!stack.empty()) {
        const Xml::Node* it = stack.back();
        stack.pop_back();
        if (!it->isElement) continue;
        if ((it->local == "Signature") && (it->nsUri == NS_DS)) count++;
        for (const auto& it_child : it->children) {
            stack.push_back(it_child.get());
        }
    }
}

//  The list of algorithms of ds:Transforms of a reference
vector<string> transforms_of (const Xml::Node* reference)
{
    vector<string> rv;
    const Xml::Node* transforms = reference->child(NS_DS, "Transforms");
    if (!transforms) return rv;
    for (const auto& it : transforms->childElements(NS_DS, "Transform")) {
        const string* algo = it->attribute("Algorithm");
        rv.push_back(algo ? *algo : string());
    }
    return rv;
}

//  The signature of the list (XAdES baseline, as trusted lists are signed): one ds:Signature, a child of the
//  root; a reference to the whole document (enveloped signature, exclusive canonicalization) and a reference to
//  the signed properties of this signature; nothing else is accepted. Returns the encoded signing certificate
int verify_list_signature (
        const Xml::Document& document,
        SmartBA& sbaSignerCert
)
{
    int ret = RET_OK;
    const Xml::Node* root = document.root();
    const Xml::Node* signature = nullptr;
    const Xml::Node* signed_info = nullptr;
    const Xml::Node* signed_props = nullptr;
    const SignatureMethod* method = nullptr;
    size_t cnt_signatures = 0, cnt_document_refs = 0, cnt_props_refs = 0;
    string s_canonical, s_text;
    SmartBA sba_signvalue, sba_signedinfo, sba_hash, sba_expected;
    Cert::CerItem* cer_parsed = nullptr;

    count_signatures(root, cnt_signatures);
    signature = root->child(NS_DS, "Signature");
    if ((cnt_signatures != 1) || !signature) {
        SET_ERROR(RET_UAPKI_TRUST_LIST_INVALID);
    }
    signed_info = signature->child(NS_DS, "SignedInfo");
    if (!signed_info) {
        SET_ERROR(RET_UAPKI_TRUST_LIST_INVALID);
    }

    {   //  The algorithms
        const Xml::Node* c14n_method = signed_info->child(NS_DS, "CanonicalizationMethod");
        const Xml::Node* sign_method = signed_info->child(NS_DS, "SignatureMethod");
        const string* c14n_algo = c14n_method ? c14n_method->attribute("Algorithm") : nullptr;
        const string* sign_algo = sign_method ? sign_method->attribute("Algorithm") : nullptr;
        if (!c14n_algo || !sign_algo) {
            SET_ERROR(RET_UAPKI_TRUST_LIST_INVALID);
        }
        if (*c14n_algo != URI_EXC_C14N) {
            SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
        }
        const string suffix = uri_suffix(*sign_algo);
        for (const auto& it : SIGNATURE_METHODS) {
            if (suffix == it.uriSuffix) method = &it;
        }
        if (!method) {
            SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
        }
    }

    //  The signed properties of this signature: ds:Object / xades:QualifyingProperties / xades:SignedProperties
    for (const auto& it_object : signature->childElements(NS_DS, "Object")) {
        const Xml::Node* qualifying = it_object->child(NS_XADES, "QualifyingProperties");
        const Xml::Node* props = qualifying ? qualifying->child(NS_XADES, "SignedProperties") : nullptr;
        if (props) {
            if (signed_props) {
                SET_ERROR(RET_UAPKI_TRUST_LIST_INVALID);
            }
            signed_props = props;
        }
    }
    if (!signed_props) {
        SET_ERROR(RET_UAPKI_TRUST_LIST_INVALID);
    }

    //  The references
    for (const auto& it : signed_info->children) {
        if (!it->isElement) continue;
        if ((it->nsUri != NS_DS) || ((it->local != "Reference") && (it->local != "CanonicalizationMethod") && (it->local != "SignatureMethod"))) {
            SET_ERROR(RET_UAPKI_TRUST_LIST_INVALID);
        }
        if (it->local != "Reference") continue;

        const string* uri = it->attribute("URI");
        const Xml::Node* digest_method = it->child(NS_DS, "DigestMethod");
        const string* digest_algo = digest_method ? digest_method->attribute("Algorithm") : nullptr;
        const vector<string> transforms = transforms_of(it.get());
        if (!uri || !digest_algo || !child_text(it.get(), NS_DS, "DigestValue", s_text)) {
            SET_ERROR(RET_UAPKI_TRUST_LIST_INVALID);
        }
        DO(base64_text_to_ba(s_text, sba_expected));

        if (uri->empty()) {
            //  The whole document without this signature
            if ((transforms.size() != 2) || (transforms[0] != URI_ENVELOPED) || (transforms[1] != URI_EXC_C14N)) {
                SET_ERROR(RET_UAPKI_TRUST_LIST_INVALID);
            }
            Xml::canonicalizeExclusive(root, signature, s_canonical);
            cnt_document_refs++;
        }
        else {
            const string* type = it->attribute("Type");
            if (
                ((*uri)[0] != '#') || !type || (*type != URI_SIGNED_PROPS) ||
                (transforms.size() != 1) || (transforms[0] != URI_EXC_C14N) ||
                (document.elementById(uri->substr(1)) != signed_props)
            ) {
                SET_ERROR(RET_UAPKI_TRUST_LIST_INVALID);
            }
            Xml::canonicalizeExclusive(signed_props, nullptr, s_canonical);
            cnt_props_refs++;
        }

        DO(digest_of(*digest_algo, s_canonical, sba_hash));
        if (ba_cmp(sba_hash.get(), sba_expected.get()) != 0) {
            SET_ERROR(RET_UAPKI_TRUST_LIST_VERIFY_FAILED);
        }
    }
    if ((cnt_document_refs != 1) || (cnt_props_refs != 1)) {
        SET_ERROR(RET_UAPKI_TRUST_LIST_INVALID);
    }

    {   //  The signing certificate: of ds:KeyInfo, the one the signed properties name by its digest
        const Xml::Node* key_info = signature->child(NS_DS, "KeyInfo");
        const Xml::Node* x509_data = key_info ? key_info->child(NS_DS, "X509Data") : nullptr;
        const vector<const Xml::Node*> certs = x509_data ? x509_data->childElements(NS_DS, "X509Certificate") : vector<const Xml::Node*>();
        const Xml::Node* signature_props = signed_props->child(NS_XADES, "SignedSignatureProperties");
        const Xml::Node* signing_cert = signature_props ? signature_props->child(NS_XADES, "SigningCertificateV2") : nullptr;
        if (signature_props && !signing_cert) {
            signing_cert = signature_props->child(NS_XADES, "SigningCertificate");
        }
        const Xml::Node* cert_entry = signing_cert ? signing_cert->child(NS_XADES, "Cert") : nullptr;
        const Xml::Node* cert_digest = cert_entry ? cert_entry->child(NS_XADES, "CertDigest") : nullptr;
        const Xml::Node* digest_method = cert_digest ? cert_digest->child(NS_DS, "DigestMethod") : nullptr;
        const string* digest_algo = digest_method ? digest_method->attribute("Algorithm") : nullptr;
        if ((certs.size() != 1) || !digest_algo || !child_text(cert_digest, NS_DS, "DigestValue", s_text) || !certs[0]->textContent(s_canonical)) {
            SET_ERROR(RET_UAPKI_TRUST_LIST_INVALID);
        }
        DO(base64_text_to_ba(s_text, sba_expected));
        DO(base64_text_to_ba(s_canonical, sbaSignerCert));
        DO(digest_of(*digest_algo, string((const char*)ba_get_buf_const(sbaSignerCert.get()), ba_get_len(sbaSignerCert.get())), sba_hash));
        if (ba_cmp(sba_hash.get(), sba_expected.get()) != 0) {
            SET_ERROR(RET_UAPKI_TRUST_LIST_VERIFY_FAILED);
        }
    }

    //  The signature value over the canonical ds:SignedInfo
    if (!child_text(signature, NS_DS, "SignatureValue", s_text)) {
        SET_ERROR(RET_UAPKI_TRUST_LIST_INVALID);
    }
    DO(base64_text_to_ba(s_text, sba_signvalue));
    if (method->ecdsa) {
        SmartBA sba_der;
        DO(ecdsa_value_to_der(sba_signvalue.get(), sba_der));
        sba_signvalue.reset(sba_der.pop());
    }
    Xml::canonicalizeExclusive(signed_info, nullptr, s_canonical);
    if (!sba_signedinfo.set(ba_alloc_from_uint8((const uint8_t*)s_canonical.data(), s_canonical.size()))) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }
    ret = Cert::parseCert(sbaSignerCert.get(), &cer_parsed);
    if (ret != RET_OK) {
        SET_ERROR(RET_UAPKI_TRUST_LIST_INVALID);
    }
    ret = Verify::verifySignature(
        method->signAlgo, sba_signedinfo.get(), false, cer_parsed->getSpki(), sba_signvalue.get()
    );
    if (ret == RET_VERIFY_FAILED) {
        SET_ERROR(RET_UAPKI_TRUST_LIST_VERIFY_FAILED);
    }

cleanup:
    delete cer_parsed;
    return ret;
}

//  The first name of a multilingual name: xml:lang "en" if present, else the first one
string first_name (const Xml::Node* names)
{
    string rv, text;
    if (!names) return rv;
    for (const auto& it : names->childElements(NS_TSL, "Name")) {
        if (!it->textContent(text)) continue;
        bool is_en = false;
        for (const auto& it_attr : it->attributes) {
            is_en |= (it_attr.prefix == "xml") && (it_attr.local == "lang") && (it_attr.value == "en");
        }
        if (rv.empty() || is_en) rv = trimmed(text);
        if (is_en) break;
    }
    return rv;
}

//  The registration identifier of a TSP among the names of TSPTradeName (ETSI TS 119 612, 5.4.2): the identity
//  type ("VAT", "NTR" for a legal person; "PAS", "IDC", "PNO", "TAX", "TIN" for a natural one), the country code,
//  "-" and the identifier: "NTRUA-36865753"
string tsp_identifier (const Xml::Node* tradeNames)
{
    string text;
    if (!tradeNames) return string();
    for (const auto& it : tradeNames->childElements(NS_TSL, "Name")) {
        if (!it->textContent(text)) continue;
        const string s = trimmed(text);
        if ((s.size() < 7) || (s[5] != '-')) continue;
        bool is_id = true;
        for (size_t i = 0; i < 5; i++) {
            is_id &= (s[i] >= 'A') && (s[i] <= 'Z');
        }
        const string type = s.substr(0, 3);
        is_id &= (type == "VAT") || (type == "NTR") || (type == "PAS") || (type == "IDC") || (type == "PNO") ||
            (type == "TAX") || (type == "TIN");
        if (is_id) return s;
    }
    return string();
}

struct ListedService {
    SmartBA     certificate;
    Cert::TrustService
                service;
};

//  One status: of the service itself or of an instance of its history
bool add_period (const Xml::Node* node, const char* statusName, const char* timeName, Cert::TrustService& service)
{
    string s_status, s_time;
    if (!child_text(node, NS_TSL, statusName, s_status) || !child_text(node, NS_TSL, timeName, s_time)) return false;
    Cert::TrustService::Period period;
    period.status = uri_suffix(s_status, '/');
    period.msFrom = parse_datetime(s_time);
    if (period.msFrom == 0) return false;
    //  The periods go from the current one to the oldest: a status ends when the next one starts
    period.msTo = service.periods.empty() ? 0 : service.periods.back().msFrom;
    service.periods.push_back(period);
    return true;
}

//  tsl:TrustServiceProviderList: every service with a certificate as its digital identity
int read_services (
        const Xml::Node* root,
        const string& listId,
        vector<unique_ptr<ListedService>>& services,
        size_t& countProviders,
        size_t& countServices
)
{
    countProviders = countServices = 0;
    const Xml::Node* tsp_list = root->child(NS_TSL, "TrustServiceProviderList");
    if (!tsp_list) return RET_OK;

    for (const auto& it_tsp : tsp_list->childElements(NS_TSL, "TrustServiceProvider")) {
        countProviders++;
        const Xml::Node* tsp_info = it_tsp->child(NS_TSL, "TSPInformation");
        const string tsp_name = first_name(tsp_info ? tsp_info->child(NS_TSL, "TSPName") : nullptr);
        const string tsp_id = tsp_identifier(tsp_info ? tsp_info->child(NS_TSL, "TSPTradeName") : nullptr);
        const Xml::Node* tsp_services = it_tsp->child(NS_TSL, "TSPServices");
        if (!tsp_services) continue;

        for (const auto& it_svc : tsp_services->childElements(NS_TSL, "TSPService")) {
            countServices++;
            const Xml::Node* info = it_svc->child(NS_TSL, "ServiceInformation");
            string s_type;
            if (!info || !child_text(info, NS_TSL, "ServiceTypeIdentifier", s_type)) {
                return refused(RET_UAPKI_TRUST_LIST_INVALID, "a service without ServiceTypeIdentifier");
            }

            Cert::TrustService service;
            service.listId = listId;
            const size_t pos = s_type.find(SVCTYPE_MARK);
            service.type = (pos == string::npos) ? s_type : s_type.substr(pos + strlen(SVCTYPE_MARK));
            service.tspName = tsp_name;
            service.tspId = tsp_id;
            service.serviceName = first_name(info->child(NS_TSL, "ServiceName"));
            if (!add_period(info, "ServiceStatus", "StatusStartingTime", service)) {
                return refused(RET_UAPKI_TRUST_LIST_INVALID, "the status of the service '" + service.serviceName + "'");
            }
            const Xml::Node* history = it_svc->child(NS_TSL, "ServiceHistory");
            if (history) {
                for (const auto& it : history->childElements(NS_TSL, "ServiceHistoryInstance")) {
                    if (!add_period(it, "ServiceStatus", "StatusStartingTime", service)) {
                        return refused(RET_UAPKI_TRUST_LIST_INVALID, "the status history of the service '" + service.serviceName + "'");
                    }
                }
            }
            //  additionalServiceInformation: for electronic signatures / seals
            const Xml::Node* extensions = info->child(NS_TSL, "ServiceInformationExtensions");
            if (extensions) {
                for (const auto& it_ext : extensions->childElements(NS_TSL, "Extension")) {
                    const Xml::Node* additional = it_ext->child(NS_TSL, "AdditionalServiceInformation");
                    string s_uri;
                    if (!additional || !child_text(additional, NS_TSL, "URI", s_uri)) continue;
                    const string suffix = uri_suffix(s_uri, '/');
                    service.forESignatures |= (suffix == "ForeSignatures");
                    service.forESeals |= (suffix == "ForeSeals");
                }
            }

            const Xml::Node* identity = info->child(NS_TSL, "ServiceDigitalIdentity");
            if (!identity) continue;
            for (const auto& it_id : identity->childElements(NS_TSL, "DigitalId")) {
                const Xml::Node* x509 = it_id->child(NS_TSL, "X509Certificate");
                string s_cert;
                if (!x509 || !x509->textContent(s_cert)) continue;
                unique_ptr<ListedService> listed(new ListedService());
                if (base64_text_to_ba(s_cert, listed->certificate) != RET_OK) {
                    return refused(RET_UAPKI_TRUST_LIST_INVALID, "the certificate of the service '" + service.serviceName + "' is not Base64");
                }
                listed->service = service;
                services.push_back(std::move(listed));
            }
        }
    }
    return RET_OK;
}

}   //  end namespace


//  The certificate of the scheme operator that signs the list, ETSI TS 119 612, 5.7.1. Refused: a CA certificate,
//  a key usage without digitalSignature and nonRepudiation, no subjectKeyIdentifier. The requirements that
//  one list does not let check exactly (the names are compared as they are written; the issuer may be a service of
//  another list of the community) and the recommended key purpose give warnings
int check_signer_certificate (
        Cert::CerItem* cerSigner,
        const Xml::Node* root,
        const Xml::Node* scheme,
        vector<string>& warnings
)
{
    const Extensions_t* extns = cerSigner->getCert()->tbsCertificate.extensions;

    if (cerSigner->getCertExtKeyUsage().isCa()) {
        return refused(RET_UAPKI_TRUST_LIST_SIGNER_NOT_TRUSTED, "the signing certificate is a CA certificate");
    }
    bool sign_usage = false, other_usage = false;
    for (uint32_t bit = 0; bit <= 8; bit++) {
        const bool is_set = cerSigner->keyUsageByBit(bit);
        if ((bit == KeyUsage_digitalSignature) || (bit == KeyUsage_nonRepudiation)) sign_usage |= is_set;
        else other_usage |= is_set;
    }
    if (!sign_usage) {
        return refused(RET_UAPKI_TRUST_LIST_SIGNER_NOT_TRUSTED, "the key usage of the signing certificate is not digitalSignature or nonRepudiation");
    }
    //  Other key usage values are excluded by the standard; the signer is named by INIT, so it is reported only
    if (other_usage) {
        warnings.push_back("SIGNER_WITH_OTHER_KEY_USAGE");
    }
    {
        SmartBA sba_keyid;
        if (ExtensionHelper::getSubjectKeyId(extns, &sba_keyid) != RET_OK) {
            return refused(RET_UAPKI_TRUST_LIST_SIGNER_NOT_TRUSTED, "the signing certificate has no subjectKeyIdentifier");
        }
    }

    {   //  The key purpose id-tsl-kp-tslSigning: should be present
        vector<string> key_purposes;
        (void)ExtensionHelper::getExtendedKeyUsage(extns, key_purposes);
        if (std::find(key_purposes.begin(), key_purposes.end(), string(OID_ETSI_KP_TSL_SIGNING)) == key_purposes.end()) {
            warnings.push_back("SIGNER_WITHOUT_TSL_SIGNING_KEY_PURPOSE");
        }
    }
    {   //  The country and the organization of the subject: the scheme territory and a scheme operator name
        ParsonHelper json;
        JSON_Object* jo_subject = json.create();
        string s_territory;
        (void)child_text(scheme, NS_TSL, "SchemeTerritory", s_territory);
        if (!jo_subject || (nameToJson(jo_subject, cerSigner->getSubject()) != RET_OK)) return RET_UAPKI_GENERAL_ERROR;
        const char* s_country = json_object_get_string(jo_subject, "C");
        const char* s_organization = json_object_get_string(jo_subject, "O");
        if (!s_country || (s_territory != s_country)) {
            warnings.push_back("SIGNER_COUNTRY_IS_NOT_SCHEME_TERRITORY");
        }
        bool is_operator = false;
        const Xml::Node* operator_name = scheme ? scheme->child(NS_TSL, "SchemeOperatorName") : nullptr;
        if (operator_name && s_organization) {
            string text;
            for (const auto& it : operator_name->childElements(NS_TSL, "Name")) {
                is_operator |= it->textContent(text) && (trimmed(text) == s_organization);
            }
        }
        if (!is_operator) {
            warnings.push_back("SIGNER_ORGANIZATION_IS_NOT_SCHEME_OPERATOR_NAME");
        }
    }
    //  The issuer: the operator itself (a self-signed certificate) or a trust service of the list (of a list of
    //  the community - not seen here)
    if (!cerSigner->isSelfSigned()) {
        bool is_listed = false;
        vector<const Xml::Node*> stack;
        stack.push_back(root);
        while (!stack.empty() && !is_listed) {
            const Xml::Node* it = stack.back();
            stack.pop_back();
            if (!it->isElement) continue;
            if ((it->local == "Signature") && (it->nsUri == NS_DS)) continue;
            if ((it->local == "X509Certificate") && (it->nsUri == NS_TSL)) {
                string text;
                SmartBA sba_cert;
                Cert::CerItem* cer_service = nullptr;
                if (it->textContent(text) && (base64_text_to_ba(text, sba_cert) == RET_OK) && (Cert::parseCert(sba_cert.get(), &cer_service) == RET_OK)) {
                    is_listed = (ba_cmp(cer_service->getSubject(), cerSigner->getIssuer()) == 0)
                        && (cerSigner->verify(cer_service) == RET_OK)
                        && (cerSigner->getVerifyStatus() == Cert::VerifyStatus::VALID);
                    delete cer_service;
                }
                continue;
            }
            for (const auto& it_child : it->children) {
                stack.push_back(it_child.get());
            }
        }
        if (!is_listed) {
            warnings.push_back("SIGNER_ISSUER_IS_NOT_A_SERVICE_OF_THE_LIST");
        }
    }
    return RET_OK;
}

//  The list is verified and applied; fromStore - a list kept in the directory of the lists (INIT): it is not
//  written again
static int add_trust_list (Cert::CerStore* cer_store, const ByteArray* baXml, const bool fromStore, JSON_Object* joResult)
{
    int ret = RET_OK;
    Cert::CerItem* cer_signer = nullptr;
    Xml::Document document;
    const Xml::Node* root = nullptr;
    const Xml::Node* scheme = nullptr;
    SmartBA sba_signercert, sba_idhash;
    string s_text, s_listid, s_type, s_territory, s_issued, s_nextupdate, s_sequence, s_storename;
    uint64_t sequence = 0;
    vector<unique_ptr<ListedService>> services;
    vector<pair<Cert::CerItem*, Cert::TrustService>> cert_services;
    size_t cnt_providers = 0, cnt_services = 0, cnt_trusted = 0, cnt_added = 0, cnt_skipped = 0;
    bool stored = false;
    vector<string> warnings;

    tl_detail.clear();

    if (document.parse(ba_get_buf_const(baXml), ba_get_len(baXml)) != Xml::Error::OK) {
        DO_JSON(json_object_set_string(joResult, "xmlError", Xml::errorToStr(document.error())));
        DO_JSON(json_object_set_number(joResult, "xmlErrorOffset", (double)document.errorOffset()));
        SET_ERROR(RET_UAPKI_TRUST_LIST_INVALID);
    }
    root = document.root();
    if ((root->local != "TrustServiceStatusList") || (root->nsUri != NS_TSL)) {
        SET_ERROR(RET_UAPKI_TRUST_LIST_INVALID);
    }

    //  The signature; then the signer: one of the certificates given to INIT as the signers of trusted lists
    //  (trustListCache.trustListSignerCerts), the certificate itself - not a certificate with a path to a trusted one,
    //  not a trusted certificate of the cache and not a certificate of another list
    DO(verify_list_signature(document, sba_signercert));
    if (!cer_store->isTrustListSigner(sba_signercert.get())) {
        SET_ERROR(refused(RET_UAPKI_TRUST_LIST_SIGNER_NOT_TRUSTED, "the signing certificate is not one of the signers of trusted lists given to INIT"));
    }
    ret = Cert::parseCert(sba_signercert.get(), &cer_signer);
    if (ret != RET_OK) {
        SET_ERROR(refused(RET_UAPKI_TRUST_LIST_INVALID, "the signing certificate is not parsed"));
    }
    scheme = root->child(NS_TSL, "SchemeInformation");
    DO(check_signer_certificate(cer_signer, root, scheme, warnings));

    //  The scheme information
    if (
        !scheme || !child_text(scheme, NS_TSL, "TSLSequenceNumber", s_sequence) || !child_text(scheme, NS_TSL, "TSLType", s_type) ||
        s_sequence.empty() || (s_sequence.find_first_not_of("0123456789") != string::npos) || (s_sequence.size() > 18)
    ) {
        SET_ERROR(RET_UAPKI_TRUST_LIST_INVALID);
    }
    sequence = strtoull(s_sequence.c_str(), nullptr, 10);
    (void)child_text(scheme, NS_TSL, "SchemeTerritory", s_territory);
    (void)child_text(scheme, NS_TSL, "ListIssueDateTime", s_issued);
    if (scheme->child(NS_TSL, "NextUpdate")) {
        (void)child_text(scheme->child(NS_TSL, "NextUpdate"), NS_TSL, "dateTime", s_nextupdate);
    }
    //  The identifier of the list: where it is published; a scheme may publish several lists of one type
    if (scheme->child(NS_TSL, "DistributionPoints")) {
        (void)child_text(scheme->child(NS_TSL, "DistributionPoints"), NS_TSL, "URI", s_listid);
    }
    if (s_listid.empty()) {
        s_listid = s_territory + " " + s_type;
    }
    if (s_listid.find_first_of("\r\n") != string::npos) {
        SET_ERROR(RET_UAPKI_TRUST_LIST_INVALID);
    }

    DO(read_services(root, s_listid, services, cnt_providers, cnt_services));

    //  The certificates of the services go to the cache; trust comes from the services, not from being added
    if (!services.empty()) {
        VectorBA vba_certs;
        vector<Cert::CerStore::AddedCerItem> added;
        for (const auto& it : services) {
            vba_certs.push_back(it->certificate.pop());
        }
        DO(cer_store->addCerts(Cert::NOT_TRUSTED, Cert::NOT_PERMANENT, vba_certs, added));
        for (size_t i = 0; i < added.size(); i++) {
            //  A certificate the library does not parse (X.509 v1...) cannot be used by it: its service is left out
            if ((added[i].errorCode != RET_OK) || !added[i].cerItem) {
                cnt_skipped++;
                continue;
            }
            cnt_added += added[i].isUnique ? 1 : 0;
            cert_services.push_back(make_pair(added[i].cerItem, services[i]->service));
        }
    }
    //  The name of the file of the list in the directory of the lists: by the identifier of the list
    if (!fromStore) {
        DO(digest_of("sha256", s_listid, sba_idhash));
        const uint8_t* buf = ba_get_buf_const(sba_idhash.get());
        static const char* HEX = "0123456789abcdef";
        for (size_t i = 0; i < 16; i++) {
            s_storename += HEX[buf[i] >> 4];
            s_storename += HEX[buf[i] & 0x0F];
        }
    }
    DO(cer_store->applyTrustList(s_listid, sequence, cert_services, cnt_trusted, baXml, s_storename, &stored));
    {
        Cert::AcceptedTrustList accepted;
        accepted.listId = s_listid;
        accepted.type = uri_suffix(s_type, '/');
        accepted.territory = s_territory;
        accepted.schemeName = first_name(scheme->child(NS_TSL, "SchemeName"));
        accepted.schemeOperatorName = first_name(scheme->child(NS_TSL, "SchemeOperatorName"));
        accepted.sequenceNumber = sequence;
        accepted.msIssued = parse_datetime(s_issued);
        accepted.msNextUpdate = parse_datetime(s_nextupdate);
        const ByteArray* ba_certid = cer_signer->getCertId();
        accepted.signerCertId.assign(ba_get_buf_const(ba_certid), ba_get_buf_const(ba_certid) + ba_get_len(ba_certid));
        accepted.countCerts = (uint32_t)cert_services.size();
        accepted.countTrustedCerts = (uint32_t)cnt_trusted;
        //  a list read from the directory of the lists is the one kept there
        accepted.stored = fromStore || stored;
        cer_store->setAcceptedTrustList(accepted);
        //  ETSI TS 119 612, 5.3.15: the list is to be issued again before its next update
        if ((accepted.msNextUpdate > 0) && (accepted.msNextUpdate < TimeUtil::mtimeNow())) {
            warnings.push_back("LIST_NEXT_UPDATE_PASSED");
        }
    }

    DO_JSON(json_object_set_string(joResult, "listId", s_listid.c_str()));
    DO_JSON(json_object_set_string(joResult, "type", uri_suffix(s_type, '/').c_str()));
    DO_JSON(json_object_set_string(joResult, "territory", s_territory.c_str()));
    DO_JSON(json_object_set_string(joResult, "schemeName", first_name(scheme->child(NS_TSL, "SchemeName")).c_str()));
    DO_JSON(json_object_set_string(joResult, "schemeOperatorName", first_name(scheme->child(NS_TSL, "SchemeOperatorName")).c_str()));
    DO_JSON(json_object_set_number(joResult, "sequenceNumber", (double)sequence));
    if (parse_datetime(s_issued) > 0) {
        DO_JSON(json_object_set_string(joResult, "listIssueDateTime", TimeUtil::mtimeToFtime(parse_datetime(s_issued)).c_str()));
    }
    if (parse_datetime(s_nextupdate) > 0) {
        DO_JSON(json_object_set_string(joResult, "nextUpdate", TimeUtil::mtimeToFtime(parse_datetime(s_nextupdate)).c_str()));
    }
    DO(json_object_set_base64(joResult, "signerCertId", cer_signer->getCertId()));
    DO_JSON(ParsonHelper::jsonObjectSetUint32(joResult, "countProviders", (uint32_t)cnt_providers));
    DO_JSON(ParsonHelper::jsonObjectSetUint32(joResult, "countServices", (uint32_t)cnt_services));
    DO_JSON(ParsonHelper::jsonObjectSetUint32(joResult, "countCerts", (uint32_t)cert_services.size()));
    DO_JSON(ParsonHelper::jsonObjectSetUint32(joResult, "countAddedCerts", (uint32_t)cnt_added));
    DO_JSON(ParsonHelper::jsonObjectSetUint32(joResult, "countTrustedCerts", (uint32_t)cnt_trusted));
    DO_JSON(ParsonHelper::jsonObjectSetUint32(joResult, "countSkippedCerts", (uint32_t)cnt_skipped));
    if (!fromStore) {
        DO_JSON(ParsonHelper::jsonObjectSetBoolean(joResult, "stored", stored));
    }
    if (!warnings.empty()) {
        DO_JSON(json_object_set_value(joResult, "warnings", json_value_init_array()));
        for (const auto& it : warnings) {
            DO_JSON(json_array_append_string(json_object_get_array(joResult, "warnings"), it.c_str()));
        }
    }

cleanup:
    delete cer_signer;
    if ((ret != RET_OK) && !tl_detail.empty()) {
        (void)json_object_set_string(joResult, "detail", tl_detail.c_str());
    }
    return ret;
}


int uapki_add_trust_list (JSON_Object* joParams, JSON_Object* joResult)
{
    LibraryConfig* lib_config = get_config();
    Cert::CerStore* cer_store = get_cerstore();
    SmartBA sba_xml;

    if (!lib_config || !cer_store) return RET_UAPKI_GENERAL_ERROR;
    if (!lib_config->isInitialized()) return RET_UAPKI_NOT_INITIALIZED;

    //  The list: "bytes" (Base64) or "text" (the XML document as a string)
    if (ParsonHelper::jsonObjectHasValue(joParams, "bytes", JSONString)) {
        if (!sba_xml.set(json_object_get_base64(joParams, "bytes"))) return RET_UAPKI_INVALID_PARAMETER;
    }
    else if (ParsonHelper::jsonObjectHasValue(joParams, "text", JSONString)) {
        const char* s_xml = json_object_get_string(joParams, "text");
        if (!sba_xml.set(ba_alloc_from_uint8((const uint8_t*)s_xml, strlen(s_xml)))) return RET_UAPKI_INVALID_PARAMETER;
    }
    else {
        return RET_UAPKI_INVALID_PARAMETER;
    }

    return add_trust_list(cer_store, sba_xml.get(), false, joResult);
}

//  LIST_TRUST_LISTS: the trusted lists accepted, the last version of every list
int uapki_list_trust_lists (JSON_Object* joParams, JSON_Object* joResult)
{
    (void)joParams;
    int ret = RET_OK;
    LibraryConfig* lib_config = get_config();
    Cert::CerStore* cer_store = get_cerstore();
    JSON_Array* ja_lists = nullptr;
    size_t idx = 0;

    if (!lib_config || !cer_store) return RET_UAPKI_GENERAL_ERROR;
    if (!lib_config->isInitialized()) return RET_UAPKI_NOT_INITIALIZED;

    const uint64_t ms_now = TimeUtil::mtimeNow();
    DO_JSON(json_object_set_value(joResult, "trustLists", json_value_init_array()));
    ja_lists = json_object_get_array(joResult, "trustLists");
    for (const auto& it : cer_store->getAcceptedTrustLists()) {
        SmartBA sba_certid;
        DO_JSON(json_array_append_value(ja_lists, json_value_init_object()));
        JSON_Object* jo_list = json_array_get_object(ja_lists, idx++);
        DO_JSON(json_object_set_string(jo_list, "listId", it.listId.c_str()));
        DO_JSON(json_object_set_string(jo_list, "type", it.type.c_str()));
        DO_JSON(json_object_set_string(jo_list, "territory", it.territory.c_str()));
        DO_JSON(json_object_set_string(jo_list, "schemeName", it.schemeName.c_str()));
        DO_JSON(json_object_set_string(jo_list, "schemeOperatorName", it.schemeOperatorName.c_str()));
        DO_JSON(json_object_set_number(jo_list, "sequenceNumber", (double)it.sequenceNumber));
        if (it.msIssued > 0) {
            DO_JSON(json_object_set_string(jo_list, "listIssueDateTime", TimeUtil::mtimeToFtime(it.msIssued).c_str()));
        }
        if (it.msNextUpdate > 0) {
            DO_JSON(json_object_set_string(jo_list, "nextUpdate", TimeUtil::mtimeToFtime(it.msNextUpdate).c_str()));
        }
        DO_JSON(ParsonHelper::jsonObjectSetBoolean(jo_list, "nextUpdatePassed", (it.msNextUpdate > 0) && (it.msNextUpdate < ms_now)));
        if (!sba_certid.set(ba_alloc_from_uint8(it.signerCertId.data(), it.signerCertId.size()))) {
            SET_ERROR(RET_UAPKI_GENERAL_ERROR);
        }
        DO(json_object_set_base64(jo_list, "signerCertId", sba_certid.get()));
        DO_JSON(ParsonHelper::jsonObjectSetUint32(jo_list, "countCerts", it.countCerts));
        DO_JSON(ParsonHelper::jsonObjectSetUint32(jo_list, "countTrustedCerts", it.countTrustedCerts));
        DO_JSON(ParsonHelper::jsonObjectSetBoolean(jo_list, "stored", it.stored));
    }

cleanup:
    return ret;
}

//  INIT: the lists kept in the directory of the lists are verified and applied again, as ADD_TRUST_LIST does;
//  a list that is not accepted now (its signer is not trusted any more...) is left out and counted
int uapki_load_trust_lists (Cert::CerStore* cerStore, size_t& countLoaded, size_t& countRefused)
{
    countLoaded = countRefused = 0;
    vector<string> file_names;
    const int ret = cerStore->getStoredTrustLists(file_names);
    if (ret != RET_OK) return ret;

    for (const auto& it : file_names) {
        SmartBA sba_xml;
        ParsonHelper json;
        JSON_Object* jo_result = json.create();
        const bool ok = jo_result && (ba_alloc_from_file(it.c_str(), &sba_xml) == RET_OK)
            && (add_trust_list(cerStore, sba_xml.get(), true, jo_result) == RET_OK);
        (ok ? countLoaded : countRefused)++;
    }
    return RET_OK;
}
