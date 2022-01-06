//  Last update: 2021-12-11

#ifndef UAPKI_NS_CERTREQ_BUILDER_H
#define UAPKI_NS_CERTREQ_BUILDER_H


#include "uapki-ns.h"
#include "uapkif.h"


using namespace std;


namespace UapkiNS {


class CertReqBuilder {
    CertificationRequestInfo_t*
                m_TbsCsrInfo;
    string      m_KeyAlgo;
    ByteArray*  m_BaTbsEncoded;
    ByteArray*  m_BaCsrEncoded;

public:
    CertReqBuilder (void);
    ~CertReqBuilder (void);

    int init (const uint32_t version = 1);
    int setSubject (const ByteArray* baNameEncoded);
    int setSubject (const vector<UapkiNS::RdName>& rdNames);
    int setSubjectPublicKeyInfo (const ByteArray* baSpkiEncoded);
    int setSubjectPublicKeyInfo (const ByteArray* baAlgoId, const ByteArray* baSubjectPublicKey);
    int setSubjectPublicKeyInfo (const UapkiNS::AlgorithmIdentifier& algorithm, const ByteArray* baSubjectPublicKey);
    int addExtensions (const vector<UapkiNS::Extension>& extensions);
    const string& getKeyAlgo (void) const { return m_KeyAlgo; }

    int encodeTbs (void);
    const ByteArray* getTbsEncoded (void) const { return m_BaTbsEncoded; }

    int encodeCertRequest (const UapkiNS::AlgorithmIdentifier& aidSignature, const ByteArray* baSignature);
    ByteArray* getCsrEncoded (const bool move = false);

public:
    static int encodeExtensions (const vector<UapkiNS::Extension>& extensions, ByteArray** baEncoded);
    static int nameAddRdName (Name_t* name, const UapkiNS::RdName& rdName);

};  //  end class CertReqBuilder


}   //  end namespace UapkiNS

#endif
