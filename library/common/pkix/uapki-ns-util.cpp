//  Last update: 2021-12-06


#include "uapki-ns-util.h"
#include "oids.h"


using namespace std;


namespace UapkiNS {


string Util::oidFromExtensionName (const string& key)
{
    string rv_s = string(key);

    if (rv_s == "subjectKeyIdentifier") rv_s = string(OID_X509v3_SubjectKeyIdentifier);
    else if (rv_s == "keyUsage") rv_s = string(OID_X509v3_KeyUsage);
    else if (rv_s == "basicConstraints") rv_s = string(OID_X509v3_BasicConstraints);
    else if (rv_s == "authorityKeyIdentifier") rv_s = string(OID_X509v3_AuthorityKeyIdentifier);
    else if (rv_s == "authorityInfoAccess") rv_s = string(OID_PKIX_AuthorityInfoAccess);
    else if (rv_s == "cRLDistributionPoints") rv_s = string(OID_X509v3_CRLDistributionPoints);
    else if (rv_s == "certificatePolicies") rv_s = string(OID_X509v3_CertificatePolicies);
    else if (rv_s == "extKeyUsage") rv_s = string(OID_X509v3_ExtendedKeyUsage);
    else if (rv_s == "freshestCRL") rv_s = string(OID_X509v3_FreshestCRL);
    else if (rv_s == "qcStatements") rv_s = string(OID_PKIX_QcStatements);
    else if (rv_s == "subjectDirectoryAttributes") rv_s = string(OID_X509v3_SubjectDirectoryAttributes);
    else if (rv_s == "subjectInfoAccess") rv_s = string(OID_PKIX_SubjectInfoAccess);
    else if (rv_s == "subjectAltName") rv_s = string(OID_X509v3_SubjectAlternativeName);
    else if (rv_s == "issuerAltName") rv_s = string(OID_X509v3_IssuerAlternativeName);

    //  Lite check oid is correct
    if ((rv_s.size() < 3) || (rv_s[0] < '0') || (rv_s[0] > '2') || (rv_s[1] != '.')) {
        rv_s.clear();
    }
    return rv_s;
}

string Util::oidFromRdName (const string& key)
{
    string rv_s = key;

    if (rv_s == "CN") rv_s = string(OID_X520_CommonName);
    else if (rv_s == "SN") rv_s = string(OID_X520_Surname);
    else if (rv_s == "SERIALNUMBER") rv_s = string(OID_X520_SerialNumber);
    else if (rv_s == "C") rv_s = string(OID_X520_Country);
    else if (rv_s == "L") rv_s = string(OID_X520_Locality);
    else if (rv_s == "S") rv_s = string(OID_X520_State);
    else if (rv_s == "STREET") rv_s = string(OID_X520_StreetAddress);
    else if (rv_s == "O") rv_s = string(OID_X520_Organization);
    else if (rv_s == "OU") rv_s = string(OID_X520_OrganizationalUnit);
    else if (rv_s == "TITLE") rv_s = string(OID_X520_Title);
    else if (rv_s == "G") rv_s = string(OID_X520_GivenName);
    else if (rv_s == "OI") rv_s = string(OID_X520_OrganizationIdentifier);

    //  Lite check oid is correct
    if ((rv_s.size() < 3) || (rv_s[0] < '0') || (rv_s[0] > '2') || (rv_s[1] != '.')) {
        rv_s.clear();
    }
    return rv_s;
}

string Util::undecorateTime (const string& time)
{
    string rv_s;
    if (time.length() >= 19) {
        rv_s.resize(14);
        //  YYYY
        rv_s[0] = time[0];
        rv_s[1] = time[1];
        rv_s[2] = time[2];
        rv_s[3] = time[3];
        //  MM
        rv_s[4] = time[5];
        rv_s[5] = time[6];
        //  DD
        rv_s[6] = time[8];
        rv_s[7] = time[9];
        //  hh
        rv_s[8] = time[11];
        rv_s[9] = time[12];
        //  mm
        rv_s[10] = time[14];
        rv_s[11] = time[15];
        //  ss
        rv_s[12] = time[17];
        rv_s[13] = time[18];
    }
    if (time.length() == 14) {
        rv_s = time;
    }
    return rv_s;
}


}   //  end namespace UapkiNS
