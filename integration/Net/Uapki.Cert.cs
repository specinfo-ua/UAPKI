/*
 * 
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

using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using UapkiNet.Polyfil;

namespace UapkiNet;

public static partial class Uapki
{
    public class DistinguishedName
    {
        [JsonPropertyName("C")]
        public string? C { get; init; }
        [JsonPropertyName("SERIALNUMBER")]
        public string? SERIALNUMBER { get; init; }
        [JsonPropertyName("CN")]
        public string? CN { get; init; }
        [JsonPropertyName("SN")]
        public string? SN { get; init; }
        [JsonPropertyName("O")]
        public string? O { get; init; }
        [JsonPropertyName("OU")]
        public string? OU { get; init; }
        [JsonPropertyName("OI")]
        public string? OI { get; init; }
        [JsonPropertyName("L")]
        public string? L { get; init; }
        [JsonPropertyName("S")]
        public string? S { get; init; }
        [JsonPropertyName("STREET")]
        public string? STREET { get; init; }
        [JsonPropertyName("G")]
        public string? G { get; init; }
        [JsonPropertyName("H")]
        public string? H { get; init; }
        [JsonPropertyName("TITLE")]
        public string? TITLE { get; init; }

        [JsonIgnore]
        public string AsString
        {
            get
            {
                string result = "";
                string delimiter = "; ";
                if (CN is not null) result += "CN=" + CN + delimiter;
                if (O is not null) result += "O=" + O + delimiter;
                if (OU is not null) result += "OU=" + OU + delimiter;
                if (OI is not null) result += "OI=" + OI + delimiter;
                if (SERIALNUMBER is not null) result += "SERIALNUMBER=" + SERIALNUMBER + delimiter;
                if (C is not null) result += "C=" + C + delimiter;
                if (L is not null) result += "L=" + L + delimiter;
                if (S is not null) result += "S=" + S + delimiter;
                if (STREET is not null) result += "STREET=" + STREET + delimiter;
                if (TITLE is not null) result += "TITLE=" + TITLE + delimiter;
                if (G is not null) result += "G=" + G + delimiter;
                if (SN is not null) result += "SN=" + SN + delimiter;
                return result.Remove(result.Length - delimiter.Length);
            }
        }
    }

    public class Validity
    {
        [JsonPropertyName("notBefore")]
        public string NotBeforeRaw { get; init; } = string.Empty;

        [JsonPropertyName("notAfter")]
        public string NotAfterRaw { get; init; } = string.Empty;

        [JsonIgnore]
        public  DateTime NotBefore => ConvertUtcTimeToDateTime(NotBeforeRaw);

        [JsonIgnore]
        public  DateTime NotAfter => ConvertUtcTimeToDateTime(NotAfterRaw);
    }

    public class SubjectPublicKeyInfo
    {
        [JsonPropertyName("bytes")]
        public byte[] Bytes { get; init; } = Array.Empty<byte>();
        [JsonPropertyName("algorithm")]
        public string AlgorithmRaw { get; init; } = string.Empty;

        [JsonPropertyName("parameters")]
        public byte[]? ParametersRaw { get; init; }

        [JsonPropertyName("publicKey")]
        public byte[] PublicKeyRaw { get; init; } = Array.Empty<byte>();

        //[JsonIgnore]
        [JsonPropertyName("algorithmName")]
        public string AlgorithmName => Algorithm.DisplayName();

        [JsonIgnore]
        public string ParametersValue => ParametersRaw is null ? "NULL" : Hex.ToHexString(ParametersRaw);

        [JsonIgnore]
        public string PublicKey => Hex.ToHexString(PublicKeyRaw);

        [JsonIgnore]
        public KeyAlgo Algorithm => AlgorithmRaw.ToKeyAlgo();

        [JsonIgnore]
        public KeyParameter? Parameters
        {
            get
            {
                if (Algorithm == KeyAlgo.Dstu4145)
                {
                    try { return ParametersRaw!.DerToKeyParameter(KeyAlgo.Dstu4145); } catch { return null; }
                }
                else if (Algorithm == KeyAlgo.Ecdsa)
                {
                    try { return ParametersRaw!.DerToKeyParameter(KeyAlgo.Ecdsa); } catch { return null; }
                }
                else if (Algorithm == KeyAlgo.Rsa)
                {
                    if (PublicKeyBits == 1024) return KeyParameter.RSA1024;
                    if (PublicKeyBits == 1536) return KeyParameter.RSA1536;
                    if (PublicKeyBits == 2048) return KeyParameter.RSA2048;
                    if (PublicKeyBits == 3072) return KeyParameter.RSA3072;
                    if (PublicKeyBits == 4096) return KeyParameter.RSA4096;
                }
                return null;
            }
        }

        [JsonIgnore]
        public  int PublicKeyBits
        {
            get
            {
                if (Algorithm == KeyAlgo.Dstu4145) return PublicKeyRaw.Length * 8;
                else if (Algorithm == KeyAlgo.Ecdsa)
                {
                    var pkBits = (PublicKeyRaw.Length - 1) * 8;
                    if (PublicKeyRaw[0] == 0x04)
                        pkBits >>= 1;
                    return pkBits;
                }
                else if (Algorithm == KeyAlgo.Rsa)
                {
                    int offset = 2;
                    int lenLen = 1;
                    if ((PublicKeyRaw[1] & 0x80) == 0x80)
                        offset += PublicKeyRaw[1] & 0xF;

                    offset++;

                    if ((PublicKeyRaw[offset] & 0x80) == 0x80)
                    {
                        lenLen = PublicKeyRaw[offset] & 0xF;
                        offset++;
                    }

                    var pkBits = PublicKeyRaw[offset] * 8;
                    if (lenLen == 2)
                    {
                        pkBits *= 256;
                        pkBits += PublicKeyRaw[offset + 1] * 8;
                    }

                    if (PublicKeyRaw[offset + lenLen] == 0)
                        pkBits -= 8;

                    return pkBits;
                }
                return 0;
            }
        }
    }

    public class SignatureInfo
    {
        [JsonPropertyName("algorithm")]
        public string Algorithm { get; init; } = string.Empty;
        [JsonPropertyName("parameters")]
        public byte[]? Parameters { get; init; }
        [JsonPropertyName("signature")]
        public byte[] Signature { get; init; } = Array.Empty<byte>();

        [JsonIgnore]
        public SignAlgo SignAlgo => Algorithm.ToSignAlgo();
        [JsonIgnore]
        public string AlgorithmName => SignAlgo.DisplayName();
    }

    public class Certificate
    {
        [JsonPropertyName("bytes")]
        public byte[] Bytes { get; init; } = Array.Empty<byte>();
        [JsonPropertyName("version")]
        public int Version { get; init; }
        [JsonPropertyName("serialNumber")]
        public string SerialNumber { get; init; } = string.Empty;
        [JsonPropertyName("issuer")]
        public DistinguishedName Issuer { get; init; } = new DistinguishedName();
        [JsonPropertyName("validity")]
        public Validity Validity { get; init; } = new Validity();
        [JsonPropertyName("subject")]
        public DistinguishedName Subject { get; init; } = new DistinguishedName();
        [JsonPropertyName("subjectPublicKeyInfo")]
        public SubjectPublicKeyInfo SubjectPublicKeyInfo { get; init; } = new SubjectPublicKeyInfo();
        [JsonPropertyName("spki")]
        public SubjectPublicKeyInfo spki => SubjectPublicKeyInfo;
        [JsonPropertyName("signatureInfo")]
        public SignatureInfo SignatureInfo { get; init; } = new SignatureInfo();
        [JsonPropertyName("otherStatements")]
        public List<string> OtherStatements { get; init; } = new List<string>();
        [JsonPropertyName("notBefore")]
        public DateTime NotBefore => Validity.NotBefore;
        [JsonPropertyName("notAfter")]
        public DateTime NotAfter => Validity.NotAfter;
        public List<Extension> Extensions
        {
            get { return _extensions; }
            init
            {
                _extensions = value;

                foreach (var extension in _extensions)
                {
                    try
                    {
                        switch (extension.ExtnId)
                        {
                            case "2.5.29.15":
                                KeyUsage = new CertKeyUsage(extension);
                                break;

                            case "2.5.29.14":
                                SubjectKeyIdentifier = extension.Decoded?.Value?.KeyIdentifier ?? "";
                                break;

                            case "2.5.29.35":
                                AuthorityKeyIdentifier = extension.Decoded?.Value?.KeyIdentifier ?? "";
                                break;

                            case "2.5.29.19":
                                if (extension.Decoded?.Value is not null)
                                {
                                    IsCa = extension.Decoded?.Value?.CA ?? false;
                                    PathLenConstraint = extension.Decoded?.Value?.PathLenConstraint ?? 0;
                                }
                                break;

                            case "2.5.29.37":
                                if (extension.Decoded?.Value?.KeyPurposeId is null)
                                    break;

                                OtherEkus = new();
                                foreach (var purpose in extension.Decoded!.Value!.KeyPurposeId!)
                                {
                                    if (purpose == "1.3.6.1.5.5.7.3.8") IsTsp = true;
                                    else if (purpose == "1.3.6.1.5.5.7.3.9") IsOcsp = true;
                                    else if (purpose == "1.3.6.1.4.1.19398.1.1.8.1") IsCmp = true;
                                    else OtherEkus.Add(purpose);
                                }
                                break;

                            case "1.3.6.1.5.5.7.1.3":
                                if (extension.Decoded?.Value?.QcStatements is null)
                                    break;

                                OtherStatements = new();
                                foreach (var statement in extension.Decoded!.Value.QcStatements!)
                                {
                                    if (statement.StatementId == "0.4.0.1862.1.1") IsQualified = true;
                                    else if (statement.StatementId == "0.4.0.1862.1.4") IsQscd = true;
                                    else if (statement.StatementId == "0.4.0.1862.1.5")
                                    {
                                        var asn1Encoded = Convert.FromBase64String(statement.StatementInfo!);
                                        if ((asn1Encoded.Length > 10) && (asn1Encoded[0] == 0x30) && ((asn1Encoded[1] & 0x80) == 0) && (asn1Encoded[2] == 0x30) && (asn1Encoded[4] == 0x16))
                                            QualifiedStatementInfo = Encoding.ASCII.GetString(asn1Encoded, 6, asn1Encoded[5]);
                                        else
                                            QualifiedStatementInfo = statement.StatementInfo;
                                    }
                                    else if (statement.StatementId == "1.2.804.2.1.1.1.2.2") IsOldQualified = true;
                                    else OtherStatements.Add(statement.StatementId);
                                }
                                break;

                            case "2.5.29.17":
                                if (extension.Decoded?.Value?.GeneralNames is null)
                                    break;

                                foreach (var name in extension.Decoded!.Value.GeneralNames!)
                                {
                                    SubjectAltName_Dns = name.Dns;
                                    SubjectAltName_Email = name.Email;
                                }
                                break;

                            case "2.5.29.32":
                                if (extension.Decoded?.Value?.CertificatePolicies is null)
                                    break;

                                CertificatePolicies = new();
                                foreach (var policy in extension.Decoded!.Value.CertificatePolicies!)
                                    CertificatePolicies.Add(policy.PolicyIdentifier);
                                break;

                            case "2.5.29.31":
                                if (extension.Decoded?.Value?.DistributionPoints is null)
                                    break;

                                CRLDistributionPoints = extension.Decoded!.Value.DistributionPoints!;
                                break;

                            case "2.5.29.46":
                                if (extension.Decoded?.Value?.DistributionPoints is null)
                                    break;

                                FreshestCRL = extension.Decoded!.Value.DistributionPoints!;
                                break;

                            case "1.3.6.1.5.5.7.1.1":
                                if (extension.Decoded?.Value?.AccessDescriptions is null)
                                    break;

                                Ocsp = new();
                                CaCerts = new();
                                foreach (var descr in extension.Decoded!.Value!.AccessDescriptions!)
                                {
                                    if (descr.Ocsp is not null) Ocsp.Add(descr.Ocsp);
                                    if (descr.CaIssuers is not null) CaCerts.Add(descr.CaIssuers);
                                }
                                break;

                            case "1.3.6.1.5.5.7.1.11":
                                if (extension.Decoded?.Value?.AccessDescriptions is null)
                                    break;

                                timeStamping = new();
                                foreach (var descr in extension.Decoded!.Value!.AccessDescriptions!)
                                {
                                    if (descr.TimeStamping is not null) timeStamping.Add(descr.TimeStamping);
                                }
                                break;

                            case "2.5.29.9":
                                if (extension.Decoded?.Value?.Attributes is null)
                                    break;

                                foreach (var attrib in extension.Decoded!.Value!.Attributes!)
                                {
                                    if (attrib.Type == "1.2.804.2.1.1.1.11.1.4.1.1") DRFO = attrib.Value;
                                    else if (attrib.Type == "1.2.804.2.1.1.1.11.1.4.2.1") EDRPOU = attrib.Value;
                                    else if (attrib.Type == "1.2.804.2.1.1.1.11.1.4.3.1") NBU = attrib.Value;
                                    else if (attrib.Type == "1.2.804.2.1.1.1.11.1.4.4.1") SPMF = attrib.Value;
                                    else if (attrib.Type == "1.2.804.2.1.1.1.11.1.4.5.1") ORG = attrib.Value;
                                    else if (attrib.Type == "1.2.804.2.1.1.1.11.1.4.6.1") UNIT = attrib.Value;
                                    else if (attrib.Type == "1.2.804.2.1.1.1.11.1.4.7.1") USER = attrib.Value;
                                    else if (attrib.Type == "1.2.804.2.1.1.1.11.1.4.11.1") EDDR = attrib.Value;
                                    else
                                        throw new UapkiException(1);
                                }
                                break;

                            default:
                                break;
                        }
                    }
                    catch { /*do nothing*/ }
                }

                if (DRFO is null && Subject.SERIALNUMBER is not null && Subject.SERIALNUMBER.StartsWith("TINUA-"))
                    DRFO = Subject.SERIALNUMBER.Substring(6);

                if (EDRPOU is null && Subject.OI is not null && Subject.OI.StartsWith("NTRUA-"))
                    EDRPOU = Subject.OI.Substring(6);
            }
        }

        [JsonPropertyName("selfSigned")]
        public bool SelfSigned { get; init; }

        private List<Extension> _extensions { get; init; } = new List<Extension>();

        [JsonIgnore]
        public string Id { get; internal set; } = string.Empty;
        [JsonPropertyName("isCa")]
        public bool IsCa { get; private set; }
        [JsonPropertyName("isTsp")]
        public bool IsTsp { get; private set; }
        [JsonPropertyName("isOcsp")]
        public bool IsOcsp { get; private set; }
        [JsonPropertyName("isCmp")]
        public bool IsCmp { get; private set; }
        [JsonIgnore]
        public bool IsQualified { get; private set; }
        [JsonIgnore]
        public bool IsOldQualified { get; private set; }
        [JsonIgnore]
        public bool IsQscd { get; private set; }
        [JsonIgnore]
        public int PathLenConstraint { get; private set; }
        [JsonIgnore]
        public CertKeyUsage KeyUsage { get; private set; } = new CertKeyUsage();
        [JsonIgnore]
        public string SubjectKeyIdentifier { get; private set; } = string.Empty;
        [JsonIgnore]
        public string AuthorityKeyIdentifier { get; private set; } = string.Empty;
        [JsonIgnore]
        public string? SubjectAltName_Dns { get; private set; }
        [JsonIgnore]
        public string? SubjectAltName_Email { get; private set; }
        [JsonIgnore]
        public string? QualifiedStatementInfo { get; private set; }
        [JsonIgnore]
        public List<string>? OtherEkus { get; private set; }
        [JsonIgnore]
        public List<string>? OtherStatetments { get; private set; }
        [JsonIgnore]
        public List<string>? CertificatePolicies { get; private set; }
        [JsonIgnore]
        public List<string>? CRLDistributionPoints { get; private set; }
        [JsonIgnore]
        public List<string>? FreshestCRL { get; private set; }
        [JsonIgnore]
        public List<string>? Ocsp { get; private set; }
        [JsonIgnore]
        public List<string>? CaCerts { get; private set; }
        [JsonIgnore]
        public List<string>? timeStamping { get; private set; }
        [JsonIgnore]
        public string? DRFO { get; private set; }
        [JsonIgnore]
        public string? EDRPOU { get; private set; }
        [JsonIgnore]
        public string? EDDR { get; private set; }
        [JsonIgnore]
        public string? NBU { get; private set; }
        [JsonIgnore]
        public string? SPMF { get; private set; }
        [JsonIgnore]
        public string? ORG { get; private set; }
        [JsonIgnore]
        public string? UNIT { get; private set; }
        [JsonIgnore]
        public string? USER { get; private set; }
    }

    public class CertInfoResult
    {
        public int ErrorCode { get; init; }
        public string? Method { get; init; }
        public Certificate? Result { get; init; }
    }

    public static Certificate GetCertInfo(string certId)
    {
        CheckInit();

        string cert_info_cmd = "{\"method\":\"CERT_INFO\",\"parameters\":{\"certId\":\"" + certId + "\"}}";

        var ret = JsonSerializer.Deserialize(Process(cert_info_cmd), jsonCtx.CertInfoResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0)
            throw new UapkiException(ret.ErrorCode);

        if (ret.Result is null)
            throw new UapkiException(0x1005);

        var cert = ret.Result;
        cert.Id = certId;
        return cert;
    }

    public class CertificateShortInfo
    {
        [JsonPropertyName("certId")]
        public string CertId { get; init; } = string.Empty;
        [JsonPropertyName("serialNumber")]
        public string SerialNumber { get; init; } = string.Empty;
        [JsonPropertyName("issuer")]
        public DistinguishedName Issuer { get; init; } = new DistinguishedName();
        [JsonPropertyName("subject")]
        public DistinguishedName Subject { get; init; } = new DistinguishedName();
        [JsonPropertyName("validity")]
        public Validity Validity { get; init; } = new Validity();
        [JsonPropertyName("subjectKeyIdentifier")]
        public string SubjectKeyIdentifier { get; init; } = string.Empty;
        [JsonPropertyName("authorityKeyIdentifier")]
        public string AuthorityKeyIdentifier { get; init; } = string.Empty;
        [JsonPropertyName("keyUsage")]
        public CertKeyUsage KeyUsage { get; init; } = new CertKeyUsage();
        [JsonPropertyName("extendedKeyUsage")]
        public List<string> ExtendedKeyUsage { get; init; } = new List<string>();
        [JsonPropertyName("isCa")]
        public bool? IsCa { get; init; }
        [JsonPropertyName("isTsp")]
        public bool? IsTsp { get; init; }
        [JsonPropertyName("isOcsp")]
        public bool? IsOcsp { get; init; }
        [JsonPropertyName("isCmp")]
        public bool? IsCmp { get; init; }

        [JsonPropertyName("keyAlgo")]
        public string KeyAlgoRaw { get; init; } = string.Empty;

        [JsonIgnore]
        public KeyAlgo KeyAlgo => KeyAlgoRaw.ToKeyAlgo();

        [JsonPropertyName("keyAlgoName")]
        public string KeyAlgoName => KeyAlgo.DisplayName();
    }

    private class CertsList
    {
        [JsonPropertyName("certIds")]
        public List<string>? CertIds { get; init; }
        [JsonPropertyName("certInfos")]
        public List<CertificateShortInfo>? CertInfos { get; init; }
    }

    private class CertsListResult
    {
        public int ErrorCode { get; init; }
        public string? Method { get; init; }
        public CertsList? Result { get; init; }
    }

    private class ListCertsParams
    {
        public bool? Storage { get; init; }
        public bool? ShowCertInfos { get; init; }
        public int? Offset { get; init; }
        public int? PageSize { get; init; }
        public List<string>? SubjectKeyIdentifiers { get; init; }
    }

    public static List<CertificateShortInfo> GetCertsShortInfoList(bool storage = false, int offset = 0, int? pageSize = null, List<string>? keyIds = null)
    {
        CheckInit();

        var parameters = new ListCertsParams()
        {
            Storage = storage,
            ShowCertInfos = true,
            Offset = offset,
            PageSize = pageSize,
            SubjectKeyIdentifiers = keyIds
        };

        string list_certs_cmd = "{\"method\":\"LIST_CERTS\",\"parameters\":" + JsonSerializer.Serialize(parameters, jsonCtx.ListCertsParams) + "}";

        var ret = JsonSerializer.Deserialize(Process(list_certs_cmd), jsonCtx.CertsListResult) ?? throw new UapkiException(0x2001);
        if (ret.Result?.CertInfos is null)
            return new List<CertificateShortInfo>();

        return ret.Result.CertInfos;
    }

    public static List<string> GetCerts(bool storage = false, List<string>? keyIds = null)
    {
        CheckInit();

        var parameters = new ListCertsParams()
        {
            Storage = storage,
            ShowCertInfos = false,
            SubjectKeyIdentifiers = keyIds
        };

        string list_certs_cmd = "{\"method\":\"LIST_CERTS\",\"parameters\":" + JsonSerializer.Serialize(parameters, jsonCtx.ListCertsParams) + "}";

        var ret = JsonSerializer.Deserialize(Process(list_certs_cmd), jsonCtx.CertsListResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0)
            throw new UapkiException(ret.ErrorCode);

        if (ret.Result?.CertIds is null)
            return new List<string>();

        return ret.Result.CertIds;
    }

    private class CertRemoveParams
    {
        public string? CertId { get; init; }
        public bool? Storage { get; init; }
        public bool? Permanent { get; init; }
    }

    public static void RemoveCert(string certId, bool storage = false, bool permanent = true)
    {
        CheckInit();

        if (storage)
            CheckStorage(KeyStorageOpenMode.RW);

        var parameters = new CertRemoveParams() { CertId = certId, Storage = storage, Permanent = permanent };
        string cert_remove_cmd = "{\"method\":\"REMOVE_CERT\",\"parameters\":" + JsonSerializer.Serialize(parameters, jsonCtx.CertRemoveParams) + "}";

        var ret = JsonSerializer.Deserialize(Process(cert_remove_cmd), jsonCtx.ErrorCodeResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0)
            throw new UapkiException(ret.ErrorCode);
    }

    public static void RemoveCert(Certificate cert, bool storage = false, bool permanent = true)
    {
        RemoveCert(cert.Id, storage, permanent);
    }

    private class BytesOnly
    {
        public byte[]? Bytes { get; init; }
    }

    private class BytesResult
    {
        public int ErrorCode { get; init; }
        public string? Method { get; init; }
        public BytesOnly? Result { get; init; }
    }

    public static byte[]? GetCert(string certId)
    {
        CheckInit();

        string get_cert_cmd = "{\"method\":\"GET_CERT\",\"parameters\":{\"certId\":\"" + certId + "\"}}";

        var ret = JsonSerializer.Deserialize(Process(get_cert_cmd), jsonCtx.BytesResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0)
            throw new UapkiException(ret.ErrorCode);

        return ret.Result?.Bytes;
    }

    private class CertsAddParams
    {
        public List<byte[]>? Certificates { get; init; }
        public byte[]? Bundle { get; init; }
        public bool? Storage { get; init; }
        public bool? Permanent { get; init; }
    }

    public class AddedCert
    {
        public string CertId { get; init; } = string.Empty;
        public bool IsUnique { get; init; }
    }

    private class AddedCerts
    {
        public List<AddedCert>? Added { get; init; }
    }

    private class CertsAddResult
    {
        public int ErrorCode { get; init; }
        public string? Method { get; init; }
        public AddedCerts? Result { get; init; }
    }

    public static List<AddedCert> ImportCerts(List<byte[]> certs, bool storage = false, bool permanent = true)
    {
        if (storage)
            CheckStorage(KeyStorageOpenMode.RW);
        else CheckInit();

        var parameters = new CertsAddParams()
        {
            Certificates = certs,
            Permanent = permanent,
            Storage = storage
        };

        string cert_add_cmd = "{\"method\":\"ADD_CERT\",\"parameters\":" + JsonSerializer.Serialize(parameters, jsonCtx.CertsAddParams) + "}";

        var ret = JsonSerializer.Deserialize(Process(cert_add_cmd), jsonCtx.CertsAddResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0)
            throw new UapkiException(ret.ErrorCode);

        return ret.Result?.Added is null ? new List<AddedCert>() : ret.Result.Added;
    }

    public static AddedCert? ImportCert(byte[] cert, bool storage = false, bool permanent = true)
    {
        var addedCerts = ImportCerts(new List<byte[]>() { cert }, storage, permanent);
        return addedCerts.Count > 0 ? addedCerts[0] : null;
    }

    public static int ImportCertBundle(byte[] bundle, bool storage = false, bool permanent = true)
    {
        if (storage)
            CheckStorage(KeyStorageOpenMode.RW);
        else CheckInit();

        var parameters = new CertsAddParams()
        {
            Bundle = bundle,
            Permanent = permanent,
            Storage = storage
        };

        string cert_add_bundle_cmd = "{\"method\":\"ADD_CERT\",\"parameters\":" + JsonSerializer.Serialize(parameters, jsonCtx.CertsAddParams) + "}";

        var ret = JsonSerializer.Deserialize(Process(cert_add_bundle_cmd), jsonCtx.CertsAddResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0)
            throw new UapkiException(ret.ErrorCode);

        if (ret.Result?.Added is null)
            return 0;

        return ret.Result.Added.Where(r => r.IsUnique).Count();
    }

    private class CertVerifyParams
    {
        public byte[]? Bytes { get; init; }
        public string? CertId { get; init; }
        public string? ValidationType { get; init; }
        public string? ValidateTime { get; init; }
    }

    public class CrlShortInfo
    {
        public string? Url { get; init; }
        public string CrlId { get; init; } = string.Empty;
        public string StatusSignature { get; init; } = string.Empty;
    }

    public class ValidateByCrlInfo
    {
        public string Status { get; init; } = string.Empty;
        public string? RevocationReason { get; init; }

        [JsonPropertyName("revocationTime")]
        public string? RevocationTimeRaw { get; init; }

        [JsonIgnore]
        public  DateTime? RevocationTime => RevocationTimeRaw != null ? ConvertUtcTimeToDateTime(RevocationTimeRaw) : null;
        public CrlShortInfo Full { get; init; } = new CrlShortInfo();
        public CrlShortInfo? Delta { get; init; }
    }

    public class ValidateByOcspInfo
    {
        public string Status { get; init; } = string.Empty;
        public string? RevocationReason { get; init; }

        [JsonPropertyName("revocationTime")]
        public string? RevocationTimeRaw { get; init; }

        [JsonIgnore]
        public  DateTime? RevocationTime => RevocationTimeRaw != null ? ConvertUtcTimeToDateTime(RevocationTimeRaw) : null;

        public string ResponseStatus { get; init; } = string.Empty;
        public OcspResponderIdentifier? ResponderId { get; init; }
        public string StatusSignature { get; init; } = string.Empty;

        [JsonPropertyName("producedAt")]
        public string ProducedAtRaw { get; init; } = string.Empty;

        [JsonIgnore]
        public  DateTime ProducedAt => ConvertUtcTimeToDateTime(ProducedAtRaw);

        [JsonPropertyName("thisUpdate")]
        public string ThisUpdateRaw { get; init; } = string.Empty;

        [JsonIgnore]
        public  DateTime ThisUpdate => ConvertUtcTimeToDateTime(ThisUpdateRaw);

        [JsonPropertyName("NextUpdate")]
        public string? NextUpdateRaw { get; init; }

        [JsonIgnore]
        public  DateTime? NextUpdate => NextUpdateRaw != null ? ConvertUtcTimeToDateTime(NextUpdateRaw) : null;
        public List<string>? CertIds { get; init; }
    }

    public class CertValidation
    {
        [JsonPropertyName("validateTime")]
        public string ValidateTimeRaw { get; init; } = string.Empty;

        [JsonIgnore]
        public  DateTime ValidateTime => ConvertUtcTimeToDateTime(ValidateTimeRaw);
        public string SubjectCertId { get; init; } = string.Empty;
        public Validity Validity { get; init; } = new Validity();
        public bool Expired { get; init; }
        public bool SelfSigned { get; init; }
        public bool Trusted { get; init; }
        public string StatusSignature { get; init; } = string.Empty;
        public string? IssuerCertId { get; init; }
        public ValidateByCrlInfo? ValidateByCRL { get; init; }
        public ValidateByOcspInfo? ValidateByOCSP { get; init; }
    }

    private class CertVerifyResult
    {
        public int ErrorCode { get; init; }
        public string? Method { get; init; }
        public CertValidation? Result { get; init; }
    }

    public static CertValidation VerifyCert(byte[] cert, bool useOCSP = false, bool useCRL = false, DateTime? validateTime = null)
    {
        string? validationType = null;
        if (validateTime != null || useCRL)
            validationType = "CRL";
        else if (useOCSP)
            validationType = "OCSP";

        var parameters = new CertVerifyParams()
        {
            Bytes = cert,
            ValidationType = validationType,
            ValidateTime = validateTime?.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
        };

        string verify_cert_cmd = "{\"method\":\"VERIFY_CERT\",\"parameters\":" + JsonSerializer.Serialize(parameters, jsonCtx.CertVerifyParams) + "}";

        var ret = JsonSerializer.Deserialize(Process(verify_cert_cmd), jsonCtx.CertVerifyResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0)
            throw new UapkiException(ret.ErrorCode);

        if (ret.Result is null)
            throw new UapkiException(0x2001);

        return ret.Result;
    }

    public static CertValidation VerifyCert(string certId, bool useOCSP = false, bool useCRL = false, DateTime? validateTime = null)
    {
        string? validationType = null;
        if (validateTime is not null || useCRL)
            validationType = "CRL";
        else if (useOCSP)
            validationType = "OCSP";

        var parameters = new CertVerifyParams()
        {
            CertId = certId,
            ValidationType = validationType,
            ValidateTime = validateTime?.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
        };

        string verify_cert_cmd = "{\"method\":\"VERIFY_CERT\",\"parameters\":" + JsonSerializer.Serialize(parameters, jsonCtx.CertVerifyParams) + "}";

        var ret = JsonSerializer.Deserialize(Process(verify_cert_cmd), jsonCtx.CertVerifyResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0)
            throw new UapkiException(ret.ErrorCode);

        if (ret.Result is null)
            throw new UapkiException(0x2001);

        return ret.Result;
    }

    private class GetCertByOcspResult
    {
        public int ErrorCode { get; init; }
        public string? Method { get; init; }
        public ValidateByOcspInfo? Result { get; init; }
    }

    public static ValidateByOcspInfo GetCertByOcsp(string url, string issuerCertId, string serialNumber)
    {
        string get_cert_by_ocsp_cmd = "{\"method\":\"CERT_STATUS_BY_OCSP\",\"parameters\":{" +
            "\"url\":\"" + url + "\"," +
            "\"issuerCertId\":\"" + issuerCertId + "\"," +
            "\"serialNumber\":\"" + serialNumber + "\"}}";

        var ret = JsonSerializer.Deserialize(Process(get_cert_by_ocsp_cmd), jsonCtx.GetCertByOcspResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0)
            throw new UapkiException(ret.ErrorCode);

        if (ret.Result is null)
            throw new UapkiException(0x2001);

        return ret.Result;
    }
}
