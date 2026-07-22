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

using System.Globalization;
using System.Numerics;
using System.Text.Json;
using System.Text.Json.Serialization;
using UapkiNet.JsonConverters;

namespace UapkiNet;

public static partial class Uapki
{
    public class SignaturePolicy
    {
        public string SigPolicyId { get; init; } = string.Empty;
    }

    public class TimeStampInfo
    {
        [JsonPropertyName("genTime")]
        public string GenTimeRaw { get; init; } = string.Empty;

        [JsonIgnore]
        public DateTime GenTime => ConvertUtcTimeToDateTime(GenTimeRaw);

        public string PolicyId { get; init; } = string.Empty;

        [JsonPropertyName("hashAlgo")]
        public string HashAlgoOid { get; init; } = string.Empty;

        [JsonPropertyName("hashedMessage")]
        public string HashedMessageRaw { get; init; } = string.Empty;

        public string StatusDigest { get; init; } = string.Empty;
        public string StatusSignature { get; init; } = string.Empty;
        public string SignerCertId { get; init; } = string.Empty;
    }

    public class HashInfo
    {
        [JsonPropertyName("hashAlgo")]
        public string? HashAlgoOid { get; init; }
        public string? HashAlgoParams { get; init; }
        public byte[]? HashValue { get; init; }
    }

    public class CertRefInfo
    {
        public HashInfo? CertHash { get; init; }
        public DistinguishedName? Issuer { get; init; }
        public string? SerialNumber { get; init; }
        public string? Status { get; init; }
    }

    public class CrlId
    {
        public DistinguishedName? CrlIssuer { get; init; }

        [JsonPropertyName("crlIssuedTime")]
        public string CrlIssuedTimeRaw { get; init; } = string.Empty;

        [JsonIgnore]
        public  DateTime CrlIssuedTime => ConvertUtcTimeToDateTime(CrlIssuedTimeRaw);

        [JsonPropertyName("crlNumber")]
        public string? CrlNumberRaw { get; init; }

        [JsonIgnore]
        public  BigInteger? CrlNumber => CrlNumberRaw != null ? BigInteger.Parse(CrlNumberRaw, NumberStyles.HexNumber, CultureInfo.InvariantCulture) : null;
    }

    [JsonConverter(typeof(KeyIdOrDistinguishedNameConverter))]
    public class OcspResponderIdentifier
    {
        public string? IdByKeyId { get; init; }
        public DistinguishedName? IdByName { get; init; }
    }

    public class OcspIdentifier
    {
        public OcspResponderIdentifier ResponderId { get; init; } = new OcspResponderIdentifier();

        [JsonPropertyName("producedAt")]
        public string ProducedAtRaw { get; init; } = string.Empty;

        [JsonIgnore]
        public DateTime ProducedAt => ConvertUtcTimeToDateTime(ProducedAtRaw);
    }

    public class OcspId
    {
        public OcspIdentifier OcspIdentifier { get; init; } = new OcspIdentifier();
        public HashInfo? OcspHash { get; init; } = new HashInfo();
    }

    public class RevocationRefInfo
    {
        public List<CrlId>? CrlIds { get; init; }
        public List<OcspId>? OcspIds { get; init; }
    }

    public class CertChainInfo
    {
        public string SubjectCertId { get; init; } = string.Empty;
        [JsonPropertyName("CN")]
        public string CN { get; init; } = string.Empty;
        public string Entity { get; init; } = string.Empty;
        public string Source { get; init; } = string.Empty;
        public Validity Validity { get; init; } = new Validity();
        public bool Expired { get; init; }
        public bool SelfSigned { get; init; }
        public bool Trusted { get; init; }
        public string IssuerCertId { get; init; } = string.Empty;
        public string StatusSignature { get; init; } = string.Empty;
        public string StatusValidation { get; init; } = string.Empty;
    }

    public class ExpectedCertInfo
    {
        public string Entity { get; init; } = string.Empty;
        public DistinguishedName? Issuer { get; init; }
        public string? SerialNumber { get; init; }
        public string? KeyId { get; init; }
    }

    public class CrlFullInfo
    {
        public string CrlNumber { get; init; } = string.Empty;

        [JsonPropertyName("thisUpdate")]
        public string ThisUpdateRaw { get; init; } = string.Empty;

        [JsonPropertyName("nextUpdate")]
        public string NextUpdateRaw { get; init; } = string.Empty;
    }

    public class ExpectedCrlInfo
    {
        public string AuthorityKeyId { get; init; } = string.Empty;
        public DistinguishedName? Issuer { get; init; }
        public string? Url { get; init; }
        public CrlFullInfo? Full { get; init; }
    }

    public class SignatureData
    {
        public string SignerCertId { get; init; } = string.Empty;
        public Certificate? SignerCertInfo { get; set; }
        public string SignatureFormat { get; init; } = string.Empty;
        public string Status { get; init; } = string.Empty;
        public bool ValidSignatures { get; init; }
        public bool ValidDigests { get; init; }
        [JsonPropertyName("bestSignatureTime")]
        public string BestSignatureTimeRaw { get; init; } = string.Empty;

        [JsonIgnore]
        public  DateTime BestSignatureTime => ConvertUtcTimeToDateTime(BestSignatureTimeRaw);

        [JsonPropertyName("signAlgo")]
        public string SignAlgoOid { get; init; } = string.Empty;

        [JsonIgnore]
        public  SignAlgo SignAlgo => SignAlgoOid.ToSignAlgo();

        [JsonPropertyName("digestAlgo")]
        public string DigestAlgoOid { get; init; } = string.Empty;

        public string StatusSignature { get; init; } = string.Empty;
        public string StatusMessageDigest { get; init; } = string.Empty;

        [JsonPropertyName("signingTime")]
        public string? SigningTimeRaw { get; init; }
        [JsonIgnore]
        public  DateTime? SigningTime => SigningTimeRaw != null ? ConvertUtcTimeToDateTime(SigningTimeRaw) : null;

        public SignaturePolicy? SignaturePolicy { get; init; }
        public string StatusEssCert { get; init; } = string.Empty;
        public TimeStampInfo? ContentTS { get; init; }
        public TimeStampInfo? SignatureTS { get; init; }
        public TimeStampInfo? ArchiveTS { get; init; }
        public string? StatusCertificateRefs { get; init; }
        public List<CertRefInfo>? CertificateRefs { get; init; }
        public List<string>? CertValues { get; init; }
        public List<RevocationRefInfo>? RevocationRefs { get; init; }
        public List<AttributeInfo>? SignedAttributes { get; init; }
        public List<AttributeInfo>? UnsignedAttributes { get; init; }
        public List<CertChainInfo>? CertificateChain { get; init; }
        public List<ExpectedCertInfo>? ExpectedCerts { get; init; }
        public List<ExpectedCrlInfo>? ExpectedCrls { get; init; }
        public List<string>? Warnings { get; init; }
    }

    public class ContentInfo
    {
        public string Type { get; init; } = string.Empty;
        public byte[] Bytes { get; init; } = Array.Empty<byte>();
    }

    public class ValidationResult
    {
        public ContentInfo? Content { get; init; }
        public List<string>? CertIds { get; init; }
        public List<SignatureData>? SignatureInfos { get; init; }
        public string? StatusSignature { get; init; } = string.Empty;
    }

    private class VerifyResult
    {
        public int ErrorCode { get; init; }
        public string? Method { get; init; }
        public ValidationResult? Result { get; init; }
    }

    private class SignedData
    {
        public byte[] Bytes { get; init; } = Array.Empty<byte>();
        public byte[]? Content { get; init; }
        public string? File { get; init; }
    }

    public class ValidationOptions
    {
        public string? ValidationType { get; init; }
    }

    private class VerifyParams
    {
        public SignedData? Signature { get; init; }
        public ValidationOptions? Options {get; init; }
    }

    public static ValidationResult Verify(byte[] signature, byte[]? content, string validationType = "FULL")
    {
        var parameters = new VerifyParams()
        {
            Signature = new SignedData()
            {
                Bytes = signature,
                Content = content
            },
            Options = new() { ValidationType = validationType }
        };

        string verify_cmd = "{\"method\":\"VERIFY\",\"parameters\":" + JsonSerializer.Serialize(parameters, jsonCtx.VerifyParams) + "}";

        var ret = JsonSerializer.Deserialize(Process(verify_cmd), jsonCtx.VerifyResult) ?? throw new UapkiException(0x2001);
        if (ret.Result?.SignatureInfos is not null)
        {
            // add signer cert info?
            return ret.Result;
        }
        else
        {
            if (ret.ErrorCode != 0)
                throw new UapkiException(ret.ErrorCode);

            return ret.Result!;
        }
    }

    public static ValidationResult Verify(string file, string validationType = "FULL")
    {
        var fi = new FileInfo(file);
        if (fi.Length > 512 * 1024 * 1024)
            throw new UapkiException("Поточна версія не підтримує підпис з інкапсуляцією даних для файлів, більших за 512 МБ");

        var signature = File.ReadAllBytes(file);
        var ext = fi.Extension;

        var parameters = new VerifyParams()
        {
            Signature = new() { Bytes = signature },
            Options = new() { ValidationType = validationType }
        };

        string verify_cmd = "{\"method\":\"VERIFY\",\"parameters\":" + JsonSerializer.Serialize(parameters, jsonCtx.VerifyParams) + "}";

        var ret = JsonSerializer.Deserialize(Process(verify_cmd), jsonCtx.VerifyResult) ?? throw new UapkiException(0x2001);
        if (ext == ".p7s" && ret.Result?.Content?.Bytes is not null)
        {
            // try store incapsulated content
            try { File.WriteAllBytes(file.Substring(0, file.Length - 4), ret.Result.Content.Bytes); } catch { /*do nothing*/ }
        }
        else if ((ret.ErrorCode == 0x1033) && (ext == ".p7s") && File.Exists(file.Substring(0, file.Length - 4)))
        {
            var f = file.Substring(0, file.Length - 4);

            var parameters2 = new VerifyParams()
            {
                Signature = new() { Bytes = signature, File = f },
                Options = new() { ValidationType = validationType }
            };

            verify_cmd = "{\"method\":\"VERIFY\",\"parameters\":" + JsonSerializer.Serialize(parameters2, jsonCtx.VerifyParams) + "}";

            ret = JsonSerializer.Deserialize(Process(verify_cmd), jsonCtx.VerifyResult) ?? throw new UapkiException(0x2001);
        }

        if (ret.Result?.SignatureInfos is not null)
        {
            // add signer cert info?
            return ret.Result;
        }
        else
        {
            if (ret.ErrorCode != 0)
                throw new UapkiException(ret.ErrorCode);

            return ret.Result!;
        }
    }
}
