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
using UapkiNet.Polyfil;

namespace UapkiNet;

public static partial class Uapki
{
    public class RevokedCertInfo
    {
        [JsonPropertyName("userCertificate")]
        public string UserCertificateRaw { get; init; } = string.Empty;

        [JsonPropertyName("revocationDate")]
        public string RevocationDateRaw { get; init; } = string.Empty;

        [JsonPropertyName("crlReason")]
        public string CrlReasonRaw { get; init; } = string.Empty;

        [JsonPropertyName("invalidityDate")]
        public string? InvalidityDateRaw { get; init; }

        [JsonIgnore]
        public byte[] UserCertificate => Hex.FromHexString(UserCertificateRaw);

        [JsonIgnore]
        public DateTime RevocationDate => ConvertUtcTimeToDateTime(RevocationDateRaw);

        [JsonIgnore]
        public short CrlReason => CrlReasonRaw switch
        {
            "UNDEFINED" => 0,
            "UNSPECIFIED" => 0,
            "KEY_COMPROMISE" => 1,
            "CA_COMPROMISE" => 2,
            "AFFILIATION_CHANGED" => 3,
            "SUPERSEDED" => 4,
            "CESSATION_OF_OPERATION" => 5,
            "CERTIFICATE_HOLD" => 6,
            "REMOVE_FROM_CRL" => 8,
            "PRIVILEGE_WITHDRAWN" => 9,
            "AA_COMPROMISE" => 10,
            _ => throw new ArgumentOutOfRangeException("crlReason", CrlReasonRaw, "Unknown CRL reason code")
        };

        [JsonIgnore]
        public  DateTime? InvalidityDate => InvalidityDateRaw is null ? null : ConvertUtcTimeToDateTime(InvalidityDateRaw);
    }

    public class CrlInfo
    {
        public string CrlId { get; init; } = string.Empty;
        public DistinguishedName Issuer { get; init; } = new DistinguishedName();

        [JsonPropertyName("thisUpdate")]
        public string ThisUpdateRaw { get; init; } = string.Empty;
        [JsonPropertyName("nextUpdate")]
        public string NextUpdateRaw { get; init; } = string.Empty;

        public int CountRevokedCerts { get; init; }
        public string AuthorityKeyId { get; init; } = string.Empty;

        [JsonPropertyName("crlNumber")]
        public string CrlNumberRaw { get; init; } = string.Empty;
        [JsonPropertyName("deltaCrlIndicator")]
        public string? DeltaCrlIndicatorRaw { get; init; }
        public List<RevokedCertInfo>? RevokedCerts { get; init; }
        public List<string>? FreshestCRL { get; init; }
        [JsonIgnore]
        public DateTime ThisUpdate => ConvertUtcTimeToDateTime(ThisUpdateRaw);

        [JsonIgnore]
        public DateTime NextUpdate => ConvertUtcTimeToDateTime(NextUpdateRaw);

        [JsonIgnore]
        public BigInteger CrlNumber => BigInteger.Parse(CrlNumberRaw, NumberStyles.HexNumber, CultureInfo.InvariantCulture);

        [JsonIgnore]
        public BigInteger? DeltaCrlIndicator => DeltaCrlIndicatorRaw is null ? null : BigInteger.Parse(DeltaCrlIndicatorRaw, NumberStyles.HexNumber, CultureInfo.InvariantCulture);

        [JsonIgnore]
        public bool IsObsolete { get { return (DateTime.UtcNow > NextUpdate); } }
    }

    public class CrlInfoResult
    {
        public int ErrorCode { get; init; }
        public string? Method { get; init; }
        public CrlInfo? Result { get; init; }
    }

    public static CrlInfo GetCrlInfo(string crlId, bool showRevokedCerts = true)
    {
        CheckInit();

        string crl_info_cmd = "{\"method\":\"CRL_INFO\",\"parameters\":{\"crlId\":\"" + crlId + "\",\"showRevokedCerts\":" + (showRevokedCerts ? "true" : "false") + "}}";

        var ret = JsonSerializer.Deserialize(Process(crl_info_cmd), jsonCtx.CrlInfoResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0)
            throw new UapkiException(ret.ErrorCode);

        if (ret.Result is null)
            throw new UapkiException(0x2001);

        return ret.Result;
    }

    public static CrlInfo GetCrlInfo(byte[] bytes)
    {
        string crl_info_cmd = "{\"method\":\"CRL_INFO\",\"parameters\":{\"bytes\":\"" + Convert.ToBase64String(bytes) + "\"}}";

        var ret = JsonSerializer.Deserialize(Process(crl_info_cmd), jsonCtx.CrlInfoResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0)
            throw new UapkiException(ret.ErrorCode);

        return ret.Result ?? throw new UapkiException(0x2001);
    }

    public class CrlAddResponse
    {
        public string CrlId { get; init; } = string.Empty;
        public bool IsUnique { get; init; }
    }

    public class CrlAddResult
    {
        public int ErrorCode { get; init; }
        public string? Method { get; init; }
        public CrlAddResponse? Result { get; init; }
    }

    public static void ImportCrl(byte[] crl, bool permanent = true)
    {
        CheckInit();

        string add_crl_cmd = "{\"method\":\"ADD_CRL\",\"parameters\":{\"bytes\":\"" + Convert.ToBase64String(crl) + "\",\"permanent\":" + (permanent ? "true" : "false") + "}}";

        var ret = JsonSerializer.Deserialize(Process(add_crl_cmd), jsonCtx.CrlAddResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0)
            throw new UapkiException(ret.ErrorCode);
    }

    public static void RemoveCrl(string crlId, bool permanent = true)
    {
        CheckInit();

        string remove_crl_cmd = "{\"method\":\"REMOVE_CRL\",\"parameters\":{\"crlId\":\"" + crlId + "\",\"permanent\":" + (permanent ? "true" : "false") + "}}";

        var ret = JsonSerializer.Deserialize(Process(remove_crl_cmd), jsonCtx.ErrorCodeResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0)
            throw new UapkiException(ret.ErrorCode);
    }

    private class CrlsList
    {
        public List<string> CrlIds { get; init; } = new List<string>();
        public int Count { get; init; }
        public int Offset { get; init; }
        public int PageSize { get; init; }
        public List<CrlInfo>? CrlInfos { get; init; }
    }

    private class CrlsListResult
    {
        public int ErrorCode { get; init; }
        public string? Method { get; init; }
        public CrlsList? Result { get; init; }
    }

    public static List<CrlInfo> GetAllCrls(bool showCrlInfos = true, int offset = 0, int? pageSize = null)
    {
        CheckInit();

        string list_crls_cmd = "{\"method\":\"LIST_CRLS\",\"parameters\":{\"showCrlInfos\":" + (showCrlInfos ? "true" : "false") + ",\"offset\":" + offset.ToString() + ",\"pageSize\":" + (pageSize?.ToString() ?? "null") + "}}";

        var ret = JsonSerializer.Deserialize(Process(list_crls_cmd), jsonCtx.CrlsListResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0)
            throw new UapkiException(ret.ErrorCode);

        if (ret.Result?.CrlInfos is not null)
            return ret.Result!.CrlInfos;

        return new List<CrlInfo>();
    }
}
