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

using System.Text.Json;
using System.Text.Json.Serialization;

namespace UapkiNet;

public partial class Uapki
{
    /// <summary>A status of a trust service in time</summary>
    public class TrustServiceStatus
    {
        /// <summary>The last part of the status identifier: "granted", "withdrawn", "recognisedatnationallevel"...</summary>
        public string Status { get; init; } = string.Empty;
        public string? From { get; init; }
        /// <summary>Absent for the current status</summary>
        public string? To { get; init; }
    }

    /// <summary>A service of a trusted list a certificate is the certificate of</summary>
    public class TrustService
    {
        public string ListId { get; init; } = string.Empty;
        /// <summary>The part of the type identifier after "/Svctype/": "CA/QC", "TSA/QTST", "Certstatus/OCSP/QC"...</summary>
        public string Type { get; init; } = string.Empty;
        public string? TspName { get; init; }
        public string? ServiceName { get; init; }
        public bool ForESignatures { get; init; }
        public bool ForESeals { get; init; }
        /// <summary>The first is the current status, then the previous ones</summary>
        public List<TrustServiceStatus>? Statuses { get; init; }
    }

    /// <summary>The result of ADD_TRUST_LIST</summary>
    public class TrustListInfo
    {
        public string ListId { get; init; } = string.Empty;
        public string? Type { get; init; }
        public string? Territory { get; init; }
        /// <summary>The name of the scheme: in English if the list has it, else the first one</summary>
        public string? SchemeName { get; init; }
        public string? SchemeOperatorName { get; init; }
        public ulong SequenceNumber { get; init; }
        public string? ListIssueDateTime { get; init; }
        public string? NextUpdate { get; init; }
        public string? SignerCertId { get; init; }
        public uint CountProviders { get; init; }
        public uint CountServices { get; init; }
        public uint CountCerts { get; init; }
        public uint CountAddedCerts { get; init; }
        public uint CountTrustedCerts { get; init; }
        public uint CountSkippedCerts { get; init; }
        /// <summary>The list is saved in the directory of trusted lists</summary>
        public bool Stored { get; init; }
        /// <summary>Remarks on the certificate that signs the list (ETSI TS 119 612, 5.7.1)</summary>
        public List<string>? Warnings { get; init; }
        //  Of a refused list
        public string? Detail { get; init; }
        public string? XmlError { get; init; }
        public long? XmlErrorOffset { get; init; }
    }

    /// <summary>An accepted trusted list (LIST_TRUST_LISTS)</summary>
    public class AcceptedTrustList
    {
        public string ListId { get; init; } = string.Empty;
        public string? Type { get; init; }
        public string? Territory { get; init; }
        /// <summary>The name of the scheme: in English if the list has it, else the first one</summary>
        public string? SchemeName { get; init; }
        public string? SchemeOperatorName { get; init; }
        public ulong SequenceNumber { get; init; }
        public string? ListIssueDateTime { get; init; }
        public string? NextUpdate { get; init; }
        /// <summary>The next update time of the list is passed: the list is to be obtained again</summary>
        public bool NextUpdatePassed { get; init; }
        public string? SignerCertId { get; init; }
        public uint CountCerts { get; init; }
        public uint CountTrustedCerts { get; init; }
        public bool Stored { get; init; }

        /// <summary>ListIssueDateTime, UTC; null - absent</summary>
        [JsonIgnore]
        public DateTime? ListIssueTime => string.IsNullOrEmpty(ListIssueDateTime) ? null : ConvertUtcTimeToDateTime(ListIssueDateTime);
        /// <summary>NextUpdate, UTC; null - absent (a closed list)</summary>
        [JsonIgnore]
        public DateTime? NextUpdateTime => string.IsNullOrEmpty(NextUpdate) ? null : ConvertUtcTimeToDateTime(NextUpdate);
    }

    public class TrustListsInfo
    {
        public List<AcceptedTrustList>? TrustLists { get; init; }
    }

    public class TrustListsResult
    {
        public int ErrorCode { get; init; }
        public string? Method { get; init; }
        public TrustListsInfo? Result { get; init; }
    }

    public class TrustListAddResult
    {
        public int ErrorCode { get; init; }
        public string? Method { get; init; }
        public TrustListInfo? Result { get; init; }
    }

    /// <summary>
    /// Adds a trusted list (ETSI TS 119 612, XML). The list is accepted if it is signed by one of the certificates of
    /// Config.TrustListCache.TrustListSignerCerts and its sequence number is not less than the accepted one
    /// </summary>
    public TrustListInfo AddTrustList(byte[] trustList)
    {
        CheckInit();

        string cmd = Request("ADD_TRUST_LIST", p => p.WriteBase64String("bytes", trustList));
        return TrustListResult(cmd);
    }

    /// <summary>Adds a trusted list given as the text of the XML document</summary>
    public TrustListInfo AddTrustListText(string trustList)
    {
        CheckInit();

        string cmd = Request("ADD_TRUST_LIST", p => p.WriteString("text", trustList));
        return TrustListResult(cmd);
    }

    /// <summary>The accepted trusted lists: the last accepted version of every list</summary>
    public List<AcceptedTrustList> ListTrustLists()
    {
        CheckInit();

        var ret = JsonSerializer.Deserialize(Process(Request("LIST_TRUST_LISTS")), jsonCtx.TrustListsResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0)
            throw new UapkiException(ret.ErrorCode);

        return ret.Result?.TrustLists ?? new List<AcceptedTrustList>();
    }

    private TrustListInfo TrustListResult(string cmd)
    {
        var ret = JsonSerializer.Deserialize(Process(cmd), jsonCtx.TrustListAddResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0)
            throw new UapkiException(ret.ErrorCode);

        return ret.Result ?? throw new UapkiException(0x1005);
    }
}
