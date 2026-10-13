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

namespace UapkiNet;

public partial class Uapki
{
    /// <summary>
    /// The options of the AUGMENT_CMS method; a property that is null is not sent (the default of the library)
    /// </summary>
    public class AugmentOptions
    {
        /// <summary>Freshness of the revocation data, minutes 0-120 (0 - always new data); default 120</summary>
        public uint? RevocationFreshness { get; init; }
        /// <summary>Use CRLs only (by default as "validationByCrl" of INIT)</summary>
        public bool? OnlyCrl { get; init; }
        /// <summary>As in VERIFY: a certificate with an unknown critical extension is unusable; default false</summary>
        public bool? CheckCriticalExtensions { get; init; }
        /// <summary>As in VERIFY: the CAs remove the expired certificates from the revocation data; default false</summary>
        public bool? CaRemovesExpiredCerts { get; init; }
    }

    private class AugmentParams
    {
        public SignedData? Signature { get; init; }
        public string SignatureFormat { get; init; } = string.Empty;
        public int? SignerInfoIndex { get; init; }
        public AugmentOptions? Options { get; init; }
    }

    /// <summary>
    /// The result of AUGMENT_CMS: the augmented signature (null if not augmented) and the result of the validation
    /// of the augmented signatures (for CAdES-B-LT and CAdES-B-LTA)
    /// </summary>
    public class AugmentResult
    {
        public byte[]? Bytes { get; init; }
        public List<SignatureData>? SignatureInfos { get; init; }
        /// <summary>Remarks, e.g. the CRL of an OCSP responder not embedded (size limit)</summary>
        public List<string>? Warnings { get; init; }
        /// <summary>The error code of the library (NOT_ALLOWED if the validation did not give TOTAL-VALID)</summary>
        public int ErrorCode { get; set; }
    }

    private class AugmentResponse
    {
        public int ErrorCode { get; init; }
        public string? Method { get; init; }
        public AugmentResult? Result { get; init; }
    }

    private static string AugmentFormatString(SignatureFormat format)
    {
        return format switch
        {
            SignatureFormat.CAdES_T => "CAdES-T",
            SignatureFormat.CAdES_B_LT => "CAdES-B-LT",
            SignatureFormat.CAdES_B_LTA => "CAdES-B-LTA",
            _ => throw new ArgumentException("AUGMENT_CMS: CAdES-T, CAdES-B-LT or CAdES-B-LTA", nameof(format))
        };
    }

    /// <summary>
    /// Augments a CAdES signature to CAdES-T, CAdES-B-LT or CAdES-B-LTA (method AUGMENT_CMS). content - the data of a
    /// detached signature (or its hash with isDigest), null for an attached one. If the validation does not give
    /// TOTAL-VALID, the result has no Bytes, its ErrorCode is NOT_ALLOWED and SignatureInfos explain why
    /// </summary>
    public AugmentResult AugmentCms(byte[] signature, byte[]? content, SignatureFormat format, AugmentOptions? options = null,
        int? signerInfoIndex = null, bool isDigest = false)
    {
        return AugmentRequest(new AugmentParams()
        {
            Signature = new SignedData() { Bytes = signature, Content = content, IsDigest = isDigest ? true : null },
            SignatureFormat = AugmentFormatString(format),
            SignerInfoIndex = signerInfoIndex,
            Options = options
        });
    }

    /// <summary>
    /// Augments a detached signature against a content file; the library reads the file in blocks
    /// </summary>
    public AugmentResult AugmentCmsDetached(byte[] signature, string contentFile, SignatureFormat format,
        AugmentOptions? options = null, int? signerInfoIndex = null)
    {
        return AugmentRequest(new AugmentParams()
        {
            Signature = new SignedData() { Bytes = signature, File = contentFile },
            SignatureFormat = AugmentFormatString(format),
            SignerInfoIndex = signerInfoIndex,
            Options = options
        });
    }

    /// <summary>
    /// Augments a detached signature against content in the memory of this process (no copies, no base64)
    /// </summary>
    public AugmentResult AugmentCms(byte[] signature, IntPtr content, ulong contentSize, SignatureFormat format,
        AugmentOptions? options = null, int? signerInfoIndex = null)
    {
        var address = (ulong)content.ToInt64();
        var ptr = IntPtr.Size == 8 ? address.ToString("X16") : ((uint)address).ToString("X8");
        return AugmentRequest(new AugmentParams()
        {
            Signature = new SignedData() { Bytes = signature, Ptr = ptr, Size = contentSize },
            SignatureFormat = AugmentFormatString(format),
            SignerInfoIndex = signerInfoIndex,
            Options = options
        });
    }

    private AugmentResult AugmentRequest(AugmentParams parameters)
    {
        string augment_cmd = Request("AUGMENT_CMS", parameters, jsonCtx.AugmentParams);

        var ret = JsonSerializer.Deserialize(Process(augment_cmd), jsonCtx.AugmentResponse) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0 && ret.Result?.SignatureInfos is null)
            throw new UapkiException(ret.ErrorCode);

        var result = ret.Result ?? throw new UapkiException(0x2001);
        result.ErrorCode = ret.ErrorCode;
        return result;
    }
}
