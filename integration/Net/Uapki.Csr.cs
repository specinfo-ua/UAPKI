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

using System.Text.Json;

namespace UapkiNet;

public static partial class Uapki
{
    public static byte[] GetCsr(SignAlgo? signAlgo = null)
    {
        string get_crs_cmd = "{\"method\":\"GET_CSR\",\"parameters\":{}}";

        if (signAlgo is not null)
            get_crs_cmd = "{\"method\":\"GET_CSR\",\"parameters\":{\"signAlgo\":\"" + signAlgo.Value.Oid() + "\"}}";

        var ret = JsonSerializer.Deserialize(Process(get_crs_cmd), jsonCtx.BytesResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0)
            throw new UapkiException(ret.ErrorCode);

        if (ret.Result?.Bytes is null)
            throw new UapkiException(0x2001);

        return ret.Result.Bytes;
    }

    public class ExtensionRequest
    {
        public string[]? ExtendedKeyUsage { get; set; }
        public string? SubjectKeyIdentifier { get; set; }
        public Extension[]? Extensions { get; set; }
    }

    public class VerifyCsrInfo
    {
        public string? KeyId { get; set; }
        public string? KeyId2 { get; set; }
        public string? StatusSignature { get; set; }
        public SignatureInfo? SignatureInfo { get; set; }
        public SubjectPublicKeyInfo? SubjectPublicKeyInfo { get; set; }
        public ExtensionRequest? ExtensionRequest { get; set; }
    }

    private class VerifyCsrResult
    {
        public int ErrorCode { get; set; }
        public VerifyCsrInfo? Result { get; set; }
    }

    public static VerifyCsrInfo VerifyCsr(byte[] csr)
    {
        string verify_csr_cmd = "{\"method\":\"VERIFY_CSR\",\"parameters\":{\"bytes\":\"" + Convert.ToBase64String(csr) + "\"}}";
        var ret = JsonSerializer.Deserialize(Process(verify_csr_cmd), jsonCtx.VerifyCsrResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0)
            throw new UapkiException(ret.ErrorCode);
        if (ret.Result is null)
            throw new UapkiException(0x2001);
        return ret.Result;
    }
}
