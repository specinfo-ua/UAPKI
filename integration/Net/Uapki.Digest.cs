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
    private class DigestParams
    {
        public string? HashAlgo { get; init; }
        public string? SignAlgo { get; init; }
        public byte[]? Bytes { get; init; }
        public string? File { get; init; }
    }

    private class DigestValue
    {
        string? HashAlgo { get; init; }
        public byte[]? Bytes { get; init; }
    }

    private class DigestResult
    {
        public int ErrorCode { get; init; }
        public string? Method { get; init; }
        public DigestValue? Result { get; init; }
    }

    public static byte[] GetDigest(byte[] bytes, HashAlgo? hashAlgo, SignAlgo? signAlgo = null)
    {
        var parameters = new DigestParams() { HashAlgo = hashAlgo?.Oid(), SignAlgo = signAlgo?.Oid(), Bytes = bytes };

        string digest_cmd = "{\"method\":\"DIGEST\",\"parameters\":" +
            JsonSerializer.Serialize(parameters, jsonCtx.DigestParams) + "}";

        var ret = JsonSerializer.Deserialize(Process(digest_cmd), jsonCtx.DigestResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0)
            throw new UapkiException(ret.ErrorCode);

        if (ret.Result?.Bytes is null)
            throw new UapkiException(0x2001);

        return ret.Result.Bytes;
    }

    public static byte[] GetFileDigest(string file, HashAlgo? hashAlgo, SignAlgo? signAlgo = null)
    {
        var parameters = new DigestParams() { HashAlgo = hashAlgo?.Oid(), SignAlgo = signAlgo?.Oid(), File = file };

        string digest_cmd = "{\"method\":\"DIGEST\",\"parameters\":" + JsonSerializer.Serialize(parameters, jsonCtx.DigestParams) + "}";

        var ret = JsonSerializer.Deserialize(Process(digest_cmd), jsonCtx.DigestResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0)
            throw new UapkiException(ret.ErrorCode);

        if (ret.Result?.Bytes is null)
            throw new UapkiException(0x2001);

        return ret.Result.Bytes;
    }
}
