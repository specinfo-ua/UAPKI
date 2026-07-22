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
    private class ContentToEncrypt
    {
        public byte[] Bytes { get; init; } = Array.Empty<byte>();
        public string EncryptionAlgo { get; init; } = string.Empty;
    }

    private class RecipientInfo
    {
        public string CertId { get; init; } = string.Empty;
        public string KdfAlgo { get; init; } = string.Empty;
    }

    private class EncryptParams
    {
        public ContentToEncrypt Content {  get; init; } = new ContentToEncrypt();
        public List<RecipientInfo> RecipientInfos { get; init; } = new List<RecipientInfo>();
    }

    // ГОСТ 28147 з kdf ГОСТ 34.311: encryptionAlgo = "1.2.804.2.1.1.1.1.1.1.3", kdfAlgo = "1.2.804.2.1.1.1.1.3.4"
    // Калина-256 з kdf Купина-256: encryptionAlgo = "1.2.804.2.1.1.1.1.1.3.3.2", kdfAlgo = "1.2.804.2.1.1.1.1.3.7"
    public static byte[] Encrypt(byte[] plain, List<string> recipientsCerts, string encryptionAlgo = "1.2.804.2.1.1.1.1.1.3.3.2", string kdfAlgo = "1.2.804.2.1.1.1.1.3.7")
    {
        CheckInit();

        var parameters = new EncryptParams()
        {
            Content = new ContentToEncrypt() { Bytes = plain, EncryptionAlgo = encryptionAlgo },
            RecipientInfos = new()
        };

        foreach (var recipient in recipientsCerts)
        {
            parameters.RecipientInfos.Add(new RecipientInfo { CertId = recipient, KdfAlgo = kdfAlgo });
        }

        string encrypt_cmd = "{\"method\":\"ENCRYPT\",\"parameters\":" + JsonSerializer.Serialize(parameters, jsonCtx.EncryptParams) + "}";

        var ret = JsonSerializer.Deserialize(Process(encrypt_cmd), jsonCtx.BytesResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0)
            throw new UapkiException(ret.ErrorCode);

        if (ret.Result?.Bytes is null)
            throw new UapkiException(0x2001);

        return ret.Result.Bytes;
    }

    public class DecryptedContent
    {
        public byte[]? Bytes { get; init; }
        public string Type { get; init; } = string.Empty;
    }

    public class DecryptedData
    {
        public DecryptedContent Content { get; init; } = new DecryptedContent();
        public string? OriginatorCertId { get; init; }
    }

    private class DecryptResult
    {
        public int ErrorCode { get; init; }
        public string? Method { get; init; }
        public DecryptedData? Result { get; init; }
    }

    public static DecryptedData Decrypt(byte[] bytes)
    {
        CheckStorage();

        string decrypt_cmd = "{\"method\":\"DECRYPT\",\"parameters\":{\"bytes\":\"" + Convert.ToBase64String(bytes) + "\"}}";

        var ret = JsonSerializer.Deserialize(Process(decrypt_cmd), jsonCtx.DecryptResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0)
            throw new UapkiException(ret.ErrorCode);

        if (ret.Result is null)
            throw new UapkiException(0x2001);

        return ret.Result;
    }
}
