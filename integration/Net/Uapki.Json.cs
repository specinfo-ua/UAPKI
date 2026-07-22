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

using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace UapkiNet;

public static partial class Uapki
{
    private static  JsonSerializerOptions jsonOpts = new JsonSerializerOptions
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        WriteIndented = false
    };

    private static  Json jsonCtx = new Json(jsonOpts);

    [JsonSerializable(typeof(Config))]
    [JsonSerializable(typeof(InitResult))]
    [JsonSerializable(typeof(VersionResult))]
    [JsonSerializable(typeof(CmProvidersResult))]
    [JsonSerializable(typeof(OpenKeyStorageParams))]
    [JsonSerializable(typeof(CrlAddResult))]
    [JsonSerializable(typeof(CrlsListResult))]
    [JsonSerializable(typeof(CrlInfoResult))]
    [JsonSerializable(typeof(ErrorCodeResult))]
    [JsonSerializable(typeof(StoragesResult))]
    [JsonSerializable(typeof(OpenKeyStorageResult))]
    [JsonSerializable(typeof(KeysResult))]
    [JsonSerializable(typeof(SelectKeyResult))]
    [JsonSerializable(typeof(CertsListResult))]
    [JsonSerializable(typeof(CertInfoResult))]
    [JsonSerializable(typeof(DigestParams))]
    [JsonSerializable(typeof(DigestResult))]
    [JsonSerializable(typeof(ListCertsParams))]
    [JsonSerializable(typeof(CertRemoveParams))]
    [JsonSerializable(typeof(SignParameters))]
    [JsonSerializable(typeof(SignResult))]
    [JsonSerializable(typeof(VerifyResult))]
    [JsonSerializable(typeof(VerifyParams))]
    [JsonSerializable(typeof(OpenKeyStorageLoginParams))]
    [JsonSerializable(typeof(BytesResult))]
    [JsonSerializable(typeof(CertsAddParams))]
    [JsonSerializable(typeof(CertsAddResult))]
    [JsonSerializable(typeof(KeyIdResult))]
    [JsonSerializable(typeof(EncryptParams))]
    [JsonSerializable(typeof(DecryptResult))]
    [JsonSerializable(typeof(CertVerifyParams))]
    [JsonSerializable(typeof(CertVerifyResult))]
    [JsonSerializable(typeof(GetCertByOcspResult))]
    [JsonSerializable(typeof(OpenKeyStorageRequest))]
    [JsonSerializable(typeof(VerifyCsrResult))]
    [JsonSerializable(typeof(ModifyCmsRequest))]
    [JsonSerializable(typeof(ModifyCmsResponse))]

    private partial class Json : JsonSerializerContext
    {
    }
}
