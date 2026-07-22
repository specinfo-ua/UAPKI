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

using System.Text.Json.Serialization;
using UapkiNet.JsonConverters;

namespace UapkiNet;

public static partial class Uapki
{
    public class PfxConfig
    {
        public string BagCipher { get; set; } = string.Empty;
        public string BagKdf { get; set; } = string.Empty;
        public string MacAlgo { get; set; } = string.Empty;
        public int? Iterations { get; set; }
    }

    public class Pkcs11ModuleConfig
    {
        public string Name { get; set; } = string.Empty;
        public bool? EkuDevice { get; set; }
        public bool? Pka { get; set; }
    }

    public class CmProviderConfig
    {
        public PfxConfig? CreatePfx { get; set; }
        public List<Pkcs11ModuleConfig>? Modules { get; set; }
    }

    public class CmProviderParams
    {
        public string? Lib { get; set; }
        public CmProviderConfig? Config { get; set; }
    }

    public class CmProvidersParams
    {
        public string? Dir { get; set; }
        public List<CmProviderParams>? AllowedProviders { get; set; }
    }
    
    public class CertCacheParams
    {
        public string? Path { get; set; }
        public List<string>? TrustedCerts { get; set; }
    }

    public class CrlCacheParams
    {
        public string? Path { get; set; }
        public bool? UseDeltaCrl { get; set; }
    }

    public class OcspParams
    {
        public int? NonceLen { get; set; }
    }

    public class TspParams
    {
        public bool? CertReq { get; set; }
        public bool? Forced { get; set; }
        public int? NonceLen { get; set; }
        public string? PolicyId { get; set; }
        [JsonConverter(typeof(SingleOrArrayStringConverter))]
        public List<string>? Url { get; set; }
    }

    public class ProxyParams
    {
        public string? Url { get; set; }
        public string? Credentials { get; set; }
    }

    public class Config
    {
        public CmProvidersParams? CmProviders { get; set; }
        public CertCacheParams? CertCache { get; set; }
        public CrlCacheParams? CrlCache { get; set; }
        public OcspParams? Ocsp { get; set; }
        public TspParams? Tsp { get; set; }
        public ProxyParams? Proxy { get; set; }
        public bool? Offline { get; set; }
        public bool? ValidationByCrl { get; set; }
    }
}
