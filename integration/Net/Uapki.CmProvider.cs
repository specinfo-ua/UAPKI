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
    public class CmProvider
    {
        public string Id { get; init; } = string.Empty;
        public string Description { get; init; } = string.Empty;
        public string LibVersion { get; init; } = string.Empty;
        public string Manufacturer { get; init; } = string.Empty;
        public bool SupportListStorages { get; init; }
    }

    public class CmProviders
    {
        public List<CmProvider>? Providers { get; init; }
    }

    public class CmProvidersResult
    {
        public int ErrorCode { get; init; }
        public string? Method { get; init; }
        public CmProviders? Result { get; init; }
    }

    private static List<CmProvider> GetProviders()
    {
        string providers_cmd = "{\"method\":\"PROVIDERS\"}";

        var ret = JsonSerializer.Deserialize(Process(providers_cmd), jsonCtx.CmProvidersResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0)
            throw new UapkiException(ret.ErrorCode);

        if (ret.Result?.Providers is not null)
            return ret.Result.Providers;
        else return new List<CmProvider>();
    }
}
