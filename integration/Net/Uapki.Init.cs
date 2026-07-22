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
    public class ErrorCodeResult
    {
        public int ErrorCode { get; init; }
        public string? Method { get; init; }
    }

    public class CertCacheInfo
    {
        public uint CountTrustedCerts { get; init; }
        public uint CountCerts { get; init; }
    }

    public class CrlCacheInfo
    {
        public uint CountCrls { get; init; }
    }

    public class InitResponse
    {
        public int CountCmProviders { get; init; }
        public CertCacheInfo CertCache { get; init; } = new CertCacheInfo();
        public CrlCacheInfo CrlCache { get; init; } = new CrlCacheInfo();
        public OcspParams? Ocsp { get; init; }
        public TspParams? Tsp { get; init; }
        public ProxyParams? Proxy { get; init; }
        public bool Offline { get; init; }
        public bool ValidationByCrl { get; init; }
    }

    private class InitResult
    {
        public int ErrorCode { get; init; }
        public string? Method { get; init; }
        public InitResponse? Result { get; init; }
    }

    private static void CheckInit()
    {
        if (UapkiInfo is null)
            throw new UapkiException("Помилка. Криптографічну бібліотеку не ініціалізовано");
    }

    public static string Init(Config parameters)
    {
        if (UapkiInfo is not null)
            return "{}";

        OpenedKeyStorage = null;
        SelectedKey = null;

        if (parameters.CertCache?.Path is not null)
            Directory.CreateDirectory(parameters.CertCache.Path);

        if (parameters.CrlCache?.Path is not null)
            Directory.CreateDirectory(parameters.CrlCache.Path!);

        string init_cmd = "{\"method\":\"INIT\",\"parameters\":" + JsonSerializer.Serialize(parameters, jsonCtx.Config) + "}";

        var res = Process(init_cmd);
        UapkiInfo = new UapkiLibraryInfo(res);
        return res;
    }

    public static string Init(string? config = null)
    {
        if (UapkiInfo is not null)
            return "{}";

        OpenedKeyStorage = null;
        SelectedKey = null;

        if (config is null || config == "")
            config = defaultConfig;

        var conf = JsonSerializer.Deserialize(config, jsonCtx.Config) ?? throw new UapkiException(0x2001);
        return Init(conf);
    }

    public static void Deinit()
    {
        CheckInit();

        if (OpenedKeyStorage != null)
            CloseKeyStorage();

        string deinit_cmd = "{\"method\":\"DEINIT\"}";
        var ret = JsonSerializer.Deserialize(Process(deinit_cmd), jsonCtx.ErrorCodeResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0)
            throw new UapkiException(ret.ErrorCode);

        UapkiInfo = null;
    }
}
