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
    private class Signature
    {
        public string Id { get; init; } = string.Empty;
        public byte[] Bytes { get; init; } = Array.Empty<byte>();
    }

    private class SignaturesList
    {
        public List<Signature> Signatures { get; init; } = new List<Signature>();
    }

    private class SignResult
    {
        public int ErrorCode { get; init; }
        public string? Method { get; init; }
        public SignaturesList? Result { get; init; }
    }

    private class SignFormat
    {
        public string SignatureFormat { get; init; } = string.Empty;
        public bool DetachedData { get; init; }
        public bool IncludeCert { get; init; }
        public bool IncludeTime { get; init; }
        public string SignAlgo { get; init; } = string.Empty;
    }

    private class DataTbs
    {
        public string Id { get; init; } = string.Empty;
        public byte[]? Bytes { get; init; }
        public string? File { get; init; }
        public bool? IsDigest { get; init; }
    }

    private class SignOptions
    {
        public bool IgnoreCertStatus { get; init; }
    }

    private class SignParameters
    {
        public SignFormat? SignParams { get; init; }
        public List<DataTbs>? DataTbs { get; init; }
        public SignOptions? Options { get; init; }
    }

    private static string SignatureFormatString(SignatureFormat signFormat)
    {
        return signFormat switch
        {
            SignatureFormat.CAdES_BES => "CAdES-BES",
            SignatureFormat.CAdES_T => "CAdES-T",
            SignatureFormat.CAdES_C => "CAdES-C",
            SignatureFormat.CAdES_XL => "CAdES-XL",
            SignatureFormat.CAdES_LT => "CAdES-XL",
            SignatureFormat.CAdES_A => "CAdES-A",
            SignatureFormat.CAdES_LTA => "CAdES-A",
            SignatureFormat.CMS => "CMS",
            SignatureFormat.RAW => "RAW",
            _ => "CAdES-T",
        };
    }

    public static List<byte[]> Sign(List<byte[]> datas, SignAlgo algo, SignatureFormat signFormat, bool detachedData, bool includeCert = true, bool ignoreCertStatus = false, bool isDigest = false)
    {
        var dataTbs = new List<DataTbs>();

        for (int i = 0; i < datas.Count; i++)
            dataTbs.Add(new DataTbs() { Id = i.ToString(), Bytes = datas[i], IsDigest = isDigest });

        var parameters = new SignParameters()
        {
            SignParams = new()
            {
                SignatureFormat = SignatureFormatString(signFormat),
                DetachedData = detachedData,
                IncludeCert = includeCert,
                IncludeTime = true,
                SignAlgo = algo.Oid(),
            },
            DataTbs = dataTbs,
            Options = new() { IgnoreCertStatus = ignoreCertStatus }
        };


        string sign_cmd = "{\"method\":\"SIGN\",\"parameters\":" + JsonSerializer.Serialize(parameters, jsonCtx.SignParameters) + "}";

        var ret = JsonSerializer.Deserialize(Process(sign_cmd), jsonCtx.SignResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0)
            throw new UapkiException(ret.ErrorCode);

        var signatures = new List<byte[]>();

        foreach (var signature in ret.Result!.Signatures)
            signatures.Add(signature.Bytes);

        return signatures;
    }

    public static void SignFiles(string[] files, SignAlgo algo, SignatureFormat signFormat, bool detachedData, bool includeCert = true, bool ignoreCertStatus = false)
    {
        var dataTbs = new List<DataTbs>();
        long totalLen = 0;

        for (int i = 0; i < files.Length; i++)
        {
            var len = new FileInfo(files[i]).Length;
            totalLen += len;

            if ((len > 512 * 1024 * 1024) && !detachedData)
                throw new UapkiException("Поточна версія не підтримує підпис з інкапсуляцією даних для файлів, більших за 512 МБ");
        }

        if (totalLen > 512 * 1024 * 1024)
        {
            var f = new string[1];
            for (int i = 0; i < files.Length; i++)
            {
                f[0] = files[i];
                SignFiles(f, algo, signFormat, detachedData, includeCert, ignoreCertStatus);
            }
            return;
        }

        for (int i = 0; i < files.Length; i++)
        {
            if (detachedData)
                dataTbs.Add(new DataTbs() { Id = i.ToString(), File = files[i] });
            else
                dataTbs.Add(new DataTbs() { Id = i.ToString(), Bytes = File.ReadAllBytes(files[i]), IsDigest = false });
        }

        var parameters = new SignParameters()
        {
            SignParams = new()
            {
                SignatureFormat = SignatureFormatString(signFormat),
                DetachedData = detachedData,
                IncludeCert = includeCert,
                IncludeTime = true,
                SignAlgo = algo.Oid(),
            },
            DataTbs = dataTbs,
            Options = new() { IgnoreCertStatus = ignoreCertStatus }
        };

        string sign_cmd = "{\"method\":\"SIGN\",\"parameters\":" + JsonSerializer.Serialize(parameters, jsonCtx.SignParameters) + "}";

        var ret = JsonSerializer.Deserialize(Process(sign_cmd), jsonCtx.SignResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0)
            throw new UapkiException(ret.ErrorCode);

        foreach (var signature in ret.Result!.Signatures)
        {
            var file = files[Convert.ToInt32(signature.Id)] + ".p7s";
            File.WriteAllBytes(file, signature.Bytes);
        }
    }
}
