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
        // Content in the memory of this process: address (hex, big-endian) and size
        public string? Ptr { get; init; }
        public ulong? Size { get; init; }
    }

    /// <summary>
    /// Data to sign: a file (read by the library in blocks) or content in the memory of this process
    /// (hashed by the library in place). The memory must stay valid for the duration of the call
    /// </summary>
    public class SignSource
    {
        public string? File { get; init; }
        public IntPtr Ptr { get; init; }
        public ulong Size { get; init; }
    }

    private class SignOptions
    {
        public bool IgnoreCertStatus { get; init; }
        //  Sent only when true: the chain of the signer must end in a trusted root (SIGN options.checkTrustedRoot)
        public bool? CheckTrustedRoot { get; init; }
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

    /// <param name="checkTrustedRoot">the chain of the signer certificate must end in a trusted root (with the certificate status check)</param>
    public List<byte[]> Sign(List<byte[]> datas, SignAlgo algo, SignatureFormat signFormat, bool detachedData, bool includeCert = true, bool ignoreCertStatus = false, bool isDigest = false, bool checkTrustedRoot = false)
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
            Options = new() { IgnoreCertStatus = ignoreCertStatus, CheckTrustedRoot = checkTrustedRoot ? true : null }
        };


        string sign_cmd = Request("SIGN", parameters, jsonCtx.SignParameters);

        var ret = JsonSerializer.Deserialize(Process(sign_cmd), jsonCtx.SignResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0)
            throw new UapkiException(ret.ErrorCode);

        var signatures = new List<byte[]>();

        foreach (var signature in ret.Result!.Signatures)
            signatures.Add(signature.Bytes);

        return signatures;
    }

    /// <summary>
    /// Detached signatures of files in one SIGN call; the library reads the files in blocks.
    /// Returns the signatures in the order of the files; nothing is written to disk
    /// </summary>
    public List<byte[]> SignFilesDetached(string[] files, SignAlgo algo, SignatureFormat signFormat, bool includeCert = true, bool ignoreCertStatus = false, bool checkTrustedRoot = false)
    {
        return SignDetached(files.Select(file => new SignSource() { File = file }).ToList(), algo, signFormat, includeCert, ignoreCertStatus, checkTrustedRoot);
    }

    /// <summary>
    /// Detached signatures of files or content in memory in one SIGN call.
    /// Returns the signatures in the order of the sources; nothing is written to disk
    /// </summary>
    public List<byte[]> SignDetached(IReadOnlyList<SignSource> sources, SignAlgo algo, SignatureFormat signFormat, bool includeCert = true, bool ignoreCertStatus = false, bool checkTrustedRoot = false)
    {
        var dataTbs = new List<DataTbs>();
        for (int i = 0; i < sources.Count; i++)
        {
            var source = sources[i];
            if (source.File is not null)
            {
                dataTbs.Add(new DataTbs() { Id = i.ToString(), File = source.File });
            }
            else
            {
                var address = (ulong)source.Ptr.ToInt64();
                var ptr = IntPtr.Size == 8 ? address.ToString("X16") : ((uint)address).ToString("X8");
                dataTbs.Add(new DataTbs() { Id = i.ToString(), Ptr = ptr, Size = source.Size });
            }
        }

        var parameters = new SignParameters()
        {
            SignParams = new()
            {
                SignatureFormat = SignatureFormatString(signFormat),
                DetachedData = true,
                IncludeCert = includeCert,
                IncludeTime = true,
                SignAlgo = algo.Oid(),
            },
            DataTbs = dataTbs,
            Options = new() { IgnoreCertStatus = ignoreCertStatus, CheckTrustedRoot = checkTrustedRoot ? true : null }
        };

        string sign_cmd = Request("SIGN", parameters, jsonCtx.SignParameters);

        var ret = JsonSerializer.Deserialize(Process(sign_cmd), jsonCtx.SignResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0)
            throw new UapkiException(ret.ErrorCode);

        var signatures = new byte[sources.Count][];
        foreach (var signature in ret.Result!.Signatures)
            signatures[Convert.ToInt32(signature.Id)] = signature.Bytes;

        if (signatures.Any(signature => signature is null))
            throw new UapkiException(0x2001);

        return signatures.ToList();
    }
}
