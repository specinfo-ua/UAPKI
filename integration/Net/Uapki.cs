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

using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace UapkiNet;
public static partial class Uapki
{
    public static UapkiLibraryInfo? UapkiInfo { get; set; }
    public static OpenedKeyStorageInfo? OpenedKeyStorage { get; set; }
    public static SelectedKeyInfo? SelectedKey { get; set; }


    [DllImport("uapki", EntryPoint = "process", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr _Process(
        [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.I1)] byte[] requestUtf8Z);

    [DllImport("uapki", EntryPoint = "json_free", CallingConvention = CallingConvention.Cdecl)]
    private static extern void _JsonFree(IntPtr response);

    private static unsafe string Process(string request)
    {
        LogMessage("REQ: " + request);
        
        var req = ConvertToUtf8Z(request ?? string.Empty);
        var p = _Process(req);
        var result = "{\"ErrorCode\":-1}";

        if (p != IntPtr.Zero)
        {
            try { result = ConvertFromUtf8Z(p); }
            finally { _JsonFree(p); }
        }

        LogMessage("RESP: " + result);
        return result;
    }

    public static string Do(string request)
    {
        return Process(request);
    }

    private static string defaultConfig 
    {
        get 
        {
            return "{}";
        }
    }

    public class UapkiLibraryInfo
    {
        public string Version { get; }
        public uint CertsCount { get; }
        public uint TrustedCertsCount { get; }
        public uint CrlsCount { get; }
        public List<CmProvider> Providers { get; }

        public UapkiLibraryInfo(string response)
        {
            var ret = JsonSerializer.Deserialize(response, jsonCtx.InitResult) ?? throw new UapkiException(0x2001);
            if (ret.ErrorCode != 0)
                throw new UapkiException(ret.ErrorCode);

            CertsCount = ret.Result!.CertCache.CountCerts;
            TrustedCertsCount = ret.Result!.CertCache.CountTrustedCerts;
            CrlsCount = ret.Result!.CrlCache.CountCrls;
            Version = GetVersion();
            Providers = GetProviders();
        }
    }

    public class MechanismInfo
    {
        private List<string> _keyParamRaw = new();
        private List<string> _signAlgoRaw = new();

        public string Id { get; init; } = string.Empty;
        public string Name { get; init; } = string.Empty;

        [JsonPropertyName("keyParam")]
        public List<string> KeyParamRaw
        {
            get { return _keyParamRaw; }
            init
            {
                _keyParamRaw = value;
                KeyParams = new();
                if (_keyParamRaw is not null)
                {
                    foreach (var param in _keyParamRaw)
                        try { KeyParams.Add(param.ToKeyParameter()); } catch { /*!*/ }
                }
            }
        }

        [JsonPropertyName("signAlgo")]
        public List<string> SignAlgoRaw
        {
            get { return _signAlgoRaw; }
            init
            {
                _signAlgoRaw = value;
                SignAlgos = new();
                if (_signAlgoRaw is not null)
                {
                    foreach (var alg in _signAlgoRaw)
                        try { SignAlgos.Add(alg.ToSignAlgo()); } catch { /*!*/ }
                }
            }
        }

        [JsonIgnore]
        public KeyAlgo Algo { get { return Id.ToKeyAlgo(); } }

        [JsonIgnore]
        public List<KeyParameter> KeyParams { get; private set; } = new();

        [JsonIgnore]
        public List<SignAlgo> SignAlgos { get; private set; } = new();
    }
    
    public static DateTime ConvertUtcTimeToDateTime(string time)
    {
        string[] formats = { "yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd HH:mm" };
        return DateTime.ParseExact(time, formats, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
    }

    [Conditional("DEBUG")]
    public static void LogMessage(string message)
    {
        try
        {
#if DEBUG
            File.AppendAllLines(Path.Combine(Path.GetTempPath(), "uapki.log"), new List<string>() { message });
#endif
        }
        catch { /*do nothing*/ }
    }
    
    private static byte[] ConvertToUtf8Z(string s)
    {
        var b = Encoding.UTF8.GetBytes(s);
        var z = new byte[b.Length + 1];
        Buffer.BlockCopy(b, 0, z, 0, b.Length);
        return z;
    }

    private static string ConvertFromUtf8Z(IntPtr p)
    {
        var bytes = new List<byte>(256);
        for (int i = 0; ; i++)
        {
            byte b = Marshal.ReadByte(p, i);
            if (b == 0) break;
            bytes.Add(b);
        }
        return Encoding.UTF8.GetString(bytes.ToArray());
    }
}
