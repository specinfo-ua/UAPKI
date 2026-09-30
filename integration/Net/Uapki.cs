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

using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace UapkiNet;
public partial class Uapki : IDisposable
{
    public UapkiLibraryInfo? UapkiInfo { get; set; }
    public OpenedKeyStorageInfo? OpenedKeyStorage { get; set; }
    public SelectedKeyInfo? SelectedKey { get; set; }


    [DllImport("uapki", EntryPoint = "process", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr _Process(
        [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.I1)] byte[] requestUtf8Z);

    [DllImport("uapki", EntryPoint = "json_free", CallingConvention = CallingConvention.Cdecl)]
    private static extern void _JsonFree(IntPtr response);

    [DllImport("uapki", EntryPoint = "uapki_session_create", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr _SessionCreate();

    [DllImport("uapki", EntryPoint = "uapki_session_free", CallingConvention = CallingConvention.Cdecl)]
    private static extern void _SessionFree(IntPtr session);

    [DllImport("uapki", EntryPoint = "uapki_session_process", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr _SessionProcess(IntPtr session, IntPtr memory,
        [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.I1)] byte[] requestUtf8Z);

    [DllImport("uapki", EntryPoint = "uapki_session_shared_memory_create", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr _SharedMemoryCreate();

    [DllImport("uapki", EntryPoint = "uapki_session_shared_memory_free", CallingConvention = CallingConvention.Cdecl)]
    private static extern void _SharedMemoryFree(IntPtr memory);

    [DllImport("uapki", EntryPoint = "uapki_session_shared_memory_process", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr _SharedMemoryProcess(IntPtr memory,
        [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.I1)] byte[] requestUtf8Z);

    private sealed class SessionHandle : SafeHandle
    {
        public SessionHandle(IntPtr handle) : base(IntPtr.Zero, true) { SetHandle(handle); }
        public override bool IsInvalid => handle == IntPtr.Zero;
        protected override bool ReleaseHandle() { _SessionFree(handle); return true; }
    }

    private sealed class SharedMemoryHandle : SafeHandle
    {
        public SharedMemoryHandle(IntPtr handle) : base(IntPtr.Zero, true) { SetHandle(handle); }
        public override bool IsInvalid => handle == IntPtr.Zero;
        protected override bool ReleaseHandle() { _SharedMemoryFree(handle); return true; }
    }

    private enum InstanceMode { Global, Session, SharedMemory }

    private readonly InstanceMode mode;
    private readonly SessionHandle? sessionHandle;
    private readonly SharedMemoryHandle? memoryHandle;      //  own (shared memory) or used by the session
    private readonly Uapki? sharedMemory;                   //  keeps the shared memory object alive for the session

    /// <summary>
    /// Глобальний екземпляр бібліотеки (функція process), як у версіях 2.x
    /// </summary>
    public static Uapki Global { get; } = new Uapki(InstanceMode.Global);

    private Uapki(InstanceMode instanceMode)
    {
        mode = instanceMode;
        if (mode == InstanceMode.SharedMemory)
            memoryHandle = new SharedMemoryHandle(CallSessionsApi(_SharedMemoryCreate));
    }

    /// <summary>
    /// Створює сесію бібліотеки (uapki_session_create). Сесію потрібно звільнити викликом Dispose
    /// </summary>
    public Uapki() : this(InstanceMode.Session)
    {
        sessionHandle = new SessionHandle(CallSessionsApi(_SessionCreate));
    }

    /// <summary>
    /// Створює сесію, яка використовує спільну пам'ять (кеші сертифікатів і СВС)
    /// </summary>
    public Uapki(Uapki sharedMemory) : this()
    {
        if (sharedMemory.mode != InstanceMode.SharedMemory)
            throw new ArgumentException("Очікується екземпляр спільної пам'яті (Uapki.CreateSharedMemory)", nameof(sharedMemory));

        this.sharedMemory = sharedMemory;
        memoryHandle = sharedMemory.memoryHandle;
    }

    /// <summary>
    /// Створює спільну пам'ять (uapki_session_shared_memory_create): кеші сертифікатів і СВС для кількох сесій.
    /// Дозволені лише методи роботи з кешами; спільну пам'ять потрібно звільнити викликом Dispose
    /// </summary>
    public static Uapki CreateSharedMemory()
    {
        return new Uapki(InstanceMode.SharedMemory);
    }

    public bool IsGlobal => mode == InstanceMode.Global;
    public bool IsSharedMemory => mode == InstanceMode.SharedMemory;

    private static IntPtr CallSessionsApi(Func<IntPtr> create)
    {
        IntPtr handle;
        try
        {
            handle = create();
        }
        catch (EntryPointNotFoundException)
        {
            throw new UapkiException("Помилка. Бібліотека uapki не підтримує сесії (потрібна версія 3.0 або новіша)");
        }
        if (handle == IntPtr.Zero)
            throw new UapkiException("Помилка. Не вдалося створити сесію бібліотеки uapki");
        return handle;
    }

    /// <summary>
    /// Звільняє сесію або спільну пам'ять; для глобального екземпляра нічого не робить
    /// </summary>
    public void Dispose()
    {
        if (mode == InstanceMode.Global)
            return;

        if (mode == InstanceMode.Session)
            sessionHandle?.Dispose();
        else
            memoryHandle?.Dispose();

        UapkiInfo = null;
        OpenedKeyStorage = null;
        SelectedKey = null;
    }

    private string Process(string request)
    {
        LogMessage("REQ: " + request);

        var req = ConvertToUtf8Z(request ?? string.Empty);
        var p = mode switch
        {
            InstanceMode.Session => ProcessWithHandles(req),
            InstanceMode.SharedMemory => ProcessWithHandles(req),
            _ => _Process(req)
        };
        var result = "{\"ErrorCode\":-1}";

        if (p != IntPtr.Zero)
        {
            try { result = ConvertFromUtf8Z(p); }
            finally { _JsonFree(p); }
        }

        LogMessage("RESP: " + result);
        return result;
    }

    //  The handles are referenced for the time of the call: Dispose from another thread waits until the call is done
    private IntPtr ProcessWithHandles(byte[] req)
    {
        bool session_added = false, memory_added = false;
        try
        {
            memoryHandle?.DangerousAddRef(ref memory_added);
            IntPtr memory = (memoryHandle is not null) ? memoryHandle.DangerousGetHandle() : IntPtr.Zero;
            if (mode == InstanceMode.SharedMemory)
                return _SharedMemoryProcess(memory, req);

            sessionHandle!.DangerousAddRef(ref session_added);
            return _SessionProcess(sessionHandle.DangerousGetHandle(), memory, req);
        }
        catch (ObjectDisposedException)
        {
            throw new UapkiException(IsSharedMemory ? "Помилка. Спільну пам'ять звільнено" : "Помилка. Сесію звільнено");
        }
        finally
        {
            if (session_added) sessionHandle!.DangerousRelease();
            if (memory_added) memoryHandle!.DangerousRelease();
        }
    }

    public string Do(string request)
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

        public UapkiLibraryInfo(Uapki uapki, string response)
        {
            var ret = JsonSerializer.Deserialize(response, jsonCtx.InitResult) ?? throw new UapkiException(0x2001);
            if (ret.ErrorCode != 0)
                throw new UapkiException(ret.ErrorCode);

            CertsCount = ret.Result!.CertCache.CountCerts;
            TrustedCertsCount = ret.Result!.CertCache.CountTrustedCerts;
            CrlsCount = ret.Result!.CrlCache.CountCrls;
            Version = uapki.GetVersion();
            //  The shared memory does not load providers (PROVIDERS is not allowed there)
            Providers = uapki.IsSharedMemory ? new List<CmProvider>() : uapki.GetProviders();
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
