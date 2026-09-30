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

using UapkiNet;

//  Sessions test of the .NET integration: global instance, parallel sessions, shared memory, Dispose

string providersDir = RequiredEnv("UAPKI_CM_PROVIDERS");
string testData = RequiredEnv("UAPKI_TEST_DATA");
if (!providersDir.EndsWith("/") && !providersDir.EndsWith("\\"))
    providersDir += Path.DirectorySeparatorChar;     //  the library appends the platform file name to dir

string work = Path.Combine(Path.GetTempPath(), "uapki-net-tests-" + Environment.ProcessId);
Directory.CreateDirectory(work);
string crlDir = Dir("crls");
string emptyCertDir = Dir("empty-certs");
byte[] p12 = File.ReadAllBytes(Path.Combine(testData, "test-diia.p12"));
const string P12_PASSWORD = "testpassword";
byte[] data = System.Text.Encoding.ASCII.GetBytes("The quick brown fox jumps over the lazy dog");
int failed = 0;

try
{
    // 1. Global instance: the process() function, as in 2.x
    Check(Uapki.Global.IsGlobal && Uapki.Global.GetVersion().Length > 0, "Global: VERSION");
    Uapki.Global.Init(Config(CertDir("global")));
    Check(Uapki.Global.UapkiInfo?.Providers.Count == 1, "Global: INIT with the cm-pkcs12 provider");

    // 2. Parallel sessions: each opens its own storage and signs; the state is per instance
    const int N = 4;
    const int SIGNS = 5;
    var sessions = new Uapki[N];
    var signatures = new List<byte[]>[N];
    try
    {
        Parallel.For(0, N, i =>
        {
            var session = new Uapki();
            sessions[i] = session;
            session.Init(Config(CertDir("session-" + i)));
            string storage = Path.Combine(work, "storage-" + i + ".p12");
            File.WriteAllBytes(storage, p12);
            session.OpenKeyStorage(storage, P12_PASSWORD, Uapki.KeyStorageOpenMode.RO);
            session.SelectKey(session.OpenedKeyStorage!.Storage.Keys![0]);
            var list = new List<byte[]>();
            for (int k = 0; k < SIGNS; k++)
            {
                //  ignoreCertStatus: the test certificate may be expired, the check is offline
                list.AddRange(session.Sign(new List<byte[]> { data }, Uapki.SignAlgo.Dstu4145_Gost34311,
                    Uapki.SignatureFormat.CAdES_BES, false, true, true));
            }
            signatures[i] = list;
        });
        Check(signatures.All(it => it?.Count == SIGNS), "sessions: " + N + " parallel sessions signed " + SIGNS + " times each");
        Check(sessions.All(it => it.OpenedKeyStorage is not null && it.SelectedKey is not null) && Uapki.Global.OpenedKeyStorage is null,
            "sessions: the storage state is per instance");
        var validation = sessions[0].Verify(signatures[N - 1][0], null);
        Check(validation.SignatureInfos?.Count == 1 && validation.SignatureInfos[0].ValidSignatures,
            "sessions: a signature made in another session is valid");
    }
    finally
    {
        foreach (var session in sessions.Where(it => it is not null))
        {
            if (session.OpenedKeyStorage is not null) session.CloseKeyStorage();
            session.Deinit();
            session.Dispose();
        }
    }

    // 3. Shared memory: a session without its own certificates sees the shared ones
    using (var shared = Uapki.CreateSharedMemory())
    {
        shared.Init(Config(CertDir("shared"), withProviders: false));
        int shared_certs = shared.GetCerts().Count;
        Check(shared.IsSharedMemory && shared_certs > 0, "shared memory: INIT with a certificate cache");

        using var session = new Uapki(shared);
        session.Init(Config(emptyCertDir));
        Check(session.GetCerts().Count == shared_certs, "shared memory: the session sees the shared certificates");
        session.Deinit();

        Expect<UapkiException>(() => shared.OpenKeyStorage(Path.Combine(work, "storage-0.p12"), P12_PASSWORD, Uapki.KeyStorageOpenMode.RO),
            "shared memory: storage methods are not allowed");
        Expect<ArgumentException>(() => new Uapki(Uapki.Global), "new Uapki(Global) is rejected");
        shared.Deinit();
    }

    // 4. Dispose
    var disposed = new Uapki();
    disposed.Dispose();
    Expect<UapkiException>(() => disposed.GetVersion(), "a disposed session rejects calls");
    var released = Uapki.CreateSharedMemory();
    using (var session = new Uapki(released))
    {
        released.Dispose();
        try
        {
            session.GetVersion();
            Check(false, "a session rejects calls after its shared memory is released");
        }
        catch (UapkiException e)
        {
            Check(e.Message.Contains("Спільну пам'ять звільнено"), "a session rejects calls after its shared memory is released");
        }
    }
    Uapki.Global.Dispose();
    Check(Uapki.Global.GetVersion().Length > 0, "Global: Dispose does nothing");
    Uapki.Global.Deinit();
}
catch (Exception e)
{
    Console.WriteLine("[FAIL] unexpected exception: " + e);
    failed++;
}
finally
{
    try { Directory.Delete(work, true); } catch { /* best effort */ }
}

Console.WriteLine(failed == 0 ? "ALL PASSED" : failed + " FAILED");
return failed;


void Check(bool ok, string what)
{
    Console.WriteLine((ok ? "[PASS] " : "[FAIL] ") + what);
    if (!ok) failed++;
}

void Expect<TException>(Action action, string what) where TException : Exception
{
    try
    {
        action();
        Check(false, what + " (no exception)");
    }
    catch (TException e)
    {
        Check(true, what + " (" + e.GetType().Name + ")");
    }
}

string RequiredEnv(string name)
{
    return Environment.GetEnvironmentVariable(name) ?? throw new InvalidOperationException("Environment variable " + name + " is not set");
}

string Dir(string name)
{
    string path = Path.Combine(work, name) + Path.DirectorySeparatorChar;
    Directory.CreateDirectory(path);
    return path;
}

//  The certificate cache renames files, so every instance gets its own copy
string CertDir(string name)
{
    string path = Dir(name);
    foreach (var file in Directory.GetFiles(Path.Combine(testData, "certs"), "*.cer"))
        File.Copy(file, Path.Combine(path, Path.GetFileName(file)), true);
    return path;
}

string Config(string certDir, bool withProviders = true)
{
    static string Json(string s) => s.Replace("\\", "\\\\");
    return "{" + (withProviders ? "\"cmProviders\":{\"dir\":\"" + Json(providersDir) + "\",\"allowedProviders\":[{\"lib\":\"cm-pkcs12\"}]}," : "")
        + "\"certCache\":{\"path\":\"" + Json(certDir) + "\"},\"crlCache\":{\"path\":\"" + Json(crlDir) + "\"},\"offline\":true}";
}
