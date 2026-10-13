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
    // VERIFY with the validation type FULL-ETSI: the report and the validation policy (offline: the root of the
    // test signatures is not trusted and the status of their certificates is not available)
    using (var etsi = new Uapki())
    {
        etsi.Init(Config(CertDir("etsi"), false));
        byte[] attached = File.ReadAllBytes(Path.Combine(testData, "atsv2-attached.p7s"));
        byte[] detached = File.ReadAllBytes(Path.Combine(testData, "atsv2-detached.p7s"));
        string contentFile = Path.Combine(testData, "test-fox.txt");

        var result = etsi.VerifyEtsi(attached);
        var report = result.SignatureValidationReports.FirstOrDefault();
        Check(result.SignatureValidationReports.Count == 1 && report is not null && !report.IsTotalPassed
            && report.SignatureValidationStatus.MainIndication == "INDETERMINATE"
            && report.SignatureValidationStatus.SubIndications?.Contains("NO_CERTIFICATE_CHAIN_FOUND") == true,
            "FULL-ETSI: an intact signature with an untrusted root is INDETERMINATE / NO_CERTIFICATE_CHAIN_FOUND");
        Check(report?.ValidationConstraintsEvaluationReport?.SignatureValidationPolicy?.PolicyName == Uapki.ValidationPolicyName.UkraineDefault
            && report.SignatureValidationProcess?.SignatureValidationProcessId == "LTA"
            && report.SignatureIdentifier?.DigestAlgAndValue?.DigestValue?.Length > 0
            && report.SignatureQuality is null,
            "FULL-ETSI: the default policy, the validation process, the identifier of the signature");
        var crypto = report?.ValidationConstraintsEvaluationReport?.ValidationConstraints?.Find(c => c.ValidationConstraintIdentifier == "cryptographicVerification");
        Check(crypto is not null && crypto.IsApplied && crypto.ValidationStatus?.MainIndication == "PASSED",
            "FULL-ETSI: the constraint cryptographicVerification passed");
        Check(report?.TimeStamps?.Count > 0 && result.FindObject(report.TimeStamps[0])?.ObjectType == "timestamp"
            && report.SignerInformation is not null && result.FindObject(report.SignerInformation.SignerCertificate)?.ObjectType == "certificate"
            && report.SignatureValidationStatus.CertificateChain?.SigningCertificate == report.SignerInformation.SignerCertificate,
            "FULL-ETSI: the time-stamps and the certificates are validation objects referenced from the report");
        Check(report?.SignatureValidationStatus.AssociatedValidationReportData?.Any(d => d.SubIndication == "NO_CERTIFICATE_CHAIN_FOUND" && d.MainIndication == "INDETERMINATE") == true,
            "FULL-ETSI: the data of a reason names its sub-indication");

        var changed = etsi.VerifyEtsi(detached, detached).SignatureValidationReports[0];
        Check(changed.SignatureValidationStatus.MainIndication == "TOTAL-FAILED" && changed.SignatureValidationStatus.SubIndications?[0] == "HASH_FAILURE",
            "FULL-ETSI: another content is TOTAL-FAILED / HASH_FAILURE");
        Check(etsi.VerifyEtsiDetached(detached, contentFile).SignatureValidationReports[0].SignatureValidationStatus.SubIndications?.Contains("HASH_FAILURE") == false,
            "FULL-ETSI: a detached signature against its content file");
        Check(etsi.VerifyEtsi(detached).SignatureValidationReports[0].SignatureValidationStatus.SubIndications?.Contains("SIGNED_DATA_NOT_FOUND") == true,
            "FULL-ETSI: without the content it is SIGNED_DATA_NOT_FOUND");

        Check(etsi.VerifyEtsi(attached, null, Uapki.ValidationPolicyName.EtsiStrict).SignatureValidationReports[0]
            .ValidationConstraintsEvaluationReport?.SignatureValidationPolicy?.PolicyName == Uapki.ValidationPolicyName.EtsiStrict,
            "FULL-ETSI: the policy EtsiStrict by name");
        var custom = etsi.VerifyEtsi(attached, null, new Uapki.ValidationPolicy() { BasedOn = Uapki.ValidationPolicyName.EtsiStrict, RevocationFreshness = 60 })
            .SignatureValidationReports[0].ValidationConstraintsEvaluationReport;
        Check(custom?.SignatureValidationPolicy?.PolicyName == Uapki.ValidationPolicyName.Custom
            && custom.SignatureValidationPolicy.BasedOn == Uapki.ValidationPolicyName.EtsiStrict
            && custom.ValidationConstraints?.Find(c => c.ValidationConstraintIdentifier == "revocationFreshnessChecker")?.ValidationConstraintParameter?.Value == "60",
            "FULL-ETSI: a policy given by values is custom, with its values in the report");
        Expect<UapkiException>(() => etsi.VerifyEtsi(attached, null, "Unknown"), "FULL-ETSI: an unknown policy is refused by the library");
        Expect<UapkiException>(() => etsi.VerifyEtsi(attached, null, new Uapki.ValidationPolicy() { TsaExtendedKeyUsage = "other" }),
            "FULL-ETSI: an unknown value of a policy field is refused by the library");
        Expect<ArgumentException>(() => etsi.VerifyEtsi(attached, null, "a\"b"), "FULL-ETSI: a policy name that is not a name is refused by the wrapper");
    }

    // Trusted lists: the test lists of data/trust-list name the certificates of data/certs as trust services
    using (var lists = new Uapki())
    {
        string listDir = Path.Combine(testData, "trust-list");
        byte[] signer = File.ReadAllBytes(Path.Combine(listDir, "trust-list-signer.cer"));
        byte[] list = File.ReadAllBytes(Path.Combine(listDir, "trust-list.xml"));
        byte[] ca = File.ReadAllBytes(Directory.GetFiles(Path.Combine(testData, "certs"), "diia-CA-*.cer")[0]);
        string storeDir = Dir("trust-lists");
        foreach (var file in Directory.GetFiles(storeDir)) File.Delete(file);
        var config = new Uapki.Config()
        {
            Offline = true,
            TrustListCache = new Uapki.TrustListCacheParams() { Path = storeDir, TrustListSignerCerts = new List<string>() { Convert.ToBase64String(signer) } }
        };
        lists.Init(config);
        Check(lists.UapkiInfo is { TrustListsCount: 0, RefusedTrustListsCount: 0 }, "trusted lists: INIT with the directory of lists");

        Check(!lists.GetCertInfo(ca).Trusted, "trusted lists: the CA is not trusted before the list");
        var info = lists.AddTrustList(list);
        Check(info.SequenceNumber == 2 && info.CountServices == 4 && info.CountTrustedCerts == 4 && info.Stored && info.Territory == "UA"
            && info.Warnings is null, "trusted lists: the list is accepted and stored");
        var caInfo = lists.GetCertInfo(ca);
        Check(caInfo.Trusted && caInfo.TrustServices is { Count: 1 } && caInfo.TrustServices[0].Type == "National-CA/QC"
            && caInfo.TrustServices[0].ForESignatures && caInfo.TrustServices[0].Statuses is { Count: 1 }
            && caInfo.TrustServices[0].Statuses![0].Status == "granted", "trusted lists: the CA of the list is trusted, with its service");
        var signerInfo = lists.GetCertInfo(signer);
        Check(signerInfo.TrustListSigner && !signerInfo.Trusted, "trusted lists: the signer of lists has its own status");
        Check(lists.AddTrustListText(System.Text.Encoding.UTF8.GetString(list)).SequenceNumber == 2, "trusted lists: the list as text");
        var accepted = lists.ListTrustLists();
        Check(accepted.Count == 1 && accepted[0].SequenceNumber == 2 && accepted[0].ListId == info.ListId && accepted[0].SignerCertId == info.SignerCertId,
            "trusted lists: the list of the accepted lists");
        ExpectCode(() => lists.AddTrustList(File.ReadAllBytes(Path.Combine(listDir, "trust-list-old.xml"))), 0x107B, "trusted lists: an older list is refused");
        ExpectCode(() => lists.AddTrustListText(System.Text.Encoding.UTF8.GetString(list).Replace("/Svcstatus/granted", "/Svcstatus/grantee")), 0x1079,
            "trusted lists: a changed list is refused");
        Check(lists.AddTrustList(File.ReadAllBytes(Path.Combine(listDir, "trust-list-withdrawn.xml"))).CountTrustedCerts == 3
            && !lists.GetCertInfo(ca).Trusted, "trusted lists: a withdrawn service is not trusted");
        using (var next = new Uapki())
        {
            next.Init(config);
            Check(next.UapkiInfo is { TrustListsCount: 1, RefusedTrustListsCount: 0 }, "trusted lists: the next INIT applies the stored list");
        }
        using (var noSigner = new Uapki())
        {
            noSigner.Init(new Uapki.Config() { Offline = true });
            ExpectCode(() => noSigner.AddTrustList(list), 0x107A, "trusted lists: a list of a signer that is not given is refused");
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

void ExpectCode(Action action, int errorCode, string what)
{
    try
    {
        action();
        Check(false, what + " (no exception)");
    }
    catch (UapkiException e)
    {
        Check(e.ErrorCode == errorCode, what + " (0x" + e.ErrorCode.ToString("X4") + ")");
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
