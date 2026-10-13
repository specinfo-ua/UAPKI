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
using System.Text.Json.Serialization;

namespace UapkiNet;

//  VERIFY with the validation type "FULL-ETSI": the report with the status indications of ETSI EN 319 102-1 in the
//  structure of ETSI TS 119 102-2, and the validation policy
public partial class Uapki
{
    /// <summary>The names of the predefined validation policies</summary>
    public static class ValidationPolicyName
    {
        public const string UkraineDefault = "UkraineDefault";
        public const string EtsiStrict = "EtsiStrict";
        /// <summary>The name in the report when the policy is given by values</summary>
        public const string Custom = "custom";
    }

    /// <summary>A constraint on a cryptographic algorithm: a hash algorithm ("SHA1"...) or the keys of a family ("RSA", "EC") shorter than KeySizeBelow bits</summary>
    public class CryptoAlgorithm
    {
        public string Algorithm { get; init; } = string.Empty;
        public int? KeySizeBelow { get; init; }
        /// <summary>The date (YYYY-MM-DD) the algorithm is reliable until; an empty string - no limit</summary>
        public string ReliableUntil { get; init; } = string.Empty;
    }

    /// <summary>
    /// A validation policy given by values: the ones that are null are those of the policy BasedOn
    /// </summary>
    public class ValidationPolicy
    {
        /// <summary>"UkraineDefault" (default) or "EtsiStrict"</summary>
        public string? BasedOn { get; init; }
        /// <summary>Freshness of the data on the status of a certificate, minutes</summary>
        public int? RevocationFreshness { get; init; }
        /// <summary>"allowAdditional" or "strict": key purposes of a time-stamping certificate besides id-kp-timeStamping</summary>
        public string? TsaExtendedKeyUsage { get; init; }
        /// <summary>"timeStampTime" (RFC 3161, section 4) or "proofOfExistence" (ETSI EN 319 102-1): the time a TSA must be trusted at</summary>
        public string? TsaTrust { get; init; }
        /// <summary>"bestSignatureTime" or "proofOfExistence": the past validation of ETSI EN 319 102-1, 5.6</summary>
        public string? PastValidation { get; init; }
        /// <summary>"shell" or "chain": the model of the certification path in the past validation</summary>
        public string? CertificatePathModel { get; init; }
        /// <summary>Time-stamp delay, minutes: the claimed signing time plus the delay must be after the time of the signature time-stamp; 0 - not specified</summary>
        public int? TimeStampDelay { get; init; }
        /// <summary>"off", "warning" or "fail": the constraints on cryptographic algorithms</summary>
        public string? CryptographicConstraints { get; init; }
        /// <summary>Changes to the constraints of the library</summary>
        public List<CryptoAlgorithm>? CryptographicAlgorithms { get; init; }
        /// <summary>"digitalSignatureOrNonRepudiation" or "nonRepudiation"</summary>
        public string? SignerKeyUsage { get; init; }
        /// <summary>The CAs remove the expired certificates from the revocation data</summary>
        public bool? CaRemovesExpiredCerts { get; init; }
        /// <summary>A certificate with an unknown critical extension is unusable; false - a remark</summary>
        public bool? CheckCriticalExtensions { get; init; }
    }

    public class DigestAlgAndValue
    {
        public string DigestMethod { get; init; } = string.Empty;
        public byte[]? DigestValue { get; init; }
    }

    public class SignatureIdentifier
    {
        public DigestAlgAndValue? DigestAlgAndValue { get; init; }
        public byte[]? SignatureValue { get; init; }
        public bool HashOnly { get; init; }
        public bool DocHashOnly { get; init; }
    }

    public class CertificateChainRefs
    {
        public string SigningCertificate { get; init; } = string.Empty;
        public List<string>? IntermediateCertificates { get; init; }
        public string? TrustAnchor { get; init; }
    }

    public class RevocationStatusInformation
    {
        public string ValidationObjectId { get; init; } = string.Empty;

        [JsonPropertyName("revocationTime")]
        public string RevocationTimeRaw { get; init; } = string.Empty;

        [JsonIgnore]
        public DateTime RevocationTime => ConvertUtcTimeToDateTime(RevocationTimeRaw);

        public string? RevocationReason { get; init; }
    }

    public class TypedData
    {
        public string Type { get; init; } = string.Empty;
        public string Value { get; init; } = string.Empty;
    }

    public class AdditionalValidationReportData
    {
        public List<TypedData>? ReportData { get; init; }
    }

    /// <summary>
    /// Either the certificate chain (TrustAnchor, CertificateChain) or the data of one reason of the status
    /// </summary>
    public class ValidationReportData
    {
        public string? TrustAnchor { get; init; }
        public CertificateChainRefs? CertificateChain { get; init; }
        public string? RelatedValidationObject { get; init; }
        public RevocationStatusInformation? RevocationStatusInformation { get; init; }
        public AdditionalValidationReportData? AdditionalValidationReportData { get; init; }

        private string? Typed(string type) => AdditionalValidationReportData?.ReportData?.Find(d => d.Type == type)?.Value;

        /// <summary>The sub-indication the entry is about; null for the entry of the certificate chain</summary>
        [JsonIgnore]
        public string? SubIndication => Typed("subIndication");

        /// <summary>The indication of the reason: "FAILED" or "INDETERMINATE"</summary>
        [JsonIgnore]
        public string? MainIndication => Typed("mainIndication");

        /// <summary>A detail of the reason</summary>
        [JsonIgnore]
        public string? Info => Typed("info");
    }

    public class ValidationStatus
    {
        /// <summary>A signature: "TOTAL-PASSED", "TOTAL-FAILED", "INDETERMINATE"; a constraint or a validation
        /// object: "PASSED", "FAILED", "INDETERMINATE"</summary>
        public string MainIndication { get; init; } = string.Empty;
        public List<string>? SubIndications { get; init; }
        public List<ValidationReportData>? AssociatedValidationReportData { get; init; }

        /// <summary>The chain of the signing certificate, when it is built</summary>
        [JsonIgnore]
        public CertificateChainRefs? CertificateChain => AssociatedValidationReportData?.Find(d => d.CertificateChain is not null)?.CertificateChain;
    }

    public class SignatureValidationProcess
    {
        /// <summary>"Basic", "LTVM" or "LTA" (ETSI EN 319 102-1, 5.3, 5.5, 5.6)</summary>
        public string SignatureValidationProcessId { get; init; } = string.Empty;
    }

    public class ProofOfExistence
    {
        [JsonPropertyName("poeTime")]
        public string PoeTimeRaw { get; init; } = string.Empty;

        [JsonIgnore]
        public DateTime PoeTime => ConvertUtcTimeToDateTime(PoeTimeRaw);

        public string? TypeOfProof { get; init; }
        /// <summary>The identifier of the time-stamp that proves the time</summary>
        public string? PoeObject { get; init; }
    }

    public class ValidationTimeInfo
    {
        [JsonPropertyName("validationTime")]
        public string ValidationTimeRaw { get; init; } = string.Empty;

        [JsonIgnore]
        public DateTime ValidationTime => ConvertUtcTimeToDateTime(ValidationTimeRaw);

        public ProofOfExistence? BestSignatureTime { get; init; }
    }

    public class SignersDocument
    {
        public DigestAlgAndValue? DigestAlgAndValue { get; init; }
    }

    public class SignerInformation
    {
        public string SignerCertificate { get; init; } = string.Empty;
        public string? Signer { get; init; }
    }

    /// <summary>
    /// The quality of a signature that passed, by the statements of the signing certificate (Basis "certificate")
    /// </summary>
    public class SignatureQuality
    {
        /// <summary>"QESig", "AdESig-QC", "AdESig-QC-old", "AdESig" or the same with "Seal"</summary>
        public List<string>? SignatureQualityInformation { get; init; }
        /// <summary>"trustedList" or "certificate"</summary>
        public string? Basis { get; init; }
        /// <summary>For the basis "trustedList": the list confirms what the certificate states</summary>
        public bool? ConfirmedByTrustedList { get; init; }
        /// <summary>The service of the trusted list (listId, type, tspName, serviceName)</summary>
        public TrustService? TrustService { get; init; }
        public List<string>? QcStatements { get; init; }

        [JsonIgnore]
        public string? Level => (SignatureQualityInformation is { Count: > 0 }) ? SignatureQualityInformation[0] : null;
    }

    public class SignatureValidationPolicy
    {
        public string PolicyName { get; init; } = string.Empty;
        public string? BasedOn { get; init; }
    }

    public class ConstraintStatus
    {
        /// <summary>"applied" or "disabled"</summary>
        public string Status { get; init; } = string.Empty;
    }

    public class ValidationConstraint
    {
        public string ValidationConstraintIdentifier { get; init; } = string.Empty;
        public TypedData? ValidationConstraintParameter { get; init; }
        public ConstraintStatus? ConstraintStatus { get; init; }
        /// <summary>"fail" - the result defines the status of the signature; "warning" - the result is a remark</summary>
        public string? Level { get; init; }
        public ValidationStatus? ValidationStatus { get; init; }

        [JsonIgnore]
        public bool IsApplied => ConstraintStatus?.Status == "applied";

        /// <summary>A remark: the constraint did not pass and does not change the status of the signature</summary>
        [JsonIgnore]
        public bool IsWarning => IsApplied && (Level == "warning") && (ValidationStatus?.MainIndication != "PASSED");
    }

    public class ValidationConstraintsEvaluationReport
    {
        public SignatureValidationPolicy? SignatureValidationPolicy { get; init; }
        public List<ValidationConstraint>? ValidationConstraints { get; init; }
    }

    public class SignatureValidationReport
    {
        public int SignerInfoIndex { get; init; }
        public SignatureIdentifier? SignatureIdentifier { get; init; }
        public ValidationStatus SignatureValidationStatus { get; init; } = new ValidationStatus();
        public SignatureValidationProcess? SignatureValidationProcess { get; init; }
        public ValidationTimeInfo? ValidationTimeInfo { get; init; }
        public SignersDocument? SignersDocument { get; init; }
        public SignerInformation? SignerInformation { get; init; }
        public SignatureQuality? SignatureQuality { get; init; }
        public ValidationConstraintsEvaluationReport? ValidationConstraintsEvaluationReport { get; init; }
        public string SignatureFormat { get; init; } = string.Empty;

        [JsonPropertyName("signAlgo")]
        public string SignAlgoOid { get; init; } = string.Empty;

        [JsonPropertyName("signingTime")]
        public string? SigningTimeRaw { get; init; }

        [JsonIgnore]
        public DateTime? SigningTime => SigningTimeRaw is null ? null : ConvertUtcTimeToDateTime(SigningTimeRaw);

        /// <summary>The identifiers of the time-stamps of the signature in SignatureValidationObjects</summary>
        public List<string>? TimeStamps { get; init; }
        public List<CertChainInfo>? Certificates { get; init; }
        public List<ExpectedCertInfo>? ExpectedCerts { get; init; }
        public List<ExpectedCrlInfo>? ExpectedCrls { get; init; }
        public List<AttributeInfo>? SignedAttributes { get; init; }
        public List<AttributeInfo>? UnsignedAttributes { get; init; }

        /// <summary>The signature is to be accepted only when it passed</summary>
        [JsonIgnore]
        public bool IsTotalPassed => SignatureValidationStatus.MainIndication == "TOTAL-PASSED";

        /// <summary>The constraints that did not pass and are remarks by the policy</summary>
        [JsonIgnore]
        public List<ValidationConstraint> Warnings =>
            ValidationConstraintsEvaluationReport?.ValidationConstraints?.FindAll(c => c.IsWarning) ?? new List<ValidationConstraint>();
    }

    /// <summary>
    /// An object used in the validation: a certificate or a time-stamp (with the report of its own validation)
    /// </summary>
    public class ValidationObject
    {
        public string Id { get; init; } = string.Empty;
        /// <summary>"certificate" or "timestamp"</summary>
        public string ObjectType { get; init; } = string.Empty;

        //  A certificate
        public string? CN { get; init; }
        public Validity? Validity { get; init; }
        public bool? SelfSigned { get; init; }
        public bool? Trusted { get; init; }
        public string? IssuerCertId { get; init; }

        //  A time-stamp
        /// <summary>"CONTENT", "SIGNATURE", "ARCHIVE" or "ARCHIVE-V2"</summary>
        public string? TimeStampType { get; init; }
        /// <summary>For a time-stamp whose certificate is in a trusted list: "QTSA" or "TSA"</summary>
        public string? TimeStampQualification { get; init; }
        public ProofOfExistence? PoeProvisioning { get; init; }
        public ValidationObjectReport? ValidationReport { get; init; }

        [JsonPropertyName("genTime")]
        public string? GenTimeRaw { get; init; }

        [JsonIgnore]
        public DateTime? GenTime => GenTimeRaw is null ? null : ConvertUtcTimeToDateTime(GenTimeRaw);

        public string? PolicyId { get; init; }

        [JsonPropertyName("hashAlgo")]
        public string? HashAlgoOid { get; init; }

        public string? StatusDigest { get; init; }
        public string? StatusSignature { get; init; }
        public string? SignerCertId { get; init; }
    }

    public class ValidationObjectReport
    {
        public ValidationStatus? SignatureValidationStatus { get; init; }
    }

    /// <summary>
    /// The result of VERIFY with the validation type "FULL-ETSI"
    /// </summary>
    public class EtsiValidationResult
    {
        public ContentInfo? Content { get; init; }
        public List<SignatureValidationReport> SignatureValidationReports { get; init; } = new List<SignatureValidationReport>();
        public List<ValidationObject> SignatureValidationObjects { get; init; } = new List<ValidationObject>();

        /// <summary>The validation object with the identifier (a certificate identifier, a time-stamp identifier)</summary>
        public ValidationObject? FindObject(string id) => SignatureValidationObjects.Find(o => o.Id == id);
    }

    private class EtsiVerifyResult
    {
        public int ErrorCode { get; init; }
        public string? Method { get; init; }
        public EtsiValidationResult? Result { get; init; }
    }

    private class EtsiOptions
    {
        public string ValidationType { get; init; } = "FULL-ETSI";
        public int? VerifySignerInfoIndex { get; init; }
        //  The name of a policy (a string) or its values (an object)
        public JsonElement? ValidationPolicy { get; init; }
        public string? ProofOfExistenceTime { get; init; }
    }

    private class EtsiVerifyParams
    {
        public SignedData? Signature { get; init; }
        public EtsiOptions? Options { get; init; }
        public bool? ReturnContent { get; init; }
    }

    private static JsonElement? PolicyElement(string? policyName, ValidationPolicy? policy)
    {
        string? json = null;
        if (policy is not null)
        {
            json = JsonSerializer.Serialize(policy, jsonCtx.ValidationPolicy);
        }
        else if (policyName is not null)
        {
            //  A name is letters and digits; anything else is refused here, not passed on in JSON
            foreach (var c in policyName)
            {
                if (!char.IsLetterOrDigit(c)) throw new ArgumentException("The name of a validation policy", nameof(policyName));
            }
            json = "\"" + policyName + "\"";
        }
        if (json is null) return null;

        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }

    /// <summary>
    /// The time ("yyyy-MM-dd HH:mm:ss", UTC) the application attests the signatures verified next by VerifyEtsi... existed
    /// at, with all their objects: a proof of existence given as an input (ETSI EN 319 102-1, 5.6.3). null - none
    /// </summary>
    public string? EtsiProofOfExistenceTime { get; set; }

    private EtsiValidationResult VerifyEtsiRequest(SignedData signature, string? policyName, ValidationPolicy? policy, int? signerInfoIndex)
    {
        var parameters = new EtsiVerifyParams()
        {
            Signature = signature,
            Options = new EtsiOptions() { VerifySignerInfoIndex = signerInfoIndex, ValidationPolicy = PolicyElement(policyName, policy), ProofOfExistenceTime = EtsiProofOfExistenceTime },
            ReturnContent = false
        };
        string verify_cmd = Request("VERIFY", parameters, jsonCtx.EtsiVerifyParams);

        //  The error of the method is what stops the whole validation; what is found for a signature is in its report
        var ret = JsonSerializer.Deserialize(Process(verify_cmd), jsonCtx.EtsiVerifyResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0)
            throw new UapkiException(ret.ErrorCode);

        return ret.Result ?? throw new UapkiException(0x2001);
    }

    /// <summary>
    /// Validates a signature with the validation type "FULL-ETSI" and a predefined policy (null - the default one,
    /// "UkraineDefault"). content - the data of a signature without encapsulated content, else null
    /// </summary>
    public EtsiValidationResult VerifyEtsi(byte[] signature, byte[]? content = null, string? policyName = null, int? signerInfoIndex = null)
    {
        return VerifyEtsiRequest(new SignedData() { Bytes = signature, Content = content }, policyName, null, signerInfoIndex);
    }

    /// <summary>
    /// Validates a signature with the validation type "FULL-ETSI" and a policy given by values
    /// </summary>
    public EtsiValidationResult VerifyEtsi(byte[] signature, byte[]? content, ValidationPolicy policy, int? signerInfoIndex = null)
    {
        return VerifyEtsiRequest(new SignedData() { Bytes = signature, Content = content }, null, policy, signerInfoIndex);
    }

    /// <summary>
    /// Validates a detached signature against a content file (the library reads it in blocks), validation type "FULL-ETSI"
    /// </summary>
    public EtsiValidationResult VerifyEtsiDetached(byte[] signature, string contentFile, string? policyName = null, int? signerInfoIndex = null)
    {
        return VerifyEtsiRequest(new SignedData() { Bytes = signature, File = contentFile }, policyName, null, signerInfoIndex);
    }

    /// <summary>
    /// Validates a detached signature against a content file with a policy given by values, validation type "FULL-ETSI"
    /// </summary>
    public EtsiValidationResult VerifyEtsiDetached(byte[] signature, string contentFile, ValidationPolicy policy, int? signerInfoIndex = null)
    {
        return VerifyEtsiRequest(new SignedData() { Bytes = signature, File = contentFile }, null, policy, signerInfoIndex);
    }
}
