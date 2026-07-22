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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace UapkiNet;

public static partial class Uapki
{
    public class QcStatements
    {
        public string StatementId { get; init; } = string.Empty;
        public string? StatementInfo { get; init; }
    }

    public class GeneralNames
    {
        public string? Dns { get; init; }
        public string? Email { get; init; }
    }

    public class CertificatePolicy
    {
        public string PolicyIdentifier { get; init; } = string.Empty;
    }

    public class CWaInfoAccessDescriptor
    {
        public string? Ocsp { get; init; }
        public string? CaIssuers { get; init; }
        public string? TimeStamping { get; init; }
    }

    public class Attribute
    {
        public string Type { get; init; } = string.Empty;
        public string Value { get; init; } = string.Empty;
    }

    public class AttributeInfo
    {
        public string Type { get; init; } = string.Empty;
        public byte[]? Bytes { get; init; }
    }

    public class CaInfoAccessDescriptor
    {
        public string? Ocsp { get; init; }
        public string? CaIssuers { get; init; }
        public string? TimeStamping { get; init; }
    }

    public class DecodedExtensionValue
    {
        //key usage
        public bool? DigitalSignature { get; init; }
        public bool? ContentCommitment { get; init; }
        public bool? KeyEncipherment { get; init; }
        public bool? DataEncipherment { get; init; }
        public bool? KeyAgreement { get; init; }
        public bool? KeyCertSign { get; init; }
        public bool? CrlSign { get; init; }
        public bool? EncipherOnly { get; init; }
        public bool? DecipherOnly { get; init; }
        // subjectKeyIdentifier and authorityKeyIdentifier
        public string? KeyIdentifier { get; init; }

        // constraints
        [JsonPropertyName("cA")]
        public bool? CA { get; init; }
        public int? PathLenConstraint { get; init; }

        // extKeyUsage OIDs
        public List<string>? KeyPurposeId { get; init; }
        // qcStatements
        public List<QcStatements>? QcStatements { get; init; }

        // generalNames
        public List<GeneralNames>? GeneralNames { get; init; }

        // certificatePolicies
        public List<CertificatePolicy>? CertificatePolicies { get; init; }

        // CRL and freshest CRL distribution points
        public List<string>? DistributionPoints { get; init; }

        // CA info access descriptions
        public List<CaInfoAccessDescriptor>? AccessDescriptions { get; init; }

        // subject directory attributes
        public List<Attribute>? Attributes { get; init; }
    }

    public class DecodedExtension
    {
        public string Id { get; init; } = string.Empty;
        public DecodedExtensionValue? Value { get; init; }
    }

    public class Extension
    {
        public string ExtnId { get; init; } = string.Empty;
        public bool? Critical { get; init; }
        public byte[] ExtnValue { get; init; } = Array.Empty<byte>();
        public DecodedExtension? Decoded { get; init; }
    }

    public class CertKeyUsage
    {
        public bool DigitalSignature { get; set; } = false;
        public bool ContentCommitment { get; set; } = false;
        public bool KeyEncipherment { get; set; } = false;
        public bool DataEncipherment { get; set; } = false;
        public bool KeyAgreement { get; set; } = false;
        public bool KeyCertSign { get; set; } = false;
        public bool CrlSign { get; set; } = false;
        public bool EncipherOnly { get; set; } = false;
        public bool DecipherOnly { get; set; } = false;
        [JsonIgnore]
        public string AsString
        {
            get
            {
                string s = "";
                string delimiter = ", ";
                if (DigitalSignature) s += UapkiResources.DigitalSignature + delimiter;
                if (ContentCommitment) s += UapkiResources.NonRepudiation + delimiter;
                if (KeyEncipherment) s += UapkiResources.KeyEncipherment + delimiter;
                if (DataEncipherment) s += UapkiResources.DataEncipherment + delimiter;
                if (KeyAgreement) s += UapkiResources.KeyAgreement + delimiter;
                if (KeyCertSign) s += UapkiResources.KeyCertSign + delimiter;
                if (CrlSign) s += UapkiResources.CrlSign + delimiter;
                if (EncipherOnly) s += UapkiResources.EncipherOnly + delimiter;
                if (DecipherOnly) s += UapkiResources.DecipherOnly + delimiter;
                return s.Remove(s.Length - delimiter.Length);
            }
        }

        [JsonIgnore]
        public short AsInt
        {
            get
            {
                short ret = 0;
                if (DigitalSignature) ret |= 1 << 0;
                if (ContentCommitment) ret |= 1 << 1;
                if (KeyEncipherment) ret |= 1 << 2;
                if (DataEncipherment) ret |= 1 << 3;
                if (KeyAgreement) ret |= 1 << 4;
                if (KeyCertSign) ret |= 1 << 5;
                if (CrlSign) ret |= 1 << 6;
                if (EncipherOnly) ret |= 1 << 7;
                if (DecipherOnly) ret |= 1 << 8;
                return ret;
            }

            set
            {
                DigitalSignature = (value & (1 << 0)) != 0;
                ContentCommitment = (value & (1 << 1)) != 0;
                KeyEncipherment = (value & (1 << 2)) != 0;
                DataEncipherment = (value & (1 << 3)) != 0;
                KeyAgreement = (value & (1 << 4)) != 0;
                KeyCertSign = (value & (1 << 5)) != 0;
                CrlSign = (value & (1 << 6)) != 0;
                EncipherOnly = (value & (1 << 7)) != 0;
                DecipherOnly = (value & (1 << 8)) != 0;
            }
        }

        public CertKeyUsage() { }

        public CertKeyUsage(Extension extn)
        {
            var ku = extn.Decoded?.Value;
            DigitalSignature = ku?.DigitalSignature ?? false;
            ContentCommitment = ku?.ContentCommitment ?? false;
            KeyEncipherment = ku?.KeyEncipherment ?? false;
            DataEncipherment = ku?.DataEncipherment ?? false;
            KeyAgreement = ku?.KeyAgreement ?? false;
            KeyCertSign = ku?.KeyCertSign ?? false;
            CrlSign = ku?.CrlSign ?? false;
            EncipherOnly = ku?.EncipherOnly ?? false;
            DecipherOnly = ku?.DecipherOnly ?? false;
        }
    }
}
