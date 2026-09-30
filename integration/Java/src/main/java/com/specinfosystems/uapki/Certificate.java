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

package com.specinfosystems.uapki;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Сертифікат (результат методу CERT_INFO); похідні властивості (isCa, keyUsage, drfo, ...) визначаються
 * з розширень під час першого звернення до них
 */
public final class Certificate {
    private byte[] bytes;
    private int version;
    private String serialNumber;
    private DistinguishedName issuer;
    private Validity validity;
    private DistinguishedName subject;
    private SubjectPublicKeyInfo subjectPublicKeyInfo;
    private SignatureInfo signatureInfo;
    private List<Extension> extensions;
    private boolean selfSigned;

    private transient String id = "";
    private transient Derived derived;

    private Certificate() {
    }

    //  Derived from the extensions
    private static final class Derived {
        boolean isCa;
        boolean isTsp;
        boolean isOcsp;
        boolean isCmp;
        boolean isQualified;
        boolean isOldQualified;
        boolean isQscd;
        int pathLenConstraint;
        CertKeyUsage keyUsage = CertKeyUsage.NONE;
        String subjectKeyIdentifier = "";
        String authorityKeyIdentifier = "";
        String subjectAltNameDns;
        String subjectAltNameEmail;
        String qualifiedStatementInfo;
        List<String> otherEkus;
        List<String> otherStatements = new ArrayList<>();
        List<String> certificatePolicies;
        List<String> crlDistributionPoints;
        List<String> freshestCrl;
        List<String> ocsp;
        List<String> caCerts;
        List<String> timeStamping;
        String drfo;
        String edrpou;
        String eddr;
        String nbu;
        String spmf;
        String org;
        String unit;
        String user;
    }

    private synchronized Derived derived() {
        if (derived == null)
            derived = parseExtensions();
        return derived;
    }

    private Derived parseExtensions() {
        Derived d = new Derived();
        for (Extension extension : extensions()) {
            try {
                DecodedExtensionValue value = extension.decoded() == null ? null : extension.decoded().value();
                switch (extension.extnId()) {
                    case "2.5.29.15":
                        d.keyUsage = CertKeyUsage.fromExtension(extension);
                        break;

                    case "2.5.29.14":
                        d.subjectKeyIdentifier = (value == null) ? "" : Util.str(value.keyIdentifier());
                        break;

                    case "2.5.29.35":
                        d.authorityKeyIdentifier = (value == null) ? "" : Util.str(value.keyIdentifier());
                        break;

                    case "2.5.29.19":
                        if (value != null) {
                            d.isCa = Boolean.TRUE.equals(value.ca());
                            d.pathLenConstraint = value.pathLenConstraint() == null ? 0 : value.pathLenConstraint();
                        }
                        break;

                    case "2.5.29.37":
                        if (value == null || value.keyPurposeId() == null)
                            break;

                        d.otherEkus = new ArrayList<>();
                        for (String purpose : value.keyPurposeId()) {
                            if (purpose.equals("1.3.6.1.5.5.7.3.8")) d.isTsp = true;
                            else if (purpose.equals("1.3.6.1.5.5.7.3.9")) d.isOcsp = true;
                            else if (purpose.equals("1.3.6.1.4.1.19398.1.1.8.1")) d.isCmp = true;
                            else d.otherEkus.add(purpose);
                        }
                        break;

                    case "1.3.6.1.5.5.7.1.3":
                        if (value == null || value.qcStatements() == null)
                            break;

                        d.otherStatements = new ArrayList<>();
                        for (QcStatements statement : value.qcStatements()) {
                            String sid = statement.statementId();
                            if (sid.equals("0.4.0.1862.1.1")) d.isQualified = true;
                            else if (sid.equals("0.4.0.1862.1.4")) d.isQscd = true;
                            else if (sid.equals("0.4.0.1862.1.5")) {
                                byte[] asn1Encoded = Base64.getDecoder().decode(statement.statementInfo());
                                if ((asn1Encoded.length > 10) && (asn1Encoded[0] == 0x30) && ((asn1Encoded[1] & 0x80) == 0)
                                        && (asn1Encoded[2] == 0x30) && (asn1Encoded[4] == 0x16))
                                    d.qualifiedStatementInfo = new String(asn1Encoded, 6, asn1Encoded[5] & 0xFF, StandardCharsets.US_ASCII);
                                else
                                    d.qualifiedStatementInfo = statement.statementInfo();
                            }
                            else if (sid.equals("1.2.804.2.1.1.1.2.2")) d.isOldQualified = true;
                            else d.otherStatements.add(sid);
                        }
                        break;

                    case "2.5.29.17":
                        if (value == null || value.generalNames() == null)
                            break;

                        for (GeneralNames name : value.generalNames()) {
                            d.subjectAltNameDns = name.dns();
                            d.subjectAltNameEmail = name.email();
                        }
                        break;

                    case "2.5.29.32":
                        if (value == null || value.certificatePolicies() == null)
                            break;

                        d.certificatePolicies = new ArrayList<>();
                        for (CertificatePolicy policy : value.certificatePolicies())
                            d.certificatePolicies.add(policy.policyIdentifier());
                        break;

                    case "2.5.29.31":
                        if (value == null || value.distributionPoints() == null)
                            break;

                        d.crlDistributionPoints = value.distributionPoints();
                        break;

                    case "2.5.29.46":
                        if (value == null || value.distributionPoints() == null)
                            break;

                        d.freshestCrl = value.distributionPoints();
                        break;

                    case "1.3.6.1.5.5.7.1.1":
                        if (value == null || value.accessDescriptions() == null)
                            break;

                        d.ocsp = new ArrayList<>();
                        d.caCerts = new ArrayList<>();
                        for (CaInfoAccessDescriptor descr : value.accessDescriptions()) {
                            if (descr.ocsp() != null) d.ocsp.add(descr.ocsp());
                            if (descr.caIssuers() != null) d.caCerts.add(descr.caIssuers());
                        }
                        break;

                    case "1.3.6.1.5.5.7.1.11":
                        if (value == null || value.accessDescriptions() == null)
                            break;

                        d.timeStamping = new ArrayList<>();
                        for (CaInfoAccessDescriptor descr : value.accessDescriptions()) {
                            if (descr.timeStamping() != null) d.timeStamping.add(descr.timeStamping());
                        }
                        break;

                    case "2.5.29.9":
                        if (value == null || value.attributes() == null)
                            break;

                        for (Attribute attrib : value.attributes()) {
                            switch (attrib.type()) {
                                case "1.2.804.2.1.1.1.11.1.4.1.1": d.drfo = attrib.value(); break;
                                case "1.2.804.2.1.1.1.11.1.4.2.1": d.edrpou = attrib.value(); break;
                                case "1.2.804.2.1.1.1.11.1.4.3.1": d.nbu = attrib.value(); break;
                                case "1.2.804.2.1.1.1.11.1.4.4.1": d.spmf = attrib.value(); break;
                                case "1.2.804.2.1.1.1.11.1.4.5.1": d.org = attrib.value(); break;
                                case "1.2.804.2.1.1.1.11.1.4.6.1": d.unit = attrib.value(); break;
                                case "1.2.804.2.1.1.1.11.1.4.7.1": d.user = attrib.value(); break;
                                case "1.2.804.2.1.1.1.11.1.4.11.1": d.eddr = attrib.value(); break;
                                default: throw new UapkiException(1);
                            }
                        }
                        break;

                    default:
                        break;
                }
            } catch (RuntimeException e) {
                //  do nothing
            }
        }

        DistinguishedName subj = subject();
        if (d.drfo == null && subj.serialNumber() != null && subj.serialNumber().startsWith("TINUA-"))
            d.drfo = subj.serialNumber().substring(6);

        if (d.edrpou == null && subj.oi() != null && subj.oi().startsWith("NTRUA-"))
            d.edrpou = subj.oi().substring(6);

        return d;
    }

    private static final DistinguishedName EMPTY_NAME = new DistinguishedName(null, null, null, null, null, null, null, null, null, null, null, null, null);

    public byte[] bytes() { return Util.bytes(bytes); }
    public int version() { return version; }
    public String serialNumber() { return Util.str(serialNumber); }
    public DistinguishedName issuer() { return issuer == null ? EMPTY_NAME : issuer; }
    public Validity validity() { return validity == null ? new Validity(null, null) : validity; }
    public DistinguishedName subject() { return subject == null ? EMPTY_NAME : subject; }
    public SubjectPublicKeyInfo subjectPublicKeyInfo() { return subjectPublicKeyInfo == null ? new SubjectPublicKeyInfo(null, null, null, null) : subjectPublicKeyInfo; }
    public SubjectPublicKeyInfo spki() { return subjectPublicKeyInfo(); }
    public SignatureInfo signatureInfo() { return signatureInfo == null ? new SignatureInfo(null, null, null) : signatureInfo; }
    public List<Extension> extensions() { return Util.list(extensions); }
    public boolean selfSigned() { return selfSigned; }
    public Instant notBefore() { return validity().notBefore(); }
    public Instant notAfter() { return validity().notAfter(); }

    /**
     * @return ідентифікатор сертифіката (certId), за яким його отримано
     */
    public String id() { return id; }

    void setId(String id) { this.id = id; }

    public boolean isCa() { return derived().isCa; }
    public boolean isTsp() { return derived().isTsp; }
    public boolean isOcsp() { return derived().isOcsp; }
    public boolean isCmp() { return derived().isCmp; }
    public boolean isQualified() { return derived().isQualified; }
    public boolean isOldQualified() { return derived().isOldQualified; }
    public boolean isQscd() { return derived().isQscd; }
    public int pathLenConstraint() { return derived().pathLenConstraint; }
    public CertKeyUsage keyUsage() { return derived().keyUsage; }
    public String subjectKeyIdentifier() { return derived().subjectKeyIdentifier; }
    public String authorityKeyIdentifier() { return derived().authorityKeyIdentifier; }
    public String subjectAltNameDns() { return derived().subjectAltNameDns; }
    public String subjectAltNameEmail() { return derived().subjectAltNameEmail; }
    public String qualifiedStatementInfo() { return derived().qualifiedStatementInfo; }
    public List<String> otherEkus() { return derived().otherEkus; }
    public List<String> otherStatements() { return derived().otherStatements; }
    public List<String> certificatePolicies() { return derived().certificatePolicies; }
    public List<String> crlDistributionPoints() { return derived().crlDistributionPoints; }
    public List<String> freshestCrl() { return derived().freshestCrl; }
    public List<String> ocsp() { return derived().ocsp; }
    public List<String> caCerts() { return derived().caCerts; }
    public List<String> timeStamping() { return derived().timeStamping; }
    public String drfo() { return derived().drfo; }
    public String edrpou() { return derived().edrpou; }
    public String eddr() { return derived().eddr; }
    public String nbu() { return derived().nbu; }
    public String spmf() { return derived().spmf; }
    public String org() { return derived().org; }
    public String unit() { return derived().unit; }
    public String user() { return derived().user; }
}
