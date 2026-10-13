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

import java.util.List;

/**
 * Політика валідації, задана значеннями (параметр options.validationPolicy методу VERIFY з типом "FULL-ETSI"):
 * поле зі значенням null має значення політики basedOn
 */
public class ValidationPolicy {
    /** Назва передвстановленої політики */
    public static final String UKRAINE_DEFAULT = "UkraineDefault";
    /** Назва передвстановленої політики */
    public static final String ETSI_STRICT = "EtsiStrict";
    /** Назва політики у звіті, коли її задано значеннями */
    public static final String CUSTOM = "custom";

    private String basedOn;
    private Integer revocationFreshness;
    private String tsaExtendedKeyUsage;
    private String tsaTrust;
    private String pastValidation;
    private String certificatePathModel;
    private Integer timeStampDelay;
    private String cryptographicConstraints;
    private List<CryptoAlgorithm> cryptographicAlgorithms;
    private String signerKeyUsage;
    private Boolean caRemovesExpiredCerts;
    private Boolean checkCriticalExtensions;

    public ValidationPolicy() {
    }

    public ValidationPolicy(String basedOn) {
        this.basedOn = basedOn;
    }

    /** Передвстановлена політика, значення якої змінюються: "UkraineDefault" (за замовчуванням), "EtsiStrict" */
    public String getBasedOn() { return basedOn; }
    public ValidationPolicy setBasedOn(String basedOn) { this.basedOn = basedOn; return this; }
    /** Свіжість даних про статус сертифіката, хвилин */
    public Integer getRevocationFreshness() { return revocationFreshness; }
    public ValidationPolicy setRevocationFreshness(Integer revocationFreshness) { this.revocationFreshness = revocationFreshness; return this; }
    /** Затримка позначки часу, хвилин: заявлений час підписання плюс затримка має бути пізніше часу позначки часу підпису; 0 - не задано */
    /** Обмеження на криптографічні алгоритми: "off", "warning" або "fail" */
    public String getCryptographicConstraints() { return cryptographicConstraints; }
    public ValidationPolicy setCryptographicConstraints(String cryptographicConstraints) { this.cryptographicConstraints = cryptographicConstraints; return this; }
    /** Зміни до обмежень бібліотеки */
    public List<CryptoAlgorithm> getCryptographicAlgorithms() { return cryptographicAlgorithms; }
    public ValidationPolicy setCryptographicAlgorithms(List<CryptoAlgorithm> cryptographicAlgorithms) { this.cryptographicAlgorithms = cryptographicAlgorithms; return this; }
    public Integer getTimeStampDelay() { return timeStampDelay; }
    public ValidationPolicy setTimeStampDelay(Integer timeStampDelay) { this.timeStampDelay = timeStampDelay; return this; }
    /** Перевірка на минулий час (ETSI EN 319 102-1, 5.6): "bestSignatureTime" або "proofOfExistence" */
    public String getPastValidation() { return pastValidation; }
    /** Модель ланцюжка у перевірці на минулий час: "shell" або "chain" */
    public String getCertificatePathModel() { return certificatePathModel; }
    public ValidationPolicy setCertificatePathModel(String certificatePathModel) { this.certificatePathModel = certificatePathModel; return this; }
    public ValidationPolicy setPastValidation(String pastValidation) { this.pastValidation = pastValidation; return this; }
    /** Час, на який служба позначок часу має бути довіреною: "timeStampTime" (RFC 3161, розділ 4) або "proofOfExistence" (ETSI EN 319 102-1) */
    public String getTsaTrust() { return tsaTrust; }
    public ValidationPolicy setTsaTrust(String tsaTrust) { this.tsaTrust = tsaTrust; return this; }
    /** "allowAdditional" або "strict": призначення ключа сертифіката служби позначок часу, крім id-kp-timeStamping */
    public String getTsaExtendedKeyUsage() { return tsaExtendedKeyUsage; }
    public ValidationPolicy setTsaExtendedKeyUsage(String tsaExtendedKeyUsage) { this.tsaExtendedKeyUsage = tsaExtendedKeyUsage; return this; }
    /** "digitalSignatureOrNonRepudiation" або "nonRepudiation" */
    public String getSignerKeyUsage() { return signerKeyUsage; }
    public ValidationPolicy setSignerKeyUsage(String signerKeyUsage) { this.signerKeyUsage = signerKeyUsage; return this; }
    /** ЦСК вилучають сертифікати, строк дії яких закінчився, з даних про відкликання */
    public Boolean getCaRemovesExpiredCerts() { return caRemovesExpiredCerts; }
    public ValidationPolicy setCaRemovesExpiredCerts(Boolean caRemovesExpiredCerts) { this.caRemovesExpiredCerts = caRemovesExpiredCerts; return this; }
    /** Сертифікат з невідомим критичним розширенням непридатний; false - зауваження */
    public Boolean getCheckCriticalExtensions() { return checkCriticalExtensions; }
    public ValidationPolicy setCheckCriticalExtensions(Boolean checkCriticalExtensions) { this.checkCriticalExtensions = checkCriticalExtensions; return this; }
}
