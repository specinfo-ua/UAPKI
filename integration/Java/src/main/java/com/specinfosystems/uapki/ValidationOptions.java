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

/**
 * Параметри перевірки підпису (параметр options методу VERIFY)
 */
public class ValidationOptions {
    //  Поле зі значенням null не передається (діє значення бібліотеки за замовчуванням)
    private String validationType;
    private Boolean onlyCrl;
    private Integer verifySignerInfoIndex;
    private Boolean checkCriticalExtensions;
    private Boolean caRemovesExpiredCerts;

    public ValidationOptions() {
    }

    public ValidationOptions(String validationType) {
        this.validationType = validationType;
    }

    /** Тип перевірки: "FULL", "CHAIN", "STRUCT" */
    public String getValidationType() { return validationType; }
    public ValidationOptions setValidationType(String validationType) { this.validationType = validationType; return this; }
    /** Використовувати виключно СВС (за замовчуванням як "validationByCrl" при ініціалізації) */
    public Boolean getOnlyCrl() { return onlyCrl; }
    public ValidationOptions setOnlyCrl(Boolean onlyCrl) { this.onlyCrl = onlyCrl; return this; }
    /** Перевірити окремого підписувача (перший індекс 0); null - усіх */
    public Integer getVerifySignerInfoIndex() { return verifySignerInfoIndex; }
    public ValidationOptions setVerifySignerInfoIndex(Integer verifySignerInfoIndex) { this.verifySignerInfoIndex = verifySignerInfoIndex; return this; }
    /** Сертифікат з невідомим критичним розширенням непридатний (RFC 5280, 4.2); за замовчуванням false */
    public Boolean getCheckCriticalExtensions() { return checkCriticalExtensions; }
    public ValidationOptions setCheckCriticalExtensions(Boolean checkCriticalExtensions) { this.checkCriticalExtensions = checkCriticalExtensions; return this; }
    /** ЦСК вилучають сертифікати, строк дії яких закінчився, з даних про відкликання (RFC 5280, 3.3): дані, видані після
     *  закінчення строку дії сертифіката, не доводять, що його не відкликано; за замовчуванням false */
    public Boolean getCaRemovesExpiredCerts() { return caRemovesExpiredCerts; }
    public ValidationOptions setCaRemovesExpiredCerts(Boolean caRemovesExpiredCerts) { this.caRemovesExpiredCerts = caRemovesExpiredCerts; return this; }
}
