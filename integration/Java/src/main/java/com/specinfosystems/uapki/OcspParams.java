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
 * Параметри OCSP (параметр ocsp методу INIT)
 */
public class OcspParams {
    private Integer nonceLen;
    private Integer cacheTime;
    private Integer maxFreshness;
    private Integer responderCrlEmbedMaxSize;

    public Integer getNonceLen() { return nonceLen; }
    public OcspParams setNonceLen(Integer nonceLen) { this.nonceLen = nonceLen; return this; }
    /** Хвилини, протягом яких відповідь без nextUpdate береться з кешу (за замовчуванням 30) */
    public Integer getCacheTime() { return cacheTime; }
    public OcspParams setCacheTime(Integer cacheTime) { this.cacheTime = cacheTime; return this; }
    /** Максимальна свіжість (хвилини) відповіді без nextUpdate для VERIFY (за замовчуванням 120) */
    public Integer getMaxFreshness() { return maxFreshness; }
    public OcspParams setMaxFreshness(Integer maxFreshness) { this.maxFreshness = maxFreshness; return this; }
    /** Найбільший розмір (байти) СВС OCSP-відповідача, що вкладається в CAdES-B-LT/B-LTA (за замовчуванням 10240) */
    public Integer getResponderCrlEmbedMaxSize() { return responderCrlEmbedMaxSize; }
    public OcspParams setResponderCrlEmbedMaxSize(Integer responderCrlEmbedMaxSize) { this.responderCrlEmbedMaxSize = responderCrlEmbedMaxSize; return this; }
}
