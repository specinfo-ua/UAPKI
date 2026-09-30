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
 * Що додати до PKCS#7-підпису (MODIFY_CMS, add)
 */
public class AddSignature {
    private byte[] bytes;
    private Boolean isSignerInfo;
    private Integer signIndex;
    private byte[] content;
    private List<byte[]> certificates;
    private List<byte[]> crls;

    /**
     * @return PKCS#7-підпис або, якщо isSignerInfo = true, DER-кодована структура SignerInfo
     */
    public byte[] getBytes() { return bytes; }
    public AddSignature setBytes(byte[] bytes) { this.bytes = bytes; return this; }

    /**
     * @return ознака, що в bytes знаходиться структура SignerInfo
     */
    public Boolean getIsSignerInfo() { return isSignerInfo; }
    public AddSignature setIsSignerInfo(Boolean isSignerInfo) { this.isSignerInfo = isSignerInfo; return this; }

    /**
     * @return індекс підпису в PKCS#7-підписі з bytes, який додається (за замовчуванням 0)
     */
    public Integer getSignIndex() { return signIndex; }
    public AddSignature setSignIndex(Integer signIndex) { this.signIndex = signIndex; return this; }

    /**
     * @return контент; має відповідати гешу в першому підписі
     */
    public byte[] getContent() { return content; }
    public AddSignature setContent(byte[] content) { this.content = content; return this; }

    public List<byte[]> getCertificates() { return certificates; }
    public AddSignature setCertificates(List<byte[]> certificates) { this.certificates = certificates; return this; }

    public List<byte[]> getCrls() { return crls; }
    public AddSignature setCrls(List<byte[]> crls) { this.crls = crls; return this; }
}
