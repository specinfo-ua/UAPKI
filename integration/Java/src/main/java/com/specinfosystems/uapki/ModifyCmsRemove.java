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
 * Що видалити з PKCS#7-підпису (MODIFY_CMS, remove); видалення виконується до додавання
 */
public class ModifyCmsRemove {
    private Boolean content;
    private Integer signIndex;
    private Boolean certificates;
    private Boolean crls;

    public Boolean getContent() { return content; }
    public ModifyCmsRemove setContent(Boolean content) { this.content = content; return this; }

    /**
     * @return індекс підпису (структури SignerInfo), який видаляється
     */
    public Integer getSignIndex() { return signIndex; }
    public ModifyCmsRemove setSignIndex(Integer signIndex) { this.signIndex = signIndex; return this; }

    /**
     * @return видалити всі сертифікати
     */
    public Boolean getCertificates() { return certificates; }
    public ModifyCmsRemove setCertificates(Boolean certificates) { this.certificates = certificates; return this; }

    /**
     * @return видалити всі СВС
     */
    public Boolean getCrls() { return crls; }
    public ModifyCmsRemove setCrls(Boolean crls) { this.crls = crls; return this; }
}
