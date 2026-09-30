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
 * Що повернути в результаті MODIFY_CMS
 */
public class ModifyCmsOptions {
    private boolean returnContent;
    private boolean returnCerts;
    private boolean returnCrls;
    private boolean returnEncodedSignerInfo;

    public boolean getReturnContent() { return returnContent; }
    public ModifyCmsOptions setReturnContent(boolean returnContent) { this.returnContent = returnContent; return this; }

    public boolean getReturnCerts() { return returnCerts; }
    public ModifyCmsOptions setReturnCerts(boolean returnCerts) { this.returnCerts = returnCerts; return this; }

    public boolean getReturnCrls() { return returnCrls; }
    public ModifyCmsOptions setReturnCrls(boolean returnCrls) { this.returnCrls = returnCrls; return this; }

    public boolean getReturnEncodedSignerInfo() { return returnEncodedSignerInfo; }
    public ModifyCmsOptions setReturnEncodedSignerInfo(boolean returnEncodedSignerInfo) { this.returnEncodedSignerInfo = returnEncodedSignerInfo; return this; }
}
