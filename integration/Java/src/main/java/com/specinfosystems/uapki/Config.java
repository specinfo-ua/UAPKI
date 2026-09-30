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
 * Параметри методу INIT
 */
public class Config {
    private CmProvidersParams cmProviders;
    private CertCacheParams certCache;
    private CrlCacheParams crlCache;
    private OcspParams ocsp;
    private TspParams tsp;
    private ProxyParams proxy;
    private Boolean offline;
    private Boolean validationByCrl;

    public CmProvidersParams getCmProviders() { return cmProviders; }
    public Config setCmProviders(CmProvidersParams cmProviders) { this.cmProviders = cmProviders; return this; }

    public CertCacheParams getCertCache() { return certCache; }
    public Config setCertCache(CertCacheParams certCache) { this.certCache = certCache; return this; }

    public CrlCacheParams getCrlCache() { return crlCache; }
    public Config setCrlCache(CrlCacheParams crlCache) { this.crlCache = crlCache; return this; }

    public OcspParams getOcsp() { return ocsp; }
    public Config setOcsp(OcspParams ocsp) { this.ocsp = ocsp; return this; }

    public TspParams getTsp() { return tsp; }
    public Config setTsp(TspParams tsp) { this.tsp = tsp; return this; }

    public ProxyParams getProxy() { return proxy; }
    public Config setProxy(ProxyParams proxy) { this.proxy = proxy; return this; }

    public Boolean getOffline() { return offline; }
    public Config setOffline(Boolean offline) { this.offline = offline; return this; }

    public Boolean getValidationByCrl() { return validationByCrl; }
    public Config setValidationByCrl(Boolean validationByCrl) { this.validationByCrl = validationByCrl; return this; }
}
