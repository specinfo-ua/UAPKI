/*
 * Copyright (c) 2021, The UAPKI Project Authors.
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

package com.sit.uapki.method;

import com.google.gson.Gson;
import com.sit.uapki.cert.CertCacheInfo;
import com.sit.uapki.common.PkiData;
import com.sit.uapki.common.TspInfo;
import com.sit.uapki.crl.CrlCacheInfo;
import java.util.ArrayList;
import java.util.List;

/**
 * Classes for INIT-method
 */
public interface Init {
    static final String METHOD = "INIT";

    class Parameters {
        class CmProviderParameters {
            class Config {
                class CreatePfx {
                    String bagCipher;
                    String bagKdf;
                    int iterations;
                    String macAlgo;
                }
                CreatePfx createPfx;
            }
            final String lib;
            final Config config;

            public CmProviderParameters (String libName, String config) {
                this.lib = libName;
                if (config != null) {
                    Gson gson = new Gson();
                    this.config = gson.fromJson(config, Config.class);
                }
                else this.config = null;
            }
        }

        class CmProviders {
            final ArrayList<CmProviderParameters> allowedProviders = new ArrayList<>();

            public void AddProvider (String libName, String config) {
                allowedProviders.add(new CmProviderParameters(libName, config));
            }
        }

        class CertCache {
            final String path;
            ArrayList<String> trustedCerts;

            public CertCache (String path, List<PkiData> trustedCerts) {
                this.path = path;
                if (trustedCerts != null) {
                    this.trustedCerts = new ArrayList<String>(){};
                    for (PkiData it : trustedCerts) {
                        this.trustedCerts.add(it.toString());
                    }
                }
            }
        }

        class CrlCache {
            final String path;

            public CrlCache(String path) {
                this.path = path;
            }
        }

        public class Tsp {
            final String url;
            final String policy;

            public Tsp (String url, String policy) {
                this.url = url;
                this.policy = policy;
            }
        }

        CmProviders cmProviders;
        CertCache certCache;
        CrlCache crlCache;
        boolean offline;
        Tsp tsp;

        /**
         * Class for parameter of a Library.init()
         */
        public Parameters () {
        }

        /**
         * Add CM-provider to list CM-providers.
         * @param lib name of CM-provider
         * @param config of CM-provider. It's JSON-string
         */
        public void addCmProvider (String lib, String config) {
            if (this.cmProviders == null) {
                this.cmProviders = new CmProviders();
            }
            this.cmProviders.AddProvider(lib, config);
        }

        /**
         * Add CM-provider to list CM-providers.
         * @param libName name of CM-provider
         */
        public void addCmProvider (String libName) {
            addCmProvider(libName, null);
        }

        /**
         * Setup a cert-cache.
         * @param path to exists directory of certificates. 
         *        If it's null then cert-cache to store certificates in memory
         * @param trustedCerts - list trusted certificates. It's Base64-string
         */
        public void setCertCache (String path, List<PkiData> trustedCerts) {
            this.certCache = new CertCache(path, trustedCerts);
        }

        /**
         * Setup a CRL-cache.
         * @param path to exists directory of CRLs.
         *        If it's null then CRL-cache to store certificates in memory
         */
        public void setCrlCache (String path) {
            this.crlCache = new CrlCache(path);
        }

        /**
         * Set offline-mode
         * @param offline value of the offline-mode
         */
        public void setOffline (boolean offline) {
            this.offline = offline;
        }

        /**
         * Setup a cert-cache.
         * @param url an absolute URL of TSP-service
         * @param policy - TSP-policy. It's OID-string.
         *        If it's null then TSP-policy not present in TSP-request.
         */ 
        public void setTspParameters (String url, String policy) {
            this.tsp = new Tsp(url, policy);
        }
    }   //  end class Parameters

    class Result {
        private CertCacheInfo certCache;
        private CrlCacheInfo crlCache;
        private int countCmProviders;
        private boolean offline;
        private TspInfo tsp;

        public CertCacheInfo getCertCacheInfo () {
            return certCache;
        }

        public CrlCacheInfo getCrlCacheInfo () {
            return crlCache;
        }

        public int getCountCmProviders () {
            return countCmProviders;
        }

        public boolean isOffline () {
            return offline;
        }

        public TspInfo getTspInfo () {
            return tsp;
        }
    }   //  end class Result

}
