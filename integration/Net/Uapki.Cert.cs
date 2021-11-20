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

using Newtonsoft.Json;
using System;

namespace UapkiLibrary
{
    public partial class Uapki
    {
        public static dynamic CertInfo(byte[] cert)
        {
            var CERT_INFO = new
            {
                method = "CERT_INFO",
                parameters = new
                {
                    bytes = Convert.ToBase64String(cert)
                }
            };
            var ret = JsonConvert.DeserializeObject<dynamic>(Process(JsonConvert.SerializeObject(CERT_INFO)));
            if (ret.errorCode != 0)
                throw new UapkiException((int)ret.errorCode);

            return ret.result;
        }

        public static dynamic CertInfo(string certId)
        {
            var CERT_INFO = new
            {
                method = "CERT_INFO",
                parameters = new
                {
                    certId = certId
                }
            };
            var ret = JsonConvert.DeserializeObject<dynamic>(Process(JsonConvert.SerializeObject(CERT_INFO)));
            if (ret.errorCode != 0)
                throw new UapkiException((int)ret.errorCode);

            return ret.result;
        }

        public static dynamic CertVerify(byte[] cert, bool useOCSP = false, bool useCRL = false, DateTime? validateTime = null)
        {
            string vType = null;
            if (validateTime != null || useCRL)
            {
                vType = "CRL";
            }
            else if (useOCSP)
            {
                vType = "OCSP";
            }

            var VERIFY_CERT = new
            {
                method = "VERIFY_CERT",
                parameters = new
                {
                    bytes = Convert.ToBase64String(cert),
                    validationType = vType,
                    validateTime = validateTime
                }
            };
            var ret = JsonConvert.DeserializeObject<dynamic>(Process(JsonConvert.SerializeObject(VERIFY_CERT)));
            if (ret.errorCode != 0)
                throw new UapkiException((int)ret.errorCode);

            return ret.result;
        }

        public static dynamic CertVerify(string certId, bool useOCSP = false, bool useCRL = false, DateTime? validateTime = null)
        {
            string vType = null;
            if (validateTime != null || useCRL)
            {
                vType = "CRL";
            }
            else if (useOCSP)
            {
                vType = "OCSP";
            }

            var VERIFY_CERT = new
            {
                method = "VERIFY_CERT",
                parameters = new
                {
                    certId = certId,
                    validationType = vType,
                    validateTime = validateTime
                }
            };
            var ret = JsonConvert.DeserializeObject<dynamic>(Process(JsonConvert.SerializeObject(VERIFY_CERT)));
            if (ret.errorCode != 0)
                throw new UapkiException((int)ret.errorCode);

            return ret.result;
        }

        public static string CertAddToCache(byte[] cert, bool permanent = true)
        {
            var ADD_CERT = new
            {
                method = "ADD_CERT",
                parameters = new
                {
                    certificates = new string[] { Convert.ToBase64String(cert) },
                    permanent = permanent
                }
            };
            var ret = JsonConvert.DeserializeObject<dynamic>(Process(JsonConvert.SerializeObject(ADD_CERT)));
            if (ret.errorCode != 0)
                throw new UapkiException((int)ret.errorCode);

            return ret.result.added[0].certId;
        }

        public static void CertRemoveFromCache(string certId)
        {
            var REMOVE_CERT = new
            {
                method = "REMOVE_CERT",
                parameters = new
                {
                    certId = certId
                }
            };
            var ret = JsonConvert.DeserializeObject<dynamic>(Process(JsonConvert.SerializeObject(REMOVE_CERT)));
            if (ret.errorCode != 0)
                throw new UapkiException((int)ret.errorCode);
        }

        public static dynamic CertsInCache(int offset = 0, int? pageSize = null)
        {
            var LIST_CERTS = new
            {
                method = "LIST_CERTS",
                parameters = new
                {
                    offset = offset,
                    pageSize = pageSize
                }
            };
            var ret = JsonConvert.DeserializeObject<dynamic>(Process(JsonConvert.SerializeObject(LIST_CERTS)));
            if (ret.errorCode != 0)
                throw new UapkiException((int)ret.errorCode);

            return ret.result;
        }
    }
}
