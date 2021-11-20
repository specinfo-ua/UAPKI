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
        public static dynamic KeyGetCsr(string signAlgo = null)
        {
            var GET_CSR = new
            {
                method = "GET_CSR",
                parameters = new
                {
                    signAlgo = signAlgo
                }
            };
            var ret = JsonConvert.DeserializeObject<dynamic>(Process(JsonConvert.SerializeObject(GET_CSR)));
            if (ret.errorCode != 0)
                throw new UapkiException((int)ret.errorCode);

            return ret.result;
        }

        public static byte[] SignCms(byte[] data, bool detachedData = true, bool includeCert = true, bool useTSP = false)
        {
            var SIGN = new
            {
                method = "SIGN",
                parameters = new
                {
                    signParams = new
                    {
                        signatureFormat = useTSP ? "CAdES-T" : "CAdES-BES",
                        detachedData = detachedData,
                        includeCert = includeCert,
                        includeTime = true,
                        includeContentTS = useTSP,
                        signAlgo = "1.2.804.2.1.1.1.1.3.1.1",
                        signaturePolicy = new 
                        {
                            sigPolicyId = "1.2.804.2.1.1.1.2.1" // Політики сертифікації: Ознака відповідності Закону України <Про електронний цифровий підпис>
                        }
                    },
                    dataTbs = new object[]
                    {
                        new
                        {
                            id = "doc-0",
                            bytes = Convert.ToBase64String(data)
                        }
                    }
                }
            };

            dynamic ret = JsonConvert.DeserializeObject<dynamic>(Process(JsonConvert.SerializeObject(SIGN)));
            if (ret.errorCode != 0)
                throw new UapkiException((int)ret.errorCode);

            return Convert.FromBase64String((string)ret.result.signatures[0].bytes);
        }

        public static string KeyGenerate(string label)
        {
            var NEW_DSTU_KEY = new
            {
                method = "CREATE_KEY",
                parameters = new
                {
                    mechanismId = "1.2.804.2.1.1.1.1.3.1",
                    parameterId = "1.2.804.2.1.1.1.1.3.1.1.2.6",
                    label = label
                }
            };
            dynamic ret = JsonConvert.DeserializeObject<dynamic>(Process(JsonConvert.SerializeObject(NEW_DSTU_KEY)));
            if (ret.errorCode != 0)
                throw new UapkiException((int)ret.errorCode);

            return ret.result.id;
        }
    }
}
