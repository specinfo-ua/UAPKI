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

using System;
using System.Text;
using System.Runtime.InteropServices;
using Newtonsoft.Json;
using System.Collections.Generic;

namespace UapkiLibrary
{
    public static partial class Uapki
    {
        [DllImport("uapki", EntryPoint = "process", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr _Process([MarshalAs(UnmanagedType.LPUTF8Str)] string request);

        [DllImport("uapki", EntryPoint = "json_free", CallingConvention = CallingConvention.Cdecl)]
        private static extern void _JsonFree(IntPtr response);

        private static unsafe string Process(string request)
        {
            string result = "{\"errorCode\":-1}";
            byte* resultPtr = (byte*)_Process(request);
            if (resultPtr != null)
            {
                int length = 0;
                for (byte* i = resultPtr; *i != 0; i++, length++) ;
                result = Encoding.UTF8.GetString(resultPtr, length);
                _JsonFree((IntPtr)resultPtr);
            }
            return result;
        }

        public static string Version()
        {
            var VERSION = new { method = "VERSION" };
            var ret = JsonConvert.DeserializeObject<dynamic>(Process(JsonConvert.SerializeObject(VERSION)));
            if (ret.errorCode != 0)
                throw new UapkiException((int)ret.errorCode);

            return ret.result.version;
        }

        public static dynamic Init(string certCachePath, string crlCachePath, string defaultTspUrl, List<byte[]> trustedCerts)
        {
            List<string> tCerts = null;

            if (trustedCerts != null)
            {
                tCerts = new List<string>();
                foreach (var trustedCert in trustedCerts)
                {
                    tCerts.Add(Convert.ToBase64String(trustedCert));
                }
            }

            var INIT = new
            {
                method = "INIT",
                parameters = new
                {
                    cmProviders = new
                    {
                        dir = "",
                        allowedProviders = new object[] {
                            new {
                                lib = "cm-pkcs12"
                            },
                            new {
                                lib = "cm-diamond"
                            },
                            new {
                                lib = "cm-almaz1c"
                            },
                            new {
                                lib = "cm-crystal1"
                            },
                            new {
                                lib = "cm-stoken"
                            }
                        }
                    },
                    certCache = new
                    {
                        path = certCachePath,
                        trustedCerts = tCerts
                    },
                    crlCache = new
                    {
                        path = crlCachePath
                    },
                    tsp = new
                    {
                        url = defaultTspUrl
                    },
                    offline = false
                }
            };
            var ret = JsonConvert.DeserializeObject<dynamic>(Process(JsonConvert.SerializeObject(INIT)));
            if (ret.errorCode != 0)
                throw new UapkiException((int)ret.errorCode);

            return ret.result;
        }

        public static void Deinit()
        {
            var DEINIT = new { method = "DEINIT" };
            var ret = JsonConvert.DeserializeObject<dynamic>(Process(JsonConvert.SerializeObject(DEINIT)));
            if (ret.errorCode != 0)
                throw new UapkiException((int)ret.errorCode);
        }

        public static dynamic Providers()
        {
            var PROVIDERS = new { method = "PROVIDERS" };
            var ret = JsonConvert.DeserializeObject<dynamic>(Process(JsonConvert.SerializeObject(PROVIDERS)));
            if (ret.errorCode != 0)
                throw new UapkiException((int)ret.errorCode);

            return ret.result;
        }

        public static dynamic VerifyCms(byte[] signature, byte[] content = null)
        {
            var VERIFY = new
            {
                method = "VERIFY",
                parameters = new
                {
                    signature = new {
                        bytes = signature,
                        content = content
                    }
                }
            };
            dynamic ret = JsonConvert.DeserializeObject<dynamic>(Process(JsonConvert.SerializeObject(VERIFY)));
            if (ret.errorCode != 0)
                throw new UapkiException((int)ret.errorCode);

            return ret.result;
        }
    }
}
