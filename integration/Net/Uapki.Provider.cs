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

namespace UapkiLibrary
{
    public partial class Uapki
    {
        public static dynamic OpenStorage(string providerId, string storageId, string password, string mode = null)
        {
            if (mode == null) 
                mode = "RO";

            var OPEN_P12 = new
            {
                method = "OPEN",
                parameters = new
                {
                    provider = providerId,
                    storage = storageId,
                    password = password,
                    mode = mode,
                    openParams = new
                    {
                        bagCipher = "1.2.804.2.1.1.1.1.1.1.3",
                        bagKdf = "1.2.804.2.1.1.1.1.1.2",
                        macAlgo = "1.2.804.2.1.1.1.1.2.1",
                        iterations = 10000
                    }
                }
            };

            dynamic ret = JsonConvert.DeserializeObject<dynamic>(Process(JsonConvert.SerializeObject(OPEN_P12)));
            if (ret.errorCode != 0)
                throw new UapkiException(ret.errorCode);

            return ret.result;
        }

        public static void CloseStorage()
        {
            var DEINIT = new { method = "CLOSE" };
            var ret = JsonConvert.DeserializeObject<dynamic>(Process(JsonConvert.SerializeObject(DEINIT)));
            if (ret.errorCode != 0)
                throw new UapkiException(ret.errorCode);
        }
    }
}
