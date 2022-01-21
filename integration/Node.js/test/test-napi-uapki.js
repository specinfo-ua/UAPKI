/*
 * Copyright (c) 2022, The UAPKI Project Authors.
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

const addon = require('./uapki');

console.log('Test API node-addon, addon:', addon)

try {
  if (!addon || !addon.version || !addon.load || !addon.unload || !addon.process)
    throw 'Invalid node-addon UAPKI';

  console.log('addon.version', addon.version())

  function doProcess (request) {
    const s_request = JSON.stringify(request);
    console.log(`process, request: ${s_request}`)
    const s_result = addon.process(s_request);
    console.log(`process, result: ${s_result}`)
    return JSON.parse(s_result);
  } //  doProcess

  const LIB_NAME = 'uapki';
  let ok = addon.load(LIB_NAME);
  console.log('addon.load', ok)

  let resp = doProcess({ method: 'VERSION'});
  console.log('resp(VERSION)', resp)

  const b64_data = 'VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==';// 'The quick brown fox jumps over the lazy dog'
  const b64_expectedhash = '16j7swfXgJRpypq8sAguT41WUeRtPNt2LQLQvzfJ5ZI=';
  resp = doProcess({
    method: 'DIGEST',
    parameters: {
      hashAlgo: '2.16.840.1.101.3.4.2.1', // sha256
      bytes: b64_data
    }
  });
  console.log('resp(DIGEST)', resp)
  if (resp.result.bytes === b64_expectedhash) console.log('DIGEST is OK.')

  //TODO: execute other methods

  console.log('TEST COMPLETED')
} catch (e) {
  console.log('Test API node-addon, exception:', e)
}