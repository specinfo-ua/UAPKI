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

#include <napi.h>
#include <string>
#include <stdlib.h>
#include "dl-macros.h"
#include "uapki-loader.h"

static const char* VERSION_ADDON = "1.0.0";


UapkiLoader uapki;

Napi::String Version (const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    return Napi::String::New(env, VERSION_ADDON);
}   //  Version

Napi::Boolean Load (const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    const bool rv = uapki.load();
    return Napi::Boolean::New(env, rv);
}   //  Load

Napi::String Process(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 1) throw Napi::TypeError::New(info.Env(), "Argument expected (string of JSON).");

    if (!uapki.isLoaded()) throw Napi::TypeError::New(info.Env(), "Library 'UAPKI' not loaded.");

    Napi::String ns_param = info[0].As<Napi::String>();
    std::string rv_s;
    std::string s_param = std::string(ns_param);
    char* s_resp = uapki.process(s_param.c_str());
    if (s_resp) {
        rv_s = std::string(s_resp);
        uapki.jsonFree(s_resp);
    }

    return Napi::String::New(env, rv_s);
}   //  Process

Napi::Value Unload (const Napi::CallbackInfo& info) {
    uapki.unload();
    return info.Env().Undefined();
}   //  Unload

Napi::Object init (Napi::Env env, Napi::Object exports) {
    exports.Set(Napi::String::New(env, "version"), Napi::Function::New(env, Version));
    exports.Set(Napi::String::New(env, "load"), Napi::Function::New(env, Load));
    exports.Set(Napi::String::New(env, "process"), Napi::Function::New(env, Process));
    exports.Set(Napi::String::New(env, "unload"), Napi::Function::New(env, Unload));

    return exports;
};

NODE_API_MODULE(uapki, init);
