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

#include "global-objects.h"


namespace UapkiNS {


static LibraryConfig* lib_config = nullptr;
static Cert::CerStore* lib_cerstore = nullptr;
static Crl::CrlStore* lib_crlstore = nullptr;


LibraryConfig* get_config (void)
{
    if (!lib_config) {
        lib_config = new LibraryConfig();
    }
    return lib_config;
}

Cert::CerStore* get_cerstore (void)
{
    if (!lib_cerstore) {
        lib_cerstore = new Cert::CerStore();
    }
    return lib_cerstore;
}

Crl::CrlStore* get_crlstore (void)
{
    if (!lib_crlstore) {
        lib_crlstore = new Crl::CrlStore();
    }
    return lib_crlstore;
}

void release_config (void)
{
    if (lib_config) {
        delete lib_config;
        lib_config = nullptr;
    }
}

void release_stores (void)
{
    if (lib_cerstore) {
        delete lib_cerstore;
        lib_cerstore = nullptr;
    }
    if (lib_crlstore) {
        delete lib_crlstore;
        lib_crlstore = nullptr;
    }
}


}   //  end namespace UapkiNS
