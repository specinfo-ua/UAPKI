/*
 * Copyright 2021 The UAPKI Project Authors.
 * Copyright 2004 Lev Walkin <vlm@lionet.info>. All rights reserved.
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

#define FILE_MARKER "uapkif/asn1/xer_encoder.c"

#include "asn_internal.h"
#include <stdio.h>
#include <errno.h>

/*
 * The XER encoder of any type. May be invoked by the application.
 */
asn_enc_rval_t
xer_encode(asn_TYPE_descriptor_t *td, void *sptr,
        enum xer_encoder_flags_e xer_flags,
        asn_app_consume_bytes_f *cb, void *app_key)
{
    asn_enc_rval_t er, tmper;
    const char *mname;
    size_t mlen;
    int xcan = (xer_flags & XER_F_CANONICAL) ? 1 : 2;

    if (!td || !sptr) {
        goto cb_failed;
    }

    mname = td->xml_tag;
    mlen = strlen(mname);

    ASN__CALLBACK3("<", 1, mname, mlen, ">", 1);

    tmper = td->xer_encoder(td, sptr, 1, xer_flags, cb, app_key);
    if (tmper.encoded == -1) {
        return tmper;
    }

    ASN__CALLBACK3("</", 2, mname, mlen, ">\n", xcan);

    er.encoded = 4 + xcan + (2 * mlen) + tmper.encoded;

    ASN__ENCODED_OK(er);
cb_failed:
    ASN__ENCODE_FAILED;
}

/*
 * This is a helper function for xer_fprint, which directs all incoming data
 * into the provided file descriptor.
 */
static int
xer__print2fp(const void *buffer, size_t size, void *app_key)
{
    FILE *stream = (FILE *)app_key;

    if (fwrite(buffer, 1, size, stream) != size) {
        return -1;
    }

    return 0;
}

int
xer_fprint(FILE *stream, asn_TYPE_descriptor_t *td, void *sptr)
{
    asn_enc_rval_t er;

    if (!stream) {
        stream = stdout;
    }
    if (!td || !sptr) {
        return -1;
    }

    er = xer_encode(td, sptr, XER_F_BASIC, xer__print2fp, stream);
    if (er.encoded == -1) {
        return -1;
    }

    return fflush(stream);
}


