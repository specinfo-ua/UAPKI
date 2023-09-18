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

#define FILE_MARKER "uapkif/asn1/ANY.c"

#include <errno.h>

#include "asn_internal.h"
#include "ANY.h"
#include "asn1-errors.h"

static asn_OCTET_STRING_specifics_t asn_DEF_ANY_specs = {
    sizeof(ANY_t),
    offsetof(ANY_t, _asn_ctx),
    ASN_OSUBV_ANY
};
asn_TYPE_descriptor_t ANY_desc = {
    "ANY",
    "ANY",
    OCTET_STRING_free,
    OCTET_STRING_print,
    asn_generic_no_constraint,
    OCTET_STRING_decode_ber,
    OCTET_STRING_encode_der,
    OCTET_STRING_decode_xer_hex,
    ANY_encode_xer,
    0, 0,
    0, /* Use generic outmost tag fetcher */
    0, 0, 0, 0,
    0,    /* No PER visible constraints */
    0, 0,    /* No members */
    &asn_DEF_ANY_specs,
};

asn_TYPE_descriptor_t *get_ANY_desc(void)
{
    return &ANY_desc;
}

asn_enc_rval_t
ANY_encode_xer(asn_TYPE_descriptor_t *td, void *sptr,
        int ilevel, enum xer_encoder_flags_e flags,
        asn_app_consume_bytes_f *cb, void *app_key)
{

    if (flags & XER_F_CANONICAL) {
        /*
         * Canonical XER-encoding of ANY type is not supported.
         */
        ASN__ENCODE_FAILED;
    }

    /* Dump as binary */
    return OCTET_STRING_encode_xer(td, sptr, ilevel, flags, cb, app_key);
}

struct _callback_arg {
    uint8_t *buffer;
    size_t offset;
    size_t size;
};

static int ANY__consume_bytes(const void *buffer, size_t size, void *key);

int
ANY_fromType(ANY_t *st, asn_TYPE_descriptor_t *td, void *sptr)
{
    struct _callback_arg arg;
    asn_enc_rval_t erval;
    int ret = RET_OK;

    arg.offset = arg.size = 0;
    arg.buffer = 0;

    CHECK_PARAM(st != NULL);
    CHECK_PARAM(td != NULL);

    if (!sptr) {
        if (st->buf) {
            FREEMEM(st->buf);
        }
        st->size = 0;
        goto cleanup;
    }

    erval = der_encode(td, sptr, ANY__consume_bytes, &arg);
    if (erval.encoded == -1) {
        SET_ERROR(RET_ASN1_DECODE_ERROR);
    }
    ASSERT((size_t)erval.encoded == arg.offset);

cleanup:
    if (st) {
        if (st->buf) {
            FREEMEM(st->buf);
        }
        st->buf = arg.buffer;
        st->size = (int)arg.offset;
    }

    return ret;
}

ANY_t *
ANY_new_fromType(asn_TYPE_descriptor_t *td, void *sptr)
{
    ANY_t tmp;
    ANY_t *st = NULL;
    int ret = RET_OK;

    memset(&tmp, 0, sizeof(tmp));

    CHECK_PARAM(sptr != NULL);
    CHECK_PARAM(td != NULL);

    if (ANY_fromType(&tmp, td, sptr)) {
        return 0;
    }

    CALLOC_CHECKED(st, sizeof(ANY_t));

cleanup:
    if (ret != RET_OK) {
        FREEMEM(tmp.buf);
        st = NULL;
    } else {
        *st = tmp;
    }

    return st;
}

int
ANY_to_type(const ANY_t *st, asn_TYPE_descriptor_t *td, void **struct_ptr)
{
    asn_dec_rval_t rval;
    void *newst = 0;
    int ret = RET_OK;

    CHECK_PARAM(st != NULL);
    CHECK_PARAM(td != NULL);
    CHECK_PARAM(struct_ptr != NULL);
    if (st->buf == 0) {
        /* Nothing to convert, make it empty. */
        *struct_ptr = (void *)0;
        goto cleanup;
    }
    rval = ber_decode(0, td, (void **)&newst, st->buf, st->size);
    if (rval.code == RC_OK) {
        *struct_ptr = newst;
        goto cleanup;
    } else {
        /* Remove possibly partially decoded data. */
        td->free_struct(td, newst, 0);
        SET_ERROR(RET_ASN1_DECODE_ERROR);
    }
cleanup:
    return ret;
}

static int ANY__consume_bytes(const void *buffer, size_t size, void *key)
{
    struct _callback_arg *arg = (struct _callback_arg *)key;
    int ret = RET_OK;

    if ((arg->offset + size) >= arg->size) {
        size_t nsize = (arg->size ? arg->size << 2 : 16) + size;
        void *p = NULL;
        REALLOC_CHECKED(arg->buffer, nsize, p);
        arg->buffer = (uint8_t *)p;
        arg->size = nsize;
    }

    memcpy(arg->buffer + arg->offset, buffer, size);
    arg->offset += size;
    ASSERT(arg->offset < arg->size);
cleanup:
    return ret;
}


