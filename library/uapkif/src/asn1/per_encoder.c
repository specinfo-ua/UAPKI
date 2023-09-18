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

#define FILE_MARKER "uapkif/asn1/per_encoder.c"

#include "asn_application.h"
#include "asn_internal.h"
#include "per_encoder.h"

static asn_enc_rval_t uper_encode_internal(asn_TYPE_descriptor_t *td, asn_per_constraints_t *, void *sptr,
        asn_app_consume_bytes_f *cb, void *app_key);

asn_enc_rval_t
uper_encode(asn_TYPE_descriptor_t *td, void *sptr, asn_app_consume_bytes_f *cb, void *app_key)
{
    return uper_encode_internal(td, 0, sptr, cb, app_key);
}

/*
 * Argument type and callback necessary for uper_encode_to_buffer().
 */
typedef struct enc_to_buf_arg {
    void *buffer;
    size_t left;
} enc_to_buf_arg;
static int encode_to_buffer_cb(const void *buffer, size_t size, void *key)
{
    enc_to_buf_arg *arg = (enc_to_buf_arg *)key;

    if (arg->left < size) {
        return -1;    /* Data exceeds the available buffer size */
    }

    memcpy(arg->buffer, buffer, size);
    arg->buffer = ((char *)arg->buffer) + size;
    arg->left -= size;

    return 0;
}

asn_enc_rval_t
uper_encode_to_buffer(asn_TYPE_descriptor_t *td, void *sptr, void *buffer, size_t buffer_size)
{
    enc_to_buf_arg key;

    key.buffer = buffer;
    key.left = buffer_size;

    if (td) {
        ASN_DEBUG("Encoding \"%s\" using UNALIGNED PER", td->name);
    }

    return uper_encode_internal(td, 0, sptr, encode_to_buffer_cb, &key);
}

typedef struct enc_dyn_arg {
    void *buffer;
    size_t length;
    size_t allocated;
} enc_dyn_arg;
static int
encode_dyn_cb(const void *buffer, size_t size, void *key)
{
    enc_dyn_arg *arg = key;
    if (arg->length + size >= arg->allocated) {
        void *p;
        arg->allocated = arg->allocated ? (arg->allocated << 2) : size;
        p = REALLOC(arg->buffer, arg->allocated);
        if (!p) {
            FREEMEM(arg->buffer);
            memset(arg, 0, sizeof(*arg));
            return -1;
        }
        arg->buffer = p;
    }
    memcpy(((char *)arg->buffer) + arg->length, buffer, size);
    arg->length += size;
    return 0;
}

ssize_t
uper_encode_to_new_buffer(asn_TYPE_descriptor_t *td, asn_per_constraints_t *constraints, void *sptr, void **buffer_r)
{
    asn_enc_rval_t er;
    enc_dyn_arg key;

    memset(&key, 0, sizeof(key));

    er = uper_encode_internal(td, constraints, sptr, encode_dyn_cb, &key);
    switch (er.encoded) {
    case -1:
        FREEMEM(key.buffer);
        return -1;
    case 0:
        FREEMEM(key.buffer);
        key.buffer = MALLOC(1);
        if (key.buffer) {
            *(char *)key.buffer = '\0';
            *buffer_r = key.buffer;
            return 1;
        } else {
            return -1;
        }
    default:
        *buffer_r = key.buffer;
        ASN_DEBUG("Complete encoded in %ld bits", (long)er.encoded);
        return ((er.encoded + 7) >> 3);
    }
}

/*
 * Internally useful functions.
 */

/* Flush partially filled buffer */
static int
_uper_encode_flush_outp(asn_per_outp_t *po)
{
    uint8_t *buf;

    if (po->nboff == 0 && po->buffer == po->tmpspace) {
        return 0;
    }

    buf = po->buffer + (po->nboff >> 3);
    /* Make sure we account for the last, partially filled */
    if (po->nboff & 0x07) {
        buf[0] &= 0xff << (8 - (po->nboff & 0x07));
        buf++;
    }

    return po->outper(po->tmpspace, buf - po->tmpspace, po->op_key);
}

static asn_enc_rval_t
uper_encode_internal(asn_TYPE_descriptor_t *td, asn_per_constraints_t *constraints, void *sptr,
        asn_app_consume_bytes_f *cb, void *app_key)
{
    asn_per_outp_t po;
    asn_enc_rval_t er;

    /*
     * Invoke type-specific encoder.
     */
    if (!td || !td->uper_encoder) {
        ASN__ENCODE_FAILED;    /* PER is not compiled in */
    }

    po.buffer = po.tmpspace;
    po.nboff = 0;
    po.nbits = 8 * sizeof(po.tmpspace);
    po.outper = cb;
    po.op_key = app_key;
    po.flushed_bytes = 0;

    er = td->uper_encoder(td, constraints, sptr, &po);
    if (er.encoded != -1) {
        size_t bits_to_flush;

        bits_to_flush = ((po.buffer - po.tmpspace) << 3) + po.nboff;

        /* Set number of bits encoded to a firm value */
        er.encoded = (po.flushed_bytes << 3) + bits_to_flush;

        if (_uper_encode_flush_outp(&po)) {
            ASN__ENCODE_FAILED;
        }
    }

    return er;
}


