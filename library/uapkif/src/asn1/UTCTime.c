/*
 * Copyright (c) 2023, The UAPKI Project Authors.
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

#include "asn_internal.h"
#include "asn1-utils.h"
#include "UTCTime.h"
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>

#undef FILE_MARKER
#define FILE_MARKER "asn1/UTCTime.c"

#ifdef    __CYGWIN__
#include "/usr/include/time.h"
#else
#include <time.h>
#endif    /* __CYGWIN__ */

#ifndef ASN___INTERNAL_TEST_MODE

/*
 * UTCTime basic type description.
 */
static const ber_tlv_tag_t asn_DEF_UTCTime_tags[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (23 << 2)),    /* [UNIVERSAL 23] IMPLICIT ...*/
    (ASN_TAG_CLASS_UNIVERSAL | (26 << 2)),  /* [UNIVERSAL 26] IMPLICIT ...*/
    (ASN_TAG_CLASS_UNIVERSAL | (4 << 2))    /* ... OCTET STRING */
};
static asn_per_constraints_t asn_DEF_UTCTime_constraints = {
    { APC_CONSTRAINED, 7, 7, 0x20, 0x7e },  /* Value */
    { APC_SEMI_CONSTRAINED, -1, -1, 0, 0 }, /* Size */
    0, 0
};
asn_TYPE_descriptor_t UTCTime_desc = {
    "UTCTime",
    "UTCTime",
    OCTET_STRING_free,
    UTCTime_print,
    UTCTime_constraint,
    OCTET_STRING_decode_ber,    /* Implemented in terms of OCTET STRING */
    OCTET_STRING_encode_der,    /* Implemented in terms of OCTET STRING */
    OCTET_STRING_decode_xer_utf8,
    UTCTime_encode_xer,
    OCTET_STRING_decode_uper,
    OCTET_STRING_encode_uper,
    0, /* Use generic outmost tag fetcher */
    asn_DEF_UTCTime_tags,
    sizeof(asn_DEF_UTCTime_tags)
    / sizeof(asn_DEF_UTCTime_tags[0]) - 2,
    asn_DEF_UTCTime_tags,
    sizeof(asn_DEF_UTCTime_tags)
    / sizeof(asn_DEF_UTCTime_tags[0]),
    &asn_DEF_UTCTime_constraints,
    0, 0,    /* No members */
    0    /* No specifics */
};

asn_TYPE_descriptor_t* get_UTCTime_desc(void)
{
    return &UTCTime_desc;
}

#endif    /* ASN___INTERNAL_TEST_MODE */

/*
 * Check that the time looks like the time.
 */
int
UTCTime_constraint(asn_TYPE_descriptor_t *td, const void *sptr,
        asn_app_constraint_failed_f *ctfailcb, void *app_key)
{
    const UTCTime_t *st = (const UTCTime_t *)sptr;

    if ((st->size != 13) || st->buf[12] != 'Z') {
        ASN__CTFAIL(app_key, td, sptr,
                "%s: Invalid time format: %s (%s:%d)",
                td->name, strerror(errno), FILE_MARKER, __LINE__);
        return -1;
    }

    return 0;
}

#ifndef    ASN___INTERNAL_TEST_MODE

asn_enc_rval_t
UTCTime_encode_xer(asn_TYPE_descriptor_t *td, void *sptr,
        int ilevel, enum xer_encoder_flags_e flags,
        asn_app_consume_bytes_f *cb, void *app_key)
{
    return OCTET_STRING_encode_xer_utf8(td, sptr, ilevel, flags, cb, app_key);
}

#endif    /* ASN___INTERNAL_TEST_MODE */

int
UTCTime_print(asn_TYPE_descriptor_t *td, const void *sptr, int ilevel,
        asn_app_consume_bytes_f *cb, void *app_key)
{
    const UTCTime_t *st = (const UTCTime_t *)sptr;

    (void)td;    /* Unused argument */
    (void)ilevel;    /* Unused argument */

    if (st && st->buf) {
        char buf[32];
        int ret;

        if (st->size != 13) {
            return (cb("<bad-value>", 11, app_key) < 0) ? -1 : 0;
        }

        ret = snprintf(buf, sizeof(buf), "%.*s", st->size, st->buf);
        ASSERT(ret > 0 && ret < (int)sizeof(buf));
        return (cb(buf, ret, app_key) < 0) ? -1 : 0;
    } else {
        return (cb("<absent>", 8, app_key) < 0) ? -1 : 0;
    }
}
