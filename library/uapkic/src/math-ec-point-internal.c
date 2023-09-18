/*
 * Copyright 2021 The UAPKI Project Authors.
 * Copyright 2016 PrivatBank IT <acsk@privatbank.ua>
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

#define FILE_MARKER "uapkic/math-ec-point-internal.c"

#include "math-ec-point-internal.h"
#include "macros-internal.h"

ECPoint *ec_point_alloc(size_t len)
{
    int ret = RET_OK;
    ECPoint *p = NULL;

    CALLOC_CHECKED(p, sizeof(ECPoint));

    CHECK_NOT_NULL(p->x = wa_alloc_with_zero(len));
    CHECK_NOT_NULL(p->y = wa_alloc_with_zero(len));
    CHECK_NOT_NULL(p->z = wa_alloc_with_zero(len));

    return p;

cleanup:

    ec_point_free(p);

    return NULL;
}

static void ec_point_init(ECPoint *p, const WordArray *px, const WordArray *py, const WordArray *pz)
{
    int ret = RET_OK;

    if (p != NULL) {
        CHECK_NOT_NULL(p->x = wa_copy_with_alloc(px));
        CHECK_NOT_NULL(p->y = wa_copy_with_alloc(py));
        p->z = (pz != NULL) ? wa_copy_with_alloc(pz) : wa_alloc_with_one(px->len);
        CHECK_NOT_NULL(p->z);
        return;
    }
cleanup:
    return;
}

ECPoint *ec_point_aff_alloc(const WordArray *px, const WordArray *py)
{
    ECPoint *p = NULL;
    int ret = RET_OK;

    if (px != NULL && py != NULL) {
        CALLOC_CHECKED(p, sizeof(ECPoint));
        ec_point_init(p, px, py, NULL);
    }

cleanup:

    return p;
}

ECPoint *ec_point_proj_alloc(const WordArray *px, const WordArray *py, const WordArray *pz)
{
    ECPoint *p = NULL;
    int ret = RET_OK;

    if (px != NULL && py != NULL && pz != NULL) {
        CALLOC_CHECKED(p, sizeof(ECPoint));
        ec_point_init(p, px, py, pz);
    }

cleanup:

    return p;
}

void ec_point_zero(ECPoint *p)
{
    if (p != NULL) {
        wa_zero(p->x);
        wa_zero(p->y);
        wa_one(p->z);
    }
}

void ec_point_copy(const ECPoint *a, ECPoint *out)
{
    int ret = RET_OK;

    if (a != NULL && out != NULL) {
        DO(wa_copy(a->x, out->x));
        DO(wa_copy(a->y, out->y));
        DO(wa_copy(a->z, out->z));
    }

cleanup:

    return;
}

ECPoint *ec_point_copy_with_alloc(const ECPoint *a)
{
    ECPoint *out = NULL;
    int ret = RET_OK;

    CALLOC_CHECKED(out, sizeof(ECPoint));

    CHECK_NOT_NULL(out->x = wa_copy_with_alloc(a->x));
    CHECK_NOT_NULL(out->y = wa_copy_with_alloc(a->y));
    CHECK_NOT_NULL(out->z = wa_copy_with_alloc(a->z));

    return out;

cleanup:

    ec_point_free(out);

    return NULL;
}

void ec_point_free(ECPoint *p)
{
    if (p != NULL) {
        wa_free(p->x);
        wa_free(p->y);
        wa_free(p->z);
        free(p);
    }
}
