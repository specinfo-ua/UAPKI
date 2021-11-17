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

#include "math-ec-precomp-internal.h"
#include "math-int-internal.h"
#include "macros-internal.h"

#undef FILE_MARKER
#define FILE_MARKER "uapkic/math-ec-precomp-internal.c"

EcPrecomp *ec_copy_precomp_with_alloc(EcPrecomp *precomp)
{
    int i, ret = RET_OK;
    EcPrecomp *precomp_copy = NULL;

    if (precomp == NULL) {
        return NULL;
    }

    CALLOC_CHECKED(precomp_copy, sizeof(EcPrecomp));
    precomp_copy->type = precomp->type;
    switch (precomp->type) {
        case EC_PRECOMP_TYPE_COMB:
        CALLOC_CHECKED(precomp_copy->ctx.comb, sizeof(EcPrecompComb));
            precomp_copy->ctx.comb->comb_width = precomp->ctx.comb->comb_width;

            if (precomp->ctx.comb->precomp != NULL) {
                int comb_len = (1 << precomp->ctx.comb->comb_width) - 1;

                CALLOC_CHECKED(precomp_copy->ctx.comb->precomp, comb_len * sizeof(ECPoint *));

                for (i = 0; i < comb_len; i++) {
                    CHECK_NOT_NULL(precomp_copy->ctx.comb->precomp[i] = ec_point_copy_with_alloc(precomp->ctx.comb->precomp[i]));
                }
            }
            break;
        case EC_PRECOMP_TYPE_WIN:
        CALLOC_CHECKED(precomp_copy->ctx.win, sizeof(EcPrecompWin));

            precomp_copy->ctx.win->win_width = precomp->ctx.win->win_width;
            precomp_copy->ctx.win->precomp_len = precomp->ctx.win->precomp_len;

            if (precomp->ctx.win->precomp != NULL) {
                CALLOC_CHECKED(precomp_copy->ctx.win->precomp, precomp->ctx.win->precomp_len * sizeof(ECPoint *));

                for (i = 0; i < precomp->ctx.win->precomp_len; i++) {
                    CHECK_NOT_NULL(precomp_copy->ctx.win->precomp[i] = ec_point_copy_with_alloc(precomp->ctx.win->precomp[i]));
                }
            }
            break;
        default:
            SET_ERROR(RET_INVALID_CTX);
    }

    return precomp_copy;

cleanup:

    ec_precomp_free(precomp_copy);

    return NULL;
}

void ec_precomp_free(EcPrecomp *precomp)
{
    int i;

    if (precomp != NULL) {
        if (precomp->type == EC_PRECOMP_TYPE_COMB) {
            if (precomp->ctx.comb->precomp != NULL) {
                for (i = 0; i < (1 << precomp->ctx.comb->comb_width) - 1; i++) {
                    ec_point_free(precomp->ctx.comb->precomp[i]);
                }
                free(precomp->ctx.comb->precomp);
            }
            free(precomp->ctx.comb);
        } else if (precomp->type == EC_PRECOMP_TYPE_WIN) {
            if (precomp->ctx.win->precomp != NULL) {
                for (i = 0; i < precomp->ctx.win->precomp_len; i++) {
                    ec_point_free(precomp->ctx.win->precomp[i]);
                }
                free(precomp->ctx.win->precomp);
            }
            free(precomp->ctx.win);
        }
        free(precomp);
    }
}
