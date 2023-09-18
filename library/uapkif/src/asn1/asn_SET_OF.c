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

#define FILE_MARKER "uapkif/asn1/asn_set_of.c"

#include "asn_internal.h"
#include "asn_SET_OF.h"
#include <errno.h>

/*
 * Add another element into the set.
 */
int
asn_set_add(void *asn_set_of_x, void *ptr)
{
    asn_anonymous_set_ *as = _A_SET_FROM_VOID(asn_set_of_x);

    if (as == 0 || ptr == 0) {
        errno = EINVAL;        /* Invalid arguments */
        ERROR_CREATE(RET_ASN1_ERROR);
        return -1;
    }

    /*
     * Make sure there's enough space to insert an element.
     */
    if (as->count == as->size) {
        int _newsize = as->size ? (as->size << 1) : 4;
        void *_new_arr;
        _new_arr = REALLOC(as->array, _newsize * sizeof(as->array[0]));
        if (_new_arr) {
            as->array = (void **)_new_arr;
            as->size = _newsize;
        } else {
            /* ENOMEM */
            ERROR_CREATE(RET_ASN1_ERROR);
            return -1;
        }
    }

    as->array[as->count++] = ptr;

    return 0;
}

void
asn_set_del(void *asn_set_of_x, int number, int _do_free)
{
    asn_anonymous_set_ *as = _A_SET_FROM_VOID(asn_set_of_x);

    if (as) {
        void *ptr;
        if (number < 0 || number >= as->count) {
            return;
        }

        if (_do_free && as->free) {
            ptr = as->array[number];
        } else {
            ptr = 0;
        }

        as->array[number] = as->array[--as->count];

        /*
         * Invoke the third-party function only when the state
         * of the parent structure is consistent.
         */
        if (ptr) {
            as->free(ptr);
        }
    }
}

/*
 * Free the contents of the set, do not free the set itself.
 */
void
asn_set_empty(void *asn_set_of_x)
{
    asn_anonymous_set_ *as = _A_SET_FROM_VOID(asn_set_of_x);

    if (as) {
        if (as->array) {
            if (as->free) {
                while (as->count--) {
                    as->free(as->array[as->count]);
                }
            }
            FREEMEM(as->array);
            as->array = 0;
        }
        as->count = 0;
        as->size = 0;
    }

}


