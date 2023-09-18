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

#define FILE_MARKER "uapkif/asn1/asn_sequence_of.c"

#include "asn_internal.h"
#include "asn_SEQUENCE_OF.h"

typedef A_SEQUENCE_OF(void) asn_sequence;

void
asn_sequence_del(void *asn_sequence_of_x, int number, int _do_free)
{
    asn_sequence *as = (asn_sequence *)asn_sequence_of_x;

    if (as) {
        void *ptr;
        int n;

        if (number < 0 || number >= as->count) {
            return;    /* Nothing to delete */
        }

        if (_do_free && as->free) {
            ptr = as->array[number];
        } else {
            ptr = 0;
        }

        /*
         * Shift all elements to the left to hide the gap.
         */
        --as->count;
        for (n = number; n < as->count; n++) {
            as->array[n] = as->array[n + 1];
        }

        /*
         * Invoke the third-party function only when the state
         * of the parent structure is consistent.
         */
        if (ptr) {
            as->free(ptr);
        }
    }
}


