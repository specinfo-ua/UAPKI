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

#ifndef    _XER_SUPPORT_H_
#define    _XER_SUPPORT_H_

#include "uapkif-export.h"
#include "asn_system.h"        /* Platform-specific types */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Types of data transferred to the application.
 */
typedef enum {
    PXML_TEXT,    /* Plain text between XML tags. */
    PXML_TAG,    /* A tag, starting with '<'. */
    PXML_COMMENT,    /* An XML comment, including "<!--" and "-->". */
    /*
     * The following chunk types are reported if the chunk
     * terminates the specified XML element.
     */
    PXML_TAG_END,        /* Tag ended */
    PXML_COMMENT_END    /* Comment ended */
} pxml_chunk_type_e;

/*
 * Callback function that is called by the parser when parsed data is
 * available. The _opaque is the pointer to a field containing opaque user
 * data specified in pxml_create() call. The chunk type is _type and the text
 * data is the piece of buffer identified by _bufid (as supplied to
 * pxml_feed() call) starting at offset _offset and of _size bytes size.
 * The chunk is NOT '\0'-terminated.
 */
typedef int (pxml_callback_f)(pxml_chunk_type_e _type,
        const void *_chunk_data, size_t _chunk_size, void *_key);

/*
 * Parse the given buffer as it were a chunk of XML data.
 * Invoke the specified callback each time the meaninful data is found.
 * This function returns number of bytes consumed from the bufer.
 * It will always be lesser than or equal to the specified _size.
 * The next invocation of this function must account the difference.
 */
UAPKIF_EXPORT ssize_t   pxml_parse(int *_stateContext, const void *_buf, size_t _size,
        pxml_callback_f *cb, void *_key);

#ifdef __cplusplus
}
#endif

#endif
