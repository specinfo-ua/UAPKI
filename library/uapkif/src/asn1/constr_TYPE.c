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

#define FILE_MARKER "uapkif/asn1/constr_type.c"

#include "asn_internal.h"
#include "constr_TYPE.h"
#include <errno.h>

/*
 * Version of the ASN.1 infrastructure shipped with compiler.
 */
int get_asn1c_environment_version()
{
    return ASN1C_ENVIRONMENT_VERSION;
}

static asn_app_consume_bytes_f _print2fp;

/*
 * Return the outmost tag of the type.
 */
ber_tlv_tag_t
asn_TYPE_outmost_tag(const asn_TYPE_descriptor_t *type_descriptor,
        const void *struct_ptr, int tag_mode, ber_tlv_tag_t tag)
{

    if (tag_mode) {
        return tag;
    }

    if (type_descriptor->tags_count) {
        return type_descriptor->tags[0];
    }

    return type_descriptor->outmost_tag(type_descriptor, struct_ptr, 0, 0);
}

/*
 * Print the target language's structure in human readable form.
 */
int
asn_fprint(FILE *stream, asn_TYPE_descriptor_t *td, const void *struct_ptr)
{
    if (!stream) {
        stream = stdout;
    }
    if (!td || !struct_ptr) {
        errno = EINVAL;
        return -1;
    }

    /* Invoke type-specific printer */
    if (td->print_struct(td, struct_ptr, 1, _print2fp, stream)) {
        return -1;
    }

    /* Terminate the output */
    if (_print2fp("\n", 1, stream)) {
        return -1;
    }

    return fflush(stream);
}

/* Dump the data into the specified stdio stream */
static int
_print2fp(const void *buffer, size_t size, void *app_key)
{
    FILE *stream = (FILE *)app_key;

    if (fwrite(buffer, 1, size, stream) != size) {
        return -1;
    }

    return 0;
}


/*
 * Some compilers do not support variable args macros.
 * This function is a replacement of ASN_DEBUG() macro.
 */
void ASN_DEBUG_f(const char *fmt, ...);
void ASN_DEBUG_f(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}


