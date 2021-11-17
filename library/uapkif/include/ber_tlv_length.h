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

#ifndef    _BER_TLV_LENGTH_H_
#define    _BER_TLV_LENGTH_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef ssize_t ber_tlv_len_t;

/*
 * This function tries to fetch the length of the BER TLV value and place it
 * in *len_r.
 * RETURN VALUES:
 *     0:    More data expected than bufptr contains.
 *    -1:    Fatal error deciphering length.
 *    >0:    Number of bytes used from bufptr.
 * On return with >0, len_r is constrained as -1..MAX, where -1 mean
 * that the value is of indefinite length.
 */
UAPKIF_EXPORT ssize_t ber_fetch_length(int _is_constructed, const void *bufptr, size_t size,
        ber_tlv_len_t *len_r);

/*
 * This function expects bufptr to be positioned over L in TLV.
 * It returns number of bytes occupied by L and V together, suitable
 * for skipping. The function properly handles indefinite length.
 * RETURN VALUES:
 *     Standard {-1,0,>0} convention.
 */
UAPKIF_EXPORT ssize_t ber_skip_length(
        struct asn_codec_ctx_s *opt_codec_ctx,    /* optional context */
        int _is_constructed, const void *bufptr, size_t size);

/*
 * This function serializes the length (L from TLV) in DER format.
 * It always returns number of bytes necessary to represent the length,
 * it is a caller's responsibility to check the return value
 * against the supplied buffer's size.
 */
UAPKIF_EXPORT size_t der_tlv_length_serialize(ber_tlv_len_t len, void *bufptr, size_t size);

#ifdef __cplusplus
}
#endif

#endif
