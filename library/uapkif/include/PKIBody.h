/*
 * Copyright (c) 2023, The UAPKI Project Authors.
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
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

#ifndef	_PKI_BODY_H_
#define	_PKI_BODY_H_


#include "asn_application.h"

/* Including external dependencies */
#include "ANY.h"
#include "constr_CHOICE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum PKIBody_PR {
    PKIBody_PR_NOTHING,	/* No components present */
    PKIBody_PR_ir,
    PKIBody_PR_ip,
    PKIBody_PR_cr,
    PKIBody_PR_cp,
    PKIBody_PR_p10cr,
    PKIBody_PR_popdecc,
    PKIBody_PR_popdecr,
    PKIBody_PR_kur,
    PKIBody_PR_kup,
    PKIBody_PR_krr,
    PKIBody_PR_krp,
    PKIBody_PR_rr,
    PKIBody_PR_rp,
    PKIBody_PR_ccr,
    PKIBody_PR_ccp,
    PKIBody_PR_ckuann,
    PKIBody_PR_cann,
    PKIBody_PR_rann,
    PKIBody_PR_crlann,
    PKIBody_PR_pkiconf,
    PKIBody_PR_nested,
    PKIBody_PR_genm,
    PKIBody_PR_genp,
    PKIBody_PR_error,
    PKIBody_PR_certConf,
    PKIBody_PR_pollReq,
    PKIBody_PR_pollRep
} PKIBody_PR;

/* PKIBody */
typedef struct PKIBody {
    PKIBody_PR present;
    union PKIBody_u {
        ANY_t   ir;
        ANY_t   ip;
        ANY_t   cr;
        ANY_t   cp;
        ANY_t   p10cr;
        ANY_t   popdecc;
        ANY_t   popdecr;
        ANY_t   kur;
        ANY_t   kup;
        ANY_t   krr;
        ANY_t   krp;
        ANY_t   rr;
        ANY_t   rp;
        ANY_t   ccr;
        ANY_t   ccp;
        ANY_t   ckuann;
        ANY_t   cann;
        ANY_t   rann;
        ANY_t   crlann;
        ANY_t   pkiconf;
        ANY_t   nested;
        ANY_t   genm;
        ANY_t   genp;
        ANY_t   error;
        ANY_t   certConf;
        ANY_t   pollReq;
        ANY_t   pollRep;
    } choice;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} PKIBody_t;

/* Implementation */
extern asn_TYPE_descriptor_t PKIBody_desc;
UAPKIF_EXPORT asn_TYPE_descriptor_t* get_PKIBody_desc(void);

#ifdef __cplusplus
}
#endif

#endif
