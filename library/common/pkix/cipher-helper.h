/*
 * Copyright (c) 2023, The UAPKI Project Authors.
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

//  Last update: 2023-02-01

#ifndef UAPKI_NS_CIPHER_HELPER_H
#define UAPKI_NS_CIPHER_HELPER_H


#include "uapki-ns.h"
#include "oids.h"
#include "uapkic.h"
#include "uapkif.h"


namespace UapkiNS {

    namespace Cipher {

        enum class Direction {
            ENCRYPT = 0,
            DECRYPT = 1
        };  //  end enum Direction

        class Dstu7624 {
        public:
            static const size_t SIZE_IV = 32;

            static int cryptData (const UapkiNS::AlgorithmIdentifier& algoId, const ByteArray* baKey,
                                const Direction direction, const ByteArray* baDataIn, ByteArray** baDataOut);
            static int decodeParams (const ByteArray* baEncoded, ByteArray** baIV);
            static int encodeParams (const ByteArray* baIV, ByteArray** baEncoded);
            static int generateKey (const size_t keyLen, ByteArray** baKey);
            static int generateIV (ByteArray** baIV);

        };  //  end class Dstu7624

        class Gost28147 {
        public:
            static const size_t SIZE_IV = 8;

            static int cryptData (const UapkiNS::AlgorithmIdentifier& algoId, const ByteArray* baKey,
                                const Direction direction, const ByteArray* baDataIn, ByteArray** baDataOut);
            static int decodeParams (const ByteArray* baEncoded, ByteArray** baIV, ByteArray** baDKE, const bool compressed = true);
            static int encodeParams (const ByteArray* baIV, const ByteArray* baDKE, ByteArray** baEncoded);
            static int generateKey (ByteArray** baKey);
            static int generateIV (ByteArray** baIV);
            static int getDKE (const Gost28147SboxId sboxId, ByteArray** baCompressedDKE);

        };  //  end class Gost28147

    }   //  end namespace Cipher

}   //  end namespace UapkiNS

#endif
