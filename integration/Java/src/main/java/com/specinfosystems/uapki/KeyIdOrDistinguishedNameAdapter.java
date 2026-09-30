/*
 * Copyright (c) 2026, The UAPKI Project Authors.
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

package com.specinfosystems.uapki;

import com.google.gson.Gson;
import com.google.gson.JsonParseException;
import com.google.gson.TypeAdapter;
import com.google.gson.TypeAdapterFactory;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.JsonWriter;

import java.io.IOException;

/**
 * Ідентифікатор відповідача OCSP: у JSON - рядок (ідентифікатор ключа) або об'єкт (DistinguishedName)
 */
final class KeyIdOrDistinguishedNameAdapter implements TypeAdapterFactory {
    @Override
    @SuppressWarnings("unchecked")
    public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
        if (type.getRawType() != OcspResponderIdentifier.class)
            return null;
        TypeAdapter<DistinguishedName> dnAdapter = gson.getAdapter(DistinguishedName.class);
        return (TypeAdapter<T>) new Adapter(dnAdapter);
    }

    private static final class Adapter extends TypeAdapter<OcspResponderIdentifier> {
        private final TypeAdapter<DistinguishedName> dnAdapter;

        Adapter(TypeAdapter<DistinguishedName> dnAdapter) {
            this.dnAdapter = dnAdapter;
        }

        @Override
        public OcspResponderIdentifier read(JsonReader reader) throws IOException {
            JsonToken token = reader.peek();
            if (token == JsonToken.NULL) {
                reader.nextNull();
                return null;
            }
            if (token == JsonToken.STRING)
                return new OcspResponderIdentifier(reader.nextString(), null);
            if (token == JsonToken.BEGIN_OBJECT)
                return new OcspResponderIdentifier(null, dnAdapter.read(reader));
            throw new JsonParseException("Unexpected JSON token for 'details'");
        }

        @Override
        public void write(JsonWriter writer, OcspResponderIdentifier value) throws IOException {
            if (value == null)
                writer.nullValue();
            else if (value.idByKeyId() != null)
                writer.value(value.idByKeyId());
            else if (value.idByName() != null)
                dnAdapter.write(writer, value.idByName());
            else
                writer.nullValue();
        }
    }
}
