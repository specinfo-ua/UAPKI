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
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParseException;
import com.google.gson.TypeAdapter;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;

import java.io.IOException;
import java.io.StringWriter;
import java.lang.reflect.Type;
import java.util.Base64;

/**
 * JSON: Gson (імена полів - як у .NET, null не серіалізуються, byte[] - Base64) і формування запитів через JsonWriter
 */
final class Json {
    static final Gson GSON = new GsonBuilder()
            .disableHtmlEscaping()
            .registerTypeAdapter(byte[].class, new Base64Adapter().nullSafe())
            .create();

    private Json() {
    }

    /**
     * Відповідь бібліотеки: {"errorCode":..,"method":"..","result":{..}}
     */
    static final class Response<T> {
        int errorCode;
        String method;
        T result;
    }

    @FunctionalInterface
    interface ParamsWriter {
        void write(JsonWriter writer) throws IOException;
    }

    static <T> Response<T> parseResponse(String json, Type resultType) {
        Response<T> ret;
        try {
            @SuppressWarnings("unchecked")
            TypeToken<Response<T>> token = (TypeToken<Response<T>>) TypeToken.getParameterized(Response.class, resultType);
            ret = GSON.fromJson(json, token);
        } catch (JsonParseException e) {
            throw new UapkiException(0x2001, e);
        }
        if (ret == null)
            throw new UapkiException(0x2001);
        return ret;
    }

    static <T> T fromJson(String json, Class<T> type) {
        T ret;
        try {
            ret = GSON.fromJson(json, type);
        } catch (JsonParseException e) {
            throw new UapkiException(0x2001, e);
        }
        if (ret == null)
            throw new UapkiException(0x2001);
        return ret;
    }

    /**
     * Запит без параметрів: {"method":"..."}
     */
    static String request(String method) {
        return buildRequest(method, null);
    }

    /**
     * Запит з параметрами, які записує writeParameters: {"method":"...","parameters":{...}}
     */
    static String request(String method, ParamsWriter writeParameters) {
        return buildRequest(method, writer -> {
            writer.beginObject();
            writeParameters.write(writer);
            writer.endObject();
        });
    }

    /**
     * Запит з параметрами-об'єктом, серіалізованим Gson: {"method":"...","parameters":{...}}
     */
    static String requestObject(String method, Object parameters) {
        return buildRequest(method, writer -> GSON.toJson(parameters, parameters.getClass(), writer));
    }

    private static String buildRequest(String method, ParamsWriter writeParameters) {
        StringWriter out = new StringWriter();
        try (JsonWriter writer = new JsonWriter(out)) {
            writer.setHtmlSafe(false);
            writer.setSerializeNulls(true);
            writer.beginObject();
            writer.name("method").value(method);
            if (writeParameters != null) {
                writer.name("parameters");
                writeParameters.write(writer);
            }
            writer.endObject();
        } catch (IOException e) {
            throw new IllegalStateException(e);     //  StringWriter does not throw
        }
        return out.toString();
    }

    static String base64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    /**
     * byte[] &lt;-&gt; Base64-рядок
     */
    static final class Base64Adapter extends TypeAdapter<byte[]> {
        @Override
        public void write(JsonWriter out, byte[] value) throws IOException {
            out.value(Base64.getEncoder().encodeToString(value));
        }

        @Override
        public byte[] read(JsonReader in) throws IOException {
            try {
                return Base64.getDecoder().decode(in.nextString());
            } catch (IllegalArgumentException e) {
                throw new JsonParseException("Invalid Base64 value", e);
            }
        }
    }
}
