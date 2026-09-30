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

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JSON names, adapters, requests, enums and messages (without the native library)
 */
class JsonTest {
    @Test
    void requestsAreEscaped() {
        String req = Json.request("CHANGE_PASSWORD", p -> p.name("newPassword").value("a\"b\\c</ї>"));
        assertEquals("{\"method\":\"CHANGE_PASSWORD\",\"parameters\":{\"newPassword\":\"a\\\"b\\\\c</ї>\"}}", req);
        assertEquals("{\"method\":\"VERSION\"}", Json.request("VERSION"));
        assertEquals("{\"method\":\"LIST_CRLS\",\"parameters\":{\"pageSize\":null}}",
                Json.request("LIST_CRLS", p -> p.name("pageSize").value((Integer) null)));
    }

    @Test
    void configNamesAndNulls() {
        Config config = new Config()
                .setCmProviders(new CmProvidersParams().setDir("C:\\dir\\").setAllowedProviders(List.of(new CmProviderParams("cm-pkcs12"))))
                .setTsp(new TspParams().setUrl(List.of("http://tsp")))
                .setOffline(true);
        assertEquals("{\"method\":\"INIT\",\"parameters\":{\"cmProviders\":{\"dir\":\"C:\\\\dir\\\\\",\"allowedProviders\":[{\"lib\":\"cm-pkcs12\"}]},"
                + "\"tsp\":{\"url\":\"http://tsp\"},\"offline\":true}}", Json.requestObject("INIT", config));

        Config parsed = Json.fromJson("{\"tsp\":{\"url\":[\"a\",\"b\"]},\"validationByCrl\":false}", Config.class);
        assertEquals(List.of("a", "b"), parsed.getTsp().getUrl());
        assertEquals(Boolean.FALSE, parsed.getValidationByCrl());
        assertTrue(Json.GSON.toJson(parsed.getTsp()).contains("\"url\":[\"a\",\"b\"]"));
    }

    @Test
    void bytesAreBase64() {
        String json = Json.GSON.toJson(new AddSignature().setBytes(new byte[] { 1, 2, 3 }).setIsSignerInfo(true));
        assertEquals("{\"bytes\":\"AQID\",\"isSignerInfo\":true}", json);
        assertArrayEquals(new byte[] { 1, 2, 3 }, Json.fromJson(json, AddSignature.class).getBytes());
    }

    @Test
    void responses() {
        Json.Response<CertChainInfo> r = Json.parseResponse(
                "{\"errorCode\":0,\"method\":\"X\",\"result\":{\"CN\":\"Name\",\"expired\":true,\"validity\":{\"notBefore\":\"2024-01-02 03:04:05\",\"notAfter\":\"2025-01-02 03:04\"}}}",
                CertChainInfo.class);
        assertEquals("Name", r.result.cn());
        assertTrue(r.result.expired());
        assertEquals("", r.result.subjectCertId());
        assertEquals(Instant.parse("2024-01-02T03:04:05Z"), r.result.validity().notBefore());
        assertEquals(Instant.parse("2025-01-02T03:04:00Z"), r.result.validity().notAfter());

        DistinguishedName dn = Json.fromJson("{\"C\":\"UA\",\"SERIALNUMBER\":\"TINUA-1\",\"CN\":\"Test\"}", DistinguishedName.class);
        assertEquals("CN=Test; SERIALNUMBER=TINUA-1; C=UA", dn.asString());

        ValidateByOcspInfo byKeyId = Json.fromJson("{\"responderId\":\"0102\",\"NextUpdate\":\"2024-01-01 00:00:00\"}", ValidateByOcspInfo.class);
        assertEquals("0102", byKeyId.responderId().idByKeyId());
        assertEquals(Instant.parse("2024-01-01T00:00:00Z"), byKeyId.nextUpdate());
        ValidateByOcspInfo byName = Json.fromJson("{\"responderId\":{\"CN\":\"OCSP\"}}", ValidateByOcspInfo.class);
        assertEquals("OCSP", byName.responderId().idByName().cn());
        assertNull(byName.responderId().idByKeyId());
        assertEquals("{\"CN\":\"OCSP\"}", Json.GSON.toJson(byName.responderId()));

        UapkiException e = assertThrows(UapkiException.class, () -> Json.parseResponse("not json{", CertChainInfo.class));
        assertEquals(0x2001, e.getErrorCode());
    }

    @Test
    void enums() {
        assertEquals("1.2.804.2.1.1.1.1.3.1.1", SignAlgo.DSTU4145_GOST34311.oid());
        assertEquals(SignAlgo.DSTU4145_KUPYNA256, SignAlgo.fromOid("1.2.804.2.1.1.1.1.3.6.1.1"));
        assertEquals(SignAlgo.UNSUPPORTED, SignAlgo.fromOid("1.2.3"));
        assertEquals(KeyAlgo.DSTU4145, KeyAlgo.fromOid("1.2.804.2.1.1.1.1.3.1.1"));
        assertEquals(KeyParameter.M257_PB, KeyParameter.fromOid("1.2.804.2.1.1.1.1.3.1.1.2.6"));
        assertEquals(KeyParameter.M257_PB, KeyParameter.fromDer(Util.fromHex("060D2A862402010101010301010206"), KeyAlgo.DSTU4145));
        assertEquals(KeyParameter.P256, KeyParameter.fromDer(Util.fromHex("06082A8648CE3D030107"), KeyAlgo.ECDSA));
        assertEquals(HashAlgo.SHA3_256, HashAlgo.fromOid("2.16.840.1.101.3.4.2.8"));
        assertThrows(UapkiException.class, () -> KeyParameter.fromOid("1.2.3"));
        assertThrows(UapkiException.class, SignAlgo.UNSUPPORTED::oid);
        assertEquals("CAdES-BES", SignatureFormat.CADES_BES.value());
        assertEquals("CAdES-XL", SignatureFormat.CADES_LT.value());
        assertEquals("[[CADES_LT]]", SignatureFormat.CADES_LT.displayName());
        assertTrue(SignAlgo.DSTU4145_GOST34311.displayName().contains("34.311"));
        assertEquals("", KeyUsage.ANY.displayName());
    }

    @Test
    void exceptionMessages() {
        assertEquals("Помилка криптобібліотеки. Метод не дозволено (наприклад, для спільної пам'яті сесій)", new UapkiException(0x1017).getMessage());
        assertEquals("Помилка криптобібліотеки. Неправильна сесія (сесію звільнено)", new UapkiException(0x101D).getMessage());
        assertEquals("Помилка криптобібліотеки. Код помилки 12AB", new UapkiException(0x12AB).getMessage());
        assertEquals(0x101E, new UapkiException(0x101E).getErrorCode());
        assertEquals(0, new UapkiException("x").getErrorCode());
    }

    @Test
    void certKeyUsage() {
        CertKeyUsage ku = CertKeyUsage.fromInt(0x3);
        assertTrue(ku.digitalSignature() && ku.contentCommitment());
        assertEquals(3, ku.asInt());
        assertEquals("", CertKeyUsage.NONE.asString());
    }
}
