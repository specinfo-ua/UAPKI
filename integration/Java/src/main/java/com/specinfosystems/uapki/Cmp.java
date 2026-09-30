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

import java.io.ByteArrayOutputStream;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Клієнт для роботи з CMP-сервером ЦСК за власним протоколом (тип 13). Підтримує від 1 до 4 ідентифікаторів
 * відкритих ключів (UAKEYID)
 */
final class Cmp {
    // OID 1.2.840.113549.1.7.1  (pkcs7-data) у DER:
    private static final byte[] OID_PKCS7_DATA = {
            0x06, 0x09,
            0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x07, 0x01
    };

    private static final int RECORD_TYPE = 13;
    private static final int REQUEST_STATUS = 0;
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(10);
    private static final long TOTAL_TIMEOUT_SECONDS = 11;

    private Cmp() {
    }

    /**
     * Відповідь CMP-сервера
     *
     * @param pkcs7Chain ланцюжок сертифікатів у форматі PKCS#7 (CMS) Binary (може бути null)
     */
    record CmpResponse(int type, int status, byte[] pkcs7Chain) {
        /** Хоча б один сертифікат знайдено */
        boolean success() {
            return status == 0;
        }

        /** Жодного сертифіката не знайдено */
        boolean notFound() {
            return status == 3;
        }
    }

    /**
     * Надсилає запит на всі адреси паралельно; результат - перша непорожня відповідь або null
     * (усі запити невдалі або минув загальний час очікування 11 с)
     */
    static CompletableFuture<byte[]> cmpAsync(List<String> urls, List<String> keyIds, ProxySelector proxy) {
        if (keyIds == null || keyIds.size() < 1 || keyIds.size() > 4)
            throw new UapkiException("keyIds must be from 1 to 4");

        List<byte[]> bKeyIds = new ArrayList<>();
        for (String keyId : keyIds) {
            if (keyId.length() != 64 && keyId.length() != 40)
                throw new UapkiException("Invalid keyId length");
            StringBuilder padded = new StringBuilder(keyId);
            while (padded.length() < 64)
                padded.append('0');
            bKeyIds.add(Util.fromHex(padded.toString()));
        }

        byte[] cmpRequest = buildRequest(bKeyIds, false, false, false);

        HttpClient.Builder builder = HttpClient.newBuilder().connectTimeout(REQUEST_TIMEOUT);
        if (proxy != null)
            builder.proxy(proxy);
        HttpClient http = builder.build();

        CompletableFuture<byte[]> result = new CompletableFuture<>();
        List<CompletableFuture<byte[]>> requests = new ArrayList<>();
        AtomicInteger remaining = new AtomicInteger(urls.size());
        if (urls.isEmpty())
            result.complete(null);

        for (String url : urls) {
            CompletableFuture<byte[]> request;
            try {
                request = send(http, url, cmpRequest);
            } catch (RuntimeException e) {
                request = CompletableFuture.failedFuture(e);
            }
            requests.add(request);
            request.whenComplete((response, error) -> {
                if (error == null && response != null)
                    result.complete(response);
                else if (remaining.decrementAndGet() == 0)
                    result.complete(null);
            });
        }

        result.completeOnTimeout(null, TOTAL_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        //  The first response (or the timeout) cancels the other requests
        result.whenComplete((r, e) -> requests.forEach(it -> it.cancel(true)));
        return result;
    }

    private static CompletableFuture<byte[]> send(HttpClient http, String url, byte[] cmpRequest) {
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                .timeout(REQUEST_TIMEOUT)
                .header("Content-Type", "application/cmp-request")
                .header("Content-Transfer-Encoding", "binary")
                .POST(HttpRequest.BodyPublishers.ofByteArray(cmpRequest))
                .build();

        return http.sendAsync(request, HttpResponse.BodyHandlers.ofByteArray())
                .thenApply(response -> {
                    if (response.statusCode() < 200 || response.statusCode() > 299)
                        throw new UapkiException(0x1025);
                    return parseResponse(response.body()).pkcs7Chain();
                });
    }

    /**
     * Формує тіло HTTP-запиту (DER-кодований ASN.1)
     */
    static byte[] buildRequest(List<byte[]> keyIds, boolean chain, boolean includeAll, boolean signResponse) {
        ByteBuffer bw = ByteBuffer.allocate(4 * 3 + 32 * 4 + 4 * 3).order(ByteOrder.LITTLE_ENDIAN);

        // INT Type = 13  (4 байти, little-endian)
        bw.putInt(RECORD_TYPE);
        // INT Status = 0
        bw.putInt(REQUEST_STATUS);
        // INT Count
        bw.putInt(keyIds.size());

        // UAKEYID[4] — завжди записуємо 4 слоти; незаповнені заповнюємо нулями
        for (int i = 0; i < 4; i++) {
            if (i < keyIds.size())
                bw.put(keyIds.get(i));
            else
                bw.put(new byte[32]);
        }

        // BOOL Chain, BOOL IncludeAll, BOOL SignResponse
        bw.putInt(chain ? 1 : 0);
        bw.putInt(includeAll ? 1 : 0);
        bw.putInt(signResponse ? 1 : 0);

        byte[] payload = new byte[bw.position()];
        bw.flip();
        bw.get(payload);

        //  SEQUENCE {
        //    OID  1.2.840.113549.1.7.1
        //    [0] EXPLICIT {
        //      OCTET STRING <payload>
        //    }
        //  }
        byte[] octetString = derTlv((byte) 0x04, payload);
        byte[] contextSpec = derTlv((byte) 0xA0, octetString);
        return derTlv((byte) 0x30, concat(OID_PKCS7_DATA, contextSpec));
    }

    /**
     * Розбирає DER-відповідь CMP-сервера
     */
    static CmpResponse parseResponse(byte[] der) {
        if (der == null || der.length == 0)
            throw new IllegalArgumentException("Порожня відповідь.");

        int[] pos = { 0 };

        // SEQUENCE
        expectTag(der, pos, 0x30, "SEQUENCE");
        readLength(der, pos); // ігноруємо довжину верхнього SEQUENCE

        // OID
        expectTag(der, pos, 0x06, "OID");
        int oidLen = readLength(der, pos);
        pos[0] += oidLen; // пропускаємо байти OID

        // CONTEXT SPECIFIC [0]
        expectTag(der, pos, 0xA0, "CONTEXT SPECIFIC [0]");
        readLength(der, pos);

        // OCTET STRING
        expectTag(der, pos, 0x04, "OCTET STRING");
        int payloadLen = readLength(der, pos);
        if (pos[0] + payloadLen > der.length)
            throw new IllegalArgumentException("Несподіваний кінець даних.");

        if (payloadLen < 8)
            throw new IllegalArgumentException("Payload too short");

        ByteBuffer payload = ByteBuffer.wrap(der, pos[0], payloadLen).order(ByteOrder.LITTLE_ENDIAN);
        int type = payload.getInt();
        int status = payload.getInt();

        byte[] pkcs7 = null;
        if (payload.hasRemaining()) {
            pkcs7 = new byte[payload.remaining()];
            payload.get(pkcs7);
        }

        return new CmpResponse(type, status, pkcs7);
    }

    private static byte[] derLength(int length) {
        if (length < 0x80)
            return new byte[] { (byte) length };
        if (length <= 0xFF)
            return new byte[] { (byte) 0x81, (byte) length };
        if (length <= 0xFFFF)
            return new byte[] { (byte) 0x82, (byte) (length >> 8), (byte) length };
        // до 3 байтів довжини (достатньо для будь-якого реального запиту)
        return new byte[] { (byte) 0x83, (byte) (length >> 16), (byte) (length >> 8), (byte) length };
    }

    private static byte[] derTlv(byte tag, byte[] value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        out.writeBytes(derLength(value.length));
        out.writeBytes(value);
        return out.toByteArray();
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    private static void expectTag(byte[] data, int[] pos, int expected, String name) {
        if (pos[0] >= data.length)
            throw new IllegalArgumentException(String.format("Очікувався тег %s (0x%02X), але дані скінчилися.", name, expected));
        if ((data[pos[0]] & 0xFF) != expected)
            throw new IllegalArgumentException(String.format("Очікувався тег %s (0x%02X), отримано 0x%02X на позиції %d.",
                    name, expected, data[pos[0]] & 0xFF, pos[0]));
        pos[0]++;
    }

    private static int readLength(byte[] data, int[] pos) {
        if (pos[0] >= data.length)
            throw new IllegalArgumentException("Несподіваний кінець даних при читанні довжини.");

        int first = data[pos[0]++] & 0xFF;
        if (first < 0x80)
            return first;

        int numBytes = first & 0x7F;
        if (numBytes > 3 || pos[0] + numBytes > data.length)
            throw new IllegalArgumentException("Неправильна довжина.");
        int length = 0;
        for (int i = 0; i < numBytes; i++)
            length = (length << 8) | (data[pos[0]++] & 0xFF);
        return length;
    }
}
