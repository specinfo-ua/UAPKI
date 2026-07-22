/*
 * Copyright (c) 2025, The UAPKI Project Authors.
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

namespace UapkiNet;

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using UapkiNet.Polyfil;

/// <summary>
/// Клієнт для роботи з CMP-сервером ЦСК за власним протоколом (тип 13). Підтримує від 1 до 4 ідентифікаторів відкритих ключів (UAKEYID).
/// </summary>
public static partial class Uapki
{
    // OID 1.2.840.113549.1.7.1  (pkcs7-data) у DER:
    private static readonly byte[] OidPkcs7Data =
    {
        0x06, 0x09,
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01
    };

    private const int RecordType = 13;
    private const int RequestStatus = 0;

    /// <summary>Параметри запиту до CMP-сервера.</summary>
    private class CmpRequest
    {
        /// <summary>Список ідентифікаторів (від 1 до 4).</summary>
        public List<byte[]> KeyIds { get; set; } = new List<byte[]>();

        /// <summary>Повертати ланцюжок сертифікатів ЦСК разом із знайденими.</summary>
        public bool Chain { get; set; } = false;

        /// <summary>Включати сертифікати серверів ЦСК (CMP, TSP, OCSP) у ланцюжок.</summary>
        public bool IncludeAll { get; set; } = false;

        /// <summary>Підписувати відповідь ключем CMP-сервера.</summary>
        public bool SignResponse { get; set; } = false;
    }

    /// <summary>Відповідь CMP-сервера.</summary>
    private class CmpResponse
    {
        public int Type { get; set; }
        public int Status { get; set; }

        /// <summary>true, якщо хоча б один сертифікат знайдено (Status == 0).</summary>
        public bool Success => Status == 0;

        /// <summary>true, якщо жодного сертифіката не знайдено (Status == 3).</summary>
        public bool NotFound => Status == 3;

        /// <summary>Ланцюжок сертифікатів у форматі PKCS#7 (CMS) Binary (може бути null).</summary>
        public byte[]? Pkcs7Chain { get; set; }
    }

    /// <summary>Формує тіло HTTP-запиту (DER-кодований ASN.1).</summary>
    private static byte[] BuildRequest(CmpRequest req)
    {
        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms);

        // INT Type = 13  (4 байти, little-endian)
        bw.Write((int)RecordType);

        // INT Status = 0
        bw.Write((int)RequestStatus);

        // INT Count
        bw.Write((int)req.KeyIds.Count);

        // UAKEYID[4] — завжди записуємо 4 слоти;
        // незаповнені заповнюємо нулями
        for (int i = 0; i < 4; i++)
        {
            if (i < req.KeyIds.Count)
                bw.Write(req.KeyIds[i]);
            else
                bw.Write(new byte[32]);
        }

        // BOOL Chain
        bw.Write(req.Chain ? 1 : 0);

        // BOOL IncludeAll
        bw.Write(req.IncludeAll ? 1 : 0);

        // BOOL SignResponse
        bw.Write(req.SignResponse ? 1 : 0);

        bw.Flush();
        byte[] payload = ms.ToArray();

        //  SEQUENCE {
        //    OID  1.2.840.113549.1.7.1
        //    [0] EXPLICIT {
        //      OCTET STRING <payload>
        //    }
        //  }
        byte[] octetString = DerOctetString(payload);
        byte[] contextSpec = DerContextSpecific(0, octetString);
        byte[] sequence = DerSequence(Concat(OidPkcs7Data, contextSpec));

        return sequence;
    }

    /// <summary>Розбирає DER-відповідь CMP-сервера.</summary>
    private static CmpResponse ParseResponse(byte[] der)
    {
        if (der == null || der.Length == 0)
            throw new ArgumentException("Порожня відповідь.");

        int pos = 0;

        // SEQUENCE
        ExpectTag(der, ref pos, 0x30, "SEQUENCE");
        ReadLength(der, ref pos); // ігноруємо довжину верхнього SEQUENCE

        // OID
        ExpectTag(der, ref pos, 0x06, "OID");
        int oidLen = ReadLength(der, ref pos);
        pos += oidLen; // пропускаємо байти OID

        // CONTEXT SPECIFIC [0]
        ExpectTag(der, ref pos, 0xA0, "CONTEXT SPECIFIC [0]");
        ReadLength(der, ref pos);

        // OCTET STRING
        ExpectTag(der, ref pos, 0x04, "OCTET STRING");
        int payloadLen = ReadLength(der, ref pos);
        byte[] payload = new byte[payloadLen];
        Array.Copy(der, pos, payload, 0, payloadLen);

        if (payload.Length < 8)
            throw new InvalidDataException("Payload too short");

        int pPos = 0;
        int type = ReadInt32LE(payload, ref pPos);
        int status = ReadInt32LE(payload, ref pPos);

        byte[]? pkcs7 = null;
        if (pPos < payload.Length)
        {
            pkcs7 = new byte[payload.Length - pPos];
            Array.Copy(payload, pPos, pkcs7, 0, pkcs7.Length);
        }

        return new CmpResponse
        {
            Type = type,
            Status = status,
            Pkcs7Chain = pkcs7
        };
    }

    private static byte[] DerLength(int length)
    {
        if (length < 0x80)
            return new[] { (byte)length };

        if (length <= 0xFF)
            return new byte[] { 0x81, (byte)length };

        if (length <= 0xFFFF)
            return new byte[]
            {
                0x82,
                (byte)(length >> 8),
                (byte)(length & 0xFF)
            };

        // до 3 байт довжини (достатньо для будь-якого реального запиту)
        return new byte[]
        {
            0x83,
            (byte)(length >> 16),
            (byte)((length >> 8) & 0xFF),
            (byte)(length & 0xFF)
        };
    }

    private static byte[] DerTLV(byte tag, byte[] value)
    {
        var len = DerLength(value.Length);
        var result = new byte[1 + len.Length + value.Length];
        result[0] = tag;
        Array.Copy(len, 0, result, 1, len.Length);
        Array.Copy(value, 0, result, 1 + len.Length, value.Length);
        return result;
    }

    private static byte[] DerSequence(byte[] inner) => DerTLV(0x30, inner);
    private static byte[] DerOctetString(byte[] value) => DerTLV(0x04, value);
    private static byte[] DerContextSpecific(int n, byte[] inner) => DerTLV((byte)(0xA0 | n), inner);

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var result = new byte[a.Length + b.Length];
        Array.Copy(a, 0, result, 0, a.Length);
        Array.Copy(b, 0, result, a.Length, b.Length);
        return result;
    }

    private static void ExpectTag(byte[] data, ref int pos, byte expected, string name)
    {
        if (pos >= data.Length)
            throw new InvalidDataException($"Очікувався тег {name} (0x{expected:X2}), але дані скінчилися.");
        if (data[pos] != expected)
            throw new InvalidDataException(
                $"Очікувався тег {name} (0x{expected:X2}), отримано 0x{data[pos]:X2} на позиції {pos}.");
        pos++;
    }

    private static int ReadLength(byte[] data, ref int pos)
    {
        if (pos >= data.Length)
            throw new InvalidDataException("Несподіваний кінець даних при читанні довжини.");

        byte first = data[pos++];
        if (first < 0x80) return first;

        int numBytes = first & 0x7F;
        int length = 0;
        for (int i = 0; i < numBytes; i++)
            length = (length << 8) | data[pos++];
        return length;
    }

    private static int ReadInt32LE(byte[] data, ref int pos)
    {
        int value = BitConverter.ToInt32(data, pos);
        pos += 4;
        return value;
    }

    private static async Task<byte[]?> SendAsync(
            string serverUrl,
            byte[] cmpRequest,
            HttpClient httpClient,
            CancellationToken cancellationToken = default)
    {
        var byteContent = new ByteArrayContent(cmpRequest);
        byteContent.Headers.TryAddWithoutValidation("Content-Type", "application/cmp-request");
        byteContent.Headers.TryAddWithoutValidation("Content-Transfer-Encoding", "binary");

        var response = await httpClient.PostAsync(serverUrl, byteContent, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        //byte[] responseBody = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        ///var resp = ParseResponse(responseBody);

        using (var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false))
        using (var ms = new MemoryStream())
        {
            // Читаємо потік асинхронно з підтримкою скасування
            await stream.CopyToAsync(ms, 128 * 1024, cancellationToken).ConfigureAwait(false);

            // Передаємо готовий масив у ваш метод
            var resp = ParseResponse(ms.ToArray());
            return resp.Pkcs7Chain;
        }
    }

    public static async Task<byte[]?> Cmp(List<string> urls, List<string> keyIds, IWebProxy? proxy = null, CancellationToken ct = default)
    {
        if ((keyIds == null) || (keyIds.Count < 1) || (keyIds.Count > 4))
            throw new UapkiException("keyIds must be from 1 to 4");

        var bKeyIds = new List<byte[]>();

        foreach (var keyId in keyIds)
        {
            if ((keyId.Length != 64) && (keyId.Length != 40))
                throw new UapkiException("Invalid keyId length");

            bKeyIds.Add(Hex.FromHexString(keyId.PadRight(64, '0')));
        }

        var cmpRequest = BuildRequest(new CmpRequest() { KeyIds = bKeyIds, Chain = false, IncludeAll = false, SignResponse = false });

        using var httpClientHandler = new HttpClientHandler { Proxy = proxy };
        using var http = new HttpClient(httpClientHandler) { Timeout = TimeSpan.FromSeconds(10) };

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(11));

        var tasks = urls
        .Select(url => SendAsync(url, cmpRequest, http, cancellationToken: cts.Token))
        .ToList();

        while (tasks.Count > 0)
        {
            if (cts.IsCancellationRequested)
                return null;

            Task<byte[]?> completed;
            try
            {
                completed = await Task.WhenAny(tasks).WithCancellation(cts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) 
            {
                return null;
            }

            tasks.Remove(completed);

            try
            {
                var response = await completed.ConfigureAwait(false);
                if (response is not null)
                {
                    cts.Cancel();
                    return response;
                }
            }
            catch { }
        }

        return null;
    }
}

public static class TaskExtensions
{
    public static async Task<Task<byte[]?>> WithCancellation(this Task<Task<byte[]?>> task, CancellationToken cancellationToken)
    {
        var tcs = new TaskCompletionSource<bool>();
        using (cancellationToken.Register(s => ((TaskCompletionSource<bool>)s!).TrySetResult(true), tcs))
        {
            var anyTask = await Task.WhenAny(task, tcs.Task).ConfigureAwait(false);
            if (anyTask == tcs.Task)
            {
                throw new OperationCanceledException(cancellationToken);
            }
        }
        return await task;
    }
}
