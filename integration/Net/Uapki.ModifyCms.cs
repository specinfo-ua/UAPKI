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

using System.Text.Json;

namespace UapkiNet;

public partial class Uapki
{
    public class ModifyCmsParameters
    {
        public byte[]? Bytes { get; set; }
        public AddSignature? Add { get; set; }
        public ModifyCmsOptions? Options { get; set; }
        public ModifyCmsRemove? Remove { get; set; }
    }

    /// <summary>
    /// Що додати до PKCS#7-підпису (MODCMS_ADD)
    /// </summary>
    public class AddSignature
    {
        /// <summary>PKCS#7-підпис або, якщо IsSignerInfo = true, DER-кодована структура SignerInfo</summary>
        public byte[]? Bytes { get; set; }
        /// <summary>Ознака, що в Bytes знаходиться структура SignerInfo</summary>
        public bool? IsSignerInfo { get; set; }
        /// <summary>Індекс підпису в PKCS#7-підписі з Bytes, який додається (за замовчуванням 0)</summary>
        public uint? SignIndex { get; set; }
        /// <summary>Контент; має відповідати гешу в першому підписі</summary>
        public byte[]? Content { get; set; }
        public List<byte[]>? Certificates { get; set; }
        public List<byte[]>? Crls { get; set; }
    }

    /// <summary>
    /// Що видалити з PKCS#7-підпису (MODCMS_REMOVE); видалення виконується до додавання
    /// </summary>
    public class ModifyCmsRemove
    {
        public bool? Content { get; set; }
        /// <summary>Індекс підпису (структури SignerInfo), який видаляється</summary>
        public int? SignIndex { get; set; }
        /// <summary>Видалити всі сертифікати</summary>
        public bool? Certificates { get; set; }
        /// <summary>Видалити всі СВС</summary>
        public bool? Crls { get; set; }
    }

    public class ModifyCmsOptions
    {
        public bool ReturnContent { get; set; }
        public bool ReturnCerts { get; set; }
        public bool ReturnCrls { get; set; }
        public bool ReturnEncodedSignerInfo { get; set; }
    }

    private class ModifyCmsResponse
    {
        public int ErrorCode { get; set; }
        public string? Method { get; set; }
        public ModifyCmsResult? Result { get; set; }
    }

    public class ModifyCmsResult
    {
        public int Version { get; set; }
        public List<string> DigestAlgorithms { get; set; } = new List<string>();
        public SignContent? Content { get; set; }
        public List<SignatureInfoEx> SignatureInfos { get; set; } = new List<SignatureInfoEx>();
        public List<byte[]> Certificates { get; set; } = new List<byte[]>();
        public List<byte[]> Crls { get; set; } = new List<byte[]>();
        public byte[]? Bytes { get; set; } // згенерований PKCS#7-підпис
    }

    public class SignContent
    {
        public string? Type { get; set; } // OID типу контенту
        public byte[]? Bytes { get; set; }
    }

    public class SignatureInfoEx
    {
        public int Version { get; set; }
        public string? SerialNumber { get; set; }
        public byte[]? IssuerBytes { get; set; }
        public DistinguishedName? Issuer { get; set; }
        public string? KeyId { get; set; }
        public string? SignAlgo { get; set; }
        public string? DigestAlgo { get; set; }
        public string? ContentType { get; set; }
        public byte[]? MessageDigest { get; set; }
        public byte[]? Bytes { get; set; }
    }

    /// <summary>
    /// Модифікація PKCS#7-підпису без зміни значень підписів (метод MODIFY_CMS): спочатку виконується
    /// видалення (remove), потім додавання (add). Якщо щось додано або видалено, новий PKCS#7-підпис
    /// повертається в ModifyCmsResult.Bytes
    /// </summary>
    public ModifyCmsResult ModifyCms(byte[] cmsBytes, AddSignature? add, ModifyCmsRemove? remove = null, ModifyCmsOptions? options = null)
    {
        var parameters = new ModifyCmsParameters
        {
            Bytes = cmsBytes,
            Add = add,
            Remove = remove,
            Options = options
        };

        string modify_cms_cmd = Request("MODIFY_CMS", parameters, jsonCtx.ModifyCmsParameters);

        var ret = JsonSerializer.Deserialize(Process(modify_cms_cmd), jsonCtx.ModifyCmsResponse) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0)
            throw new UapkiException(ret.ErrorCode);

        return ret.Result ?? throw new UapkiException(0x2001);
    }

    /// <summary>
    /// Додати до PKCS#7-підпису підпис і/або сертифікати, а також отримати контент, сертифікати, СВС
    /// </summary>
    public ModifyCmsResult ModifyCms(byte[] cmsBytes, byte[]? addSignatureBytes = null, List<byte[]>? addCertificates = null, bool returnContent = false, bool returnCerts = false, bool returnCrls = false, bool returnEncodedSignerInfo = false)
    {
        var add = (addSignatureBytes != null || (addCertificates != null && addCertificates.Count > 0)) ? new AddSignature
        {
            Bytes = addSignatureBytes,
            Certificates = addCertificates
        } : null;
        var options = new ModifyCmsOptions
        {
            ReturnContent = returnContent,
            ReturnCerts = returnCerts,
            ReturnCrls = returnCrls,
            ReturnEncodedSignerInfo = returnEncodedSignerInfo
        };

        return ModifyCms(cmsBytes, add, null, options);
    }
}
