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

using System.Text.Json;
using System.Text.Json.Serialization;

namespace UapkiNet;

public static partial class Uapki
{
    public class Key
    {
        public string Id { get; init; } = string.Empty;
        public string? KeyId2 { get; init; }
        public string MechanismId { get; init; } = string.Empty;
        public string ParameterId { get; init; } = string.Empty;
        public string? Label { get; init; }
        public string? Application { get; init; }
        public string? CertId { get; init; }

        [JsonIgnore]
        public  KeyAlgo KeyAlgo { get { return MechanismId.ToKeyAlgo(); } }
        [JsonIgnore]
        public  KeyParameter KeyParam { get { return ParameterId.ToKeyParameter(); } }

        [JsonIgnore]
        public string KeyAlgoAndParamDisplay
        {
            get
            {
                string s1 = "", s2 = "";
                try { s1 = KeyAlgo.DisplayName(); } catch { /*do nothing*/ }
                try { s2 = KeyParam.DisplayName(); } catch { /*do nothing*/ }
                if (s1.Length > 0 && s2.Length > 0)
                    return s1 + " (" + s2 + ")";
                return s1;
            }
        }

        [JsonIgnore]
        public  string KeyAlgoDisplay { get { return KeyAlgo.DisplayName(); } }

        [JsonIgnore]
        public  string KeyParamDisplay { get { return KeyParam.DisplayName(); } }

        [JsonIgnore]
        public List<CertificateShortInfo>? Certs { get; internal set; }

        
        [JsonIgnore]
        public string UsageDisplay { get { return Usage.DisplayName(); } }
        
        [JsonIgnore]
        public DateTime? DateTime
        { 
            get 
            {
                if (Certs is not null && Certs.Count > 0)
                {
                    return Certs.Max(item => item.Validity.NotAfter);
                }
                return null;
            }
        }

        [JsonIgnore]
        public string DateTimeDisplay { get { return DateTime != null ? ((DateTime)DateTime).ToString("yyyy-MM-dd hh:mm") : ""; } }

        [JsonIgnore]
        public string Name 
        { 
            get 
            {
                if (Certs is not null && Certs.Count > 0)
                {
                    return Certs[0].Subject.CN + "\n" + Certs[0].Subject.O;
                }
                else
                {
                    var name = "Сертифікат відсутній";
                    if (Label is not null)
                    {
                        if (Label.StartsWith("SIG:"))
                            return name + "\nЗгенеровано: " + ConvertUtcTimeToDateTime(Label.Substring(4)).ToString("yyyy-MM-dd hh:mm");
                        if (Label.StartsWith("KEP:"))
                            return name + "\nЗгенеровано: " + ConvertUtcTimeToDateTime(Label.Substring(4)).ToString("yyyy-MM-dd hh:mm");
                        // Almaz
                        if (Label.StartsWith("SIGN-")) 
                            return name + "\nКонтекст: " + Label.Substring(5);
                        if (Label.StartsWith("KEP-")) 
                            return name + "\nКонтекст: " + Label.Substring(4);
                    }
                    return name;
                }
            }
        }

        [JsonIgnore]
        public KeyUsage Usage
        {
            get
            {
                if (Certs is not null && Certs.Count > 0)
                {
                    var cert = Certs[0];
                    if (cert.KeyUsage.KeyAgreement)
                        return KeyUsage.KeyAgreement;
                    if (cert.KeyUsage.KeyEncipherment)
                        return KeyUsage.KeyEncipherment;
                    if (cert.KeyUsage.DigitalSignature)
                        return KeyUsage.Signature;
                }
                else
                {
                    if ((Label?.StartsWith("SIG") == true) || (Label?.Equals("KM AFD1") == true))
                        return KeyUsage.Signature;
                    if ((Label?.StartsWith("KEP") == true) || (Label?.Equals("KM AFD2") == true))
                    {
                        if (KeyAlgo != KeyAlgo.Rsa) return KeyUsage.KeyAgreement;
                        else return KeyUsage.KeyEncipherment;
                    }
                }

                return KeyUsage.Any;
            }
        }
    }

    public class SelectedKeyInfo
    {
        public Key? Key { get; internal set; }
        public Certificate? Cert { get; internal set; }
    }

    private class KeysList
    {
        public List<Key>? Keys { get; init; }
    }

    private class KeysResult
    {
        public int ErrorCode { get; init; }
        public string? Method { get; init; }
        public KeysList? Result { get; init; }
    }

    public static void UpdateKeysInOpenedStorage(bool withCerts = false)
    {
        CheckInit();
        CheckStorage();

        string keys_cmd = "{\"method\":\"KEYS\"}";

        var ret = JsonSerializer.Deserialize(Process(keys_cmd), jsonCtx.KeysResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0)
            throw new UapkiException(ret.ErrorCode);

        if (ret.Result!.Keys is null)
        {
            OpenedKeyStorage!.Storage.Keys = new List<Key>();
            return;
        }

        var keys = ret.Result!.Keys;

        if (withCerts)
        {
            for (int i = 0; i < keys.Count; i++)
            {
                var key = keys[i];
                var ids = new List<string> { key.Id };
                if (key.KeyId2 is not null) ids.Add(key.KeyId2!);
                key.Certs = GetCertsShortInfoList(keyIds: ids);
                keys[i] = key;
            }
        }

        OpenedKeyStorage!.Storage.Keys = keys;
    }

    private class SelectKeyResult
    {
        public int ErrorCode { get; init; }
        public string? Method { get; init; }
        public Key? Result { get; init; }
    }

    public class ParametersId
    {
        public string Id { get; init; } = string.Empty;
    }

    public class IdRequest
    {
        public string? Method { get; init; }
        public ParametersId Parameters { get; init; } = new ParametersId();
    }

    public static void SelectKeyByCert(string certId)
    {
        CheckInit();
        CheckStorage();

        string select_cmd = "{\"method\":\"SELECT_KEY\",\"parameters\":{\"certId\":\"" + certId + "\"}}";

        var ret = JsonSerializer.Deserialize(Process(select_cmd), jsonCtx.SelectKeyResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0)
            throw new UapkiException(ret.ErrorCode);

        SelectedKey = new SelectedKeyInfo()
        {
            Key = ret.Result,
            Cert = ret.Result?.CertId is not null ? GetCertInfo(ret.Result.CertId) : null
        };
    }

    public static void SelectKey(string keyId)
    {
        CheckInit();
        CheckStorage();

        string select_cmd = "{\"method\":\"SELECT_KEY\",\"parameters\":{\"id\":\"" + keyId + "\"}}";

        var ret = JsonSerializer.Deserialize(Process(select_cmd), jsonCtx.SelectKeyResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0)
            throw new UapkiException(ret.ErrorCode);

        SelectedKey = new SelectedKeyInfo()
        {
            Key = ret.Result,
            Cert = ret.Result?.CertId is not null ? GetCertInfo(ret.Result.CertId) : null
        };
    }

    public static void SelectKey(Key key)
    {
        SelectKey(key.Id);
    }
        
    public static string SelectKeyCmd(string select_cmd)
    {
        CheckInit();
        CheckStorage();

        var res = Process(select_cmd);

        var ret = JsonSerializer.Deserialize(res, jsonCtx.SelectKeyResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode == 0)
        {
            SelectedKey = new SelectedKeyInfo()
            {
                Key = ret.Result,
                Cert = ret.Result?.CertId is not null ? GetCertInfo(ret.Result.CertId) : null
            };
        }

        return res;
    }

    public static void DeleteKey(Key key)
    {
        CheckInit();
        CheckStorage(KeyStorageOpenMode.RW);

        string delete_key_cmd = "{\"method\":\"DELETE_KEY\",\"parameters\":{\"id\":\"" + key.Id + "\"}}";

        var ret = JsonSerializer.Deserialize(Process(delete_key_cmd), jsonCtx.ErrorCodeResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0)
            throw new UapkiException(ret.ErrorCode);

        if (SelectedKey?.Key?.Id == key.Id)
            SelectedKey = null;
    }

    private class KeyId
    {
        public string? Id { get; init; }
    }

    private class KeyIdResult
    {
        public int ErrorCode { get; init; }
        public string? Method { get; init; }
        public KeyId? Result { get; init; }
    }

    public static string GenerateKey(string label, string application, string mechanism, string parameter, bool isKep)
    {
        CheckStorage(KeyStorageOpenMode.RW);

        string gen_key_cmd = "{\"method\":\"CREATE_KEY\",\"parameters\":{" +
            "\"mechanismId\":\"" + mechanism + "\"," +
            "\"parameterId\":\"" + parameter + "\"," +
            "\"label\":\"" + label + "\"," +
            "\"application\":\"" + application + "\"," +
            "\"flags\":{\"keyAgreement\":" + (isKep ? "true" : "false") + "}}}";

        var ret = JsonSerializer.Deserialize(Process(gen_key_cmd), jsonCtx.KeyIdResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0)
            throw new UapkiException(ret.ErrorCode);

        if (ret.Result?.Id is null)
            throw new UapkiException(0x2001);

        return ret.Result.Id;
    }
}
