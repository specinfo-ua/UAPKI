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
    public class KeyStorage
    {
        public string Id { get; init; } = string.Empty;
        public string Manufacturer { get; init; } = string.Empty;
        public string Model { get; init; } = string.Empty;
        public string Description { get; init; } = string.Empty;
        public string Serial { get; init; } = string.Empty;
        public string Label { get; init; } = string.Empty;
        public bool PasswordCountLow { get; init; } = false;
        public bool PasswordFinalTry { get; init; } = false;
        public bool PasswordLocked { get; init; } = false;
        public bool PasswordToBeChanged { get; init; } = false;
        public uint PasswordAttemptsLeft { get; init; } = 255;
        public uint PasswordMinLen { get; init; } = 6;
        public uint PasswordMaxLen { get; init; } = 64;

        [JsonIgnore]
        public string ProviderId { get; internal set; } = string.Empty;

        [JsonIgnore]
        public List<Key>? Keys { get; internal set; }

        public KeyStorage() { }

        public KeyStorage(string fileName, string providerId)
        {
            Id = fileName;
            ProviderId = providerId;
            Manufacturer = "SPECINFOSYSTEMS";
            Description = "FILE";
            Model = "FILE";
            Label = fileName;
            Serial = Path.GetFileName(fileName);
        }
    }

    private static void CheckStorage(KeyStorageOpenMode requiredMode = KeyStorageOpenMode.RO)
    {
        CheckInit();

        if (OpenedKeyStorage is null)
            throw new UapkiException("Помилка. Сховище ключів не відкрито");

        if (requiredMode == KeyStorageOpenMode.RW && OpenedKeyStorage.Mode == KeyStorageOpenMode.RO)
            throw new UapkiException("Помилка. Сховище ключів відкрито тільки для читання");
    }

    private class KeyStoragesList
    {
        public List<KeyStorage>? Storages { get; init; }
    }

    private class StoragesResult
    {
        public int ErrorCode { get; init; }
        public string? Method { get; init; }
        public KeyStoragesList? Result { get; init; }
    }

    public static List<KeyStorage> GetKeyStorages(List<CmProvider>? providers = null)
    {
        CheckInit();

        var keyStorages = new List<KeyStorage>();

        providers ??= UapkiInfo!.Providers;

        foreach (var provider in providers)
        {
            if (!provider.SupportListStorages)
                continue;

            string storages_cmd = "{\"method\":\"STORAGES\",\"parameters\":{\"provider\":\"" + provider.Id + "\"}}";

            var ret = JsonSerializer.Deserialize(Process(storages_cmd), jsonCtx.StoragesResult) ?? throw new UapkiException(0x2001);
            if (ret.ErrorCode != 0)
                throw new UapkiException(ret.ErrorCode);

            if (ret.Result is null)
                throw new UapkiException(0x2001);

            if (ret.Result.Storages is not null)
            {
                foreach (var storage in ret.Result.Storages)
                {
                    try
                    {
                        var s = storage;
                        s.ProviderId = provider.Id;
                        keyStorages.Add(s);
                    }
                    catch { /*do nothing*/ }
                }
            }
        }

        return keyStorages;
    }

    public class OpenedKeyStorageInfo
    {
        public KeyStorage Storage { get; internal set; } = new KeyStorage();
        public KeyStorageInfo StorageInfo { get; init; } = new KeyStorageInfo();
        public KeyStorageOpenMode Mode { get; init; }
    }

    public class KeyStorageInfo
    {
        public List<MechanismInfo>? Mechanisms { get; init; }
        public bool? UserPresense { get; init; }
    }

    private class OpenKeyStorageResult
    {
        public int ErrorCode { get; init; }
        public string? Method { get; init; }
        public KeyStorageInfo? Result { get; init; }
    }

    public class OpenKeyStorageLoginParams
    {
        public uint? Partition { get; init; }
        public string? UserType { get; init; }
    }

    public class OpenKeyStorageExtParams
    {
        public string? DeviceType { get; init; }
    }

    private class OpenKeyStorageParams
    {
        public string? Provider { get; init; }
        public string? Storage { get; init; }
        public string? Password { get; init; }
        public string? Mode { get; init; }
        public string? Username { get; init; }
        public OpenKeyStorageExtParams? OpenParams { get; init; }
    }

    public static void OpenKeyStorage(KeyStorage storage, string passwd, KeyStorageOpenMode mode, OpenKeyStorageLoginParams? loginParams = null, OpenKeyStorageExtParams? openParams = null)
    {
        if (OpenedKeyStorage is not null)
            CloseKeyStorage();

        string openMode = "RW";
        if (mode == KeyStorageOpenMode.CREATE)
        {
            openMode = "CREATE";
        }
        else
        {
            var ext = Path.GetExtension(storage.Id);
            if ((mode == KeyStorageOpenMode.RO) || (storage.ProviderId == "PKCS12" && ext != ".p12" && ext != ".pfx"))
                openMode = "RO";
        }

        var parameters = new OpenKeyStorageParams()
        {
            Provider = storage.ProviderId,
            Storage = storage.Id,
            Password = passwd,
            Mode = openMode,
            Username = loginParams is not null ? JsonSerializer.Serialize(loginParams, jsonCtx.OpenKeyStorageLoginParams) : null,
            OpenParams = openParams
        };

        string open_cmd = "{\"method\":\"OPEN\",\"parameters\":" +
            JsonSerializer.Serialize(parameters, jsonCtx.OpenKeyStorageParams) + "}";

        var ret = JsonSerializer.Deserialize(Process(open_cmd), jsonCtx.OpenKeyStorageResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0)
            throw new UapkiException(ret.ErrorCode);

        if (ret.Result is null)
            throw new UapkiException(0x2001);

        OpenedKeyStorage = new()
        {
            Storage = storage,
            StorageInfo = ret.Result,
            Mode = mode
        };

        UpdateKeysInOpenedStorage(true);
    }

    private class OpenKeyStorageRequest
    {
        public string? Method { get; init; }
        public OpenKeyStorageParams? Parameters { get; init; }
    }

    public static string OpenKeyStorageCmd(string open_cmd)
    {
        if (OpenedKeyStorage is not null)
            CloseKeyStorage();

        var req = JsonSerializer.Deserialize(open_cmd, jsonCtx.OpenKeyStorageRequest) ?? throw new UapkiException(0x2001);
        var res = Process(open_cmd);
        var ret = JsonSerializer.Deserialize(res, jsonCtx.OpenKeyStorageResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode == 0)
        {
            if (ret.Result is null)
                throw new UapkiException(0x2001);

            if (req.Parameters?.Storage is null || req.Parameters?.Provider is null)
                throw new UapkiException(0x2001);

            OpenedKeyStorage = new OpenedKeyStorageInfo()
            {
                Storage = new KeyStorage(req.Parameters.Storage, req.Parameters.Provider),
                StorageInfo = ret.Result,
                Mode = req.Parameters.Mode is not null && (req.Parameters.Mode == "RW" || req.Parameters.Mode == "CREATE") ?
                    KeyStorageOpenMode.RW : KeyStorageOpenMode.RO
            };

            UpdateKeysInOpenedStorage(true);
        }

        return res;
    }

    public static void OpenKeyStorage(string fileName, string passwd, KeyStorageOpenMode mode)
    {
        if (OpenedKeyStorage is not null)
            CloseKeyStorage();

        string openMode = "RW";
        if (mode == KeyStorageOpenMode.CREATE)
        {
            openMode = "CREATE";
        }
        else
        {
            var ext = Path.GetExtension(fileName);
            if ((mode == KeyStorageOpenMode.RO) || (ext != ".p12" && ext != ".pfx"))
                openMode = "RO";
        }

        var parameters = new OpenKeyStorageParams()
        {
            Provider = "PKCS12",
            Storage = fileName,
            Password = passwd,
            Mode = openMode
        };

        string open_p12_cmd = "{\"method\":\"OPEN\",\"parameters\":" +
            JsonSerializer.Serialize(parameters, jsonCtx.OpenKeyStorageParams) + "}";

        var ret = JsonSerializer.Deserialize(Process(open_p12_cmd), jsonCtx.OpenKeyStorageResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0)
            throw new UapkiException(ret.ErrorCode);

        if (ret.Result is null)
            throw new UapkiException(0x2001);

        OpenedKeyStorage = new OpenedKeyStorageInfo()
        {
            Storage = new KeyStorage(fileName, "PKCS12"),
            StorageInfo = ret.Result,
            Mode = (openMode == "RW" || openMode == "CREATE") ? KeyStorageOpenMode.RW : KeyStorageOpenMode.RO
        };

        UpdateKeysInOpenedStorage(true);
    }

    public static void CloseKeyStorage()
    {
        CheckStorage();

        string close_cmd = "{\"method\":\"CLOSE\"}";

        var ret = JsonSerializer.Deserialize(Process(close_cmd), jsonCtx.ErrorCodeResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0)
            throw new UapkiException(ret.ErrorCode);

        OpenedKeyStorage = null;
        SelectedKey = null;
    }

    public static void ChangePassword(string newPassword)
    {
        CheckStorage(KeyStorageOpenMode.RW);

        string change_password_cmd = "{\"method\":\"CHANGE_PASSWORD\",\"parameters\":{\"newPassword\":\"" + newPassword + "\"}}";

        var ret = JsonSerializer.Deserialize(Process(change_password_cmd), jsonCtx.ErrorCodeResult) ?? throw new UapkiException(0x2001);
        if (ret.ErrorCode != 0)
            throw new UapkiException(ret.ErrorCode);
    }
}
