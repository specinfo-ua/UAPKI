/*
 * Copyright (c) 2021, The UAPKI Project Authors.
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

using System;
using System.IO;
using UapkiLibrary;

namespace UapkiNet
{
    class UapkiApp
    {
        static string selectedStorage = null;
        static string selectedStorageMode = null;
        static string selectedKeyId = null;

        static dynamic providersList = null;
        static dynamic storagesList = null;
        static dynamic keysList = null;

        static bool printShortCertInfo(dynamic certInfo)
        {
            Console.WriteLine("Власник: " + certInfo.subject.CN);
            Console.WriteLine("Видавець: " + certInfo.issuer.CN);
            Console.WriteLine("Серiйний номер: " + certInfo.serialNumber);
            Console.WriteLine("Термiн дiї: з " + certInfo.validity.notBefore + " по " + certInfo.validity.notAfter);
            return certInfo.selfSigned;
        }

        static bool printShortCertInfo(byte[] cert)
        {
            return printShortCertInfo(Uapki.CertInfo(cert));
        }

        static bool printShortCertInfo(string certId)
        {
            return printShortCertInfo(Uapki.CertInfo(certId));
        }

        static string ReadPassword()
        {
            var pass = string.Empty;
            ConsoleKey key;
            do
            {
                var keyInfo = Console.ReadKey(intercept: true);
                key = keyInfo.Key;

                if (key == ConsoleKey.Backspace && pass.Length > 0)
                {
                    Console.Write("\b \b");
                    pass = pass[0..^1];
                }
                else if (!char.IsControl(keyInfo.KeyChar))
                {
                    Console.Write("*");
                    pass += keyInfo.KeyChar;
                }
            } while (key != ConsoleKey.Enter);

            return pass;
        }

        static string OidToAlgName(string oid)
        {
            // TODO
            return oid;
        }

        static string AlgNameOidTo(string algo)
        {
            // TODO
            return algo;
        }

        static void StorageOpen(string mode = "RO")
        {
            try
            {
                if (selectedStorage != null)
                {
                    Console.WriteLine("Сховище ключів вже відкрито: " + selectedStorage);
                    Console.WriteLine("Якщо необхідно відкрити інше сховище - спочатку закрийте поточне");
                    return;
                }

                Console.Write("Введiть iм'я сховища ключiв: ");
                var storageId = Console.ReadLine();
                string newMode = mode;
                
                if (!File.Exists(storageId)) 
                {
                    if (newMode == "RO")
                    {
                        Console.Write("Заданого сховища ключів не існує");
                        return;
                    }
                    else
                        newMode = "CREATE";
                }
                
                Console.Write("Введiть пароль до сховища ключiв: ");
                string pass = ReadPassword();
                Console.WriteLine("");

                var result = Uapki.OpenStorage("PKCS12", storageId, pass, newMode);

                Console.WriteLine("Сховище ключiв вiдкрито в режимі " + ((newMode == "RO") ? "'тільки читання'" : "'читання/запис'"));
                selectedStorage = storageId;
                selectedStorageMode = mode;
            }
            catch (Exception e)
            {
                Console.WriteLine("Помилка відкриття сховища ключів: " + e.Message);
            }
        }

        static void StorageClose()
        {
            try
            {
                if (selectedStorage == null)
                {
                    Console.WriteLine("Немає відкритого сховища");
                    return;
                }

                Uapki.CloseStorage();
                Console.WriteLine("Сховище ключiв вiдкрито в режимі 'тільки читання'");

                selectedStorage = null;
                selectedKeyId = null;
                keysList = null;
            }
            catch (Exception e)
            {
                Console.WriteLine("Помилка відкриття сховища ключів: " + e.Message);
            }
        }

        static void KeySelect(string storageMode = null)
        {
            try
            {
                if (selectedStorage == null)
                {
                    Console.WriteLine("Сховище ключів не відкрито. Виконується open-storage");
                    StorageOpen(storageMode);
                    if (selectedStorage == null) return;
                }

                keysList = Uapki.StorageKeysList().keys;

                if (keysList == null || keysList.Count == 0)
                {
                    Console.WriteLine("У сховищі немає ключів");
                    return;
                }

                Console.WriteLine("Перелiк ключiв у сховищi:");
                int i = 1;
                foreach (dynamic key in keysList)
                {
                    Console.WriteLine(i.ToString() + ": Назва: " + (key.label != null ? key.label : "відсутня") + 
                        ", алгоритм: " + OidToAlgName((string)key.mechanismId) + " iдентифiкатор (HEX): " + key.id);
                    i++;
                }
                Console.Write("Виберiть ключ. Введiть номер у переліку: ");
                int k = Convert.ToInt32(Console.ReadLine());
                if (k < 1 || k >= i)
                {
                    Console.WriteLine("Неправильний номер ключа");
                    return;
                }

                var result = Uapki.StorageSelectKey((string)keysList[k - 1].id);
                selectedKeyId = keysList[k - 1].id;

                if (result.certificate != null)
                {
                    Console.WriteLine("Ключ завантажено, сертифiкат:");
                    printShortCertInfo(Convert.FromBase64String((string)result.certificate));
                    return;
                }
                else if (result.certId != null)
                {
                    Console.WriteLine("Ключ завантажено, сертифiкат:");
                    printShortCertInfo((string)result.certId);
                    return;
                }

                Console.WriteLine("Ключ завантажено, сертифiкат вiдсутнiй");

            }
            catch (Exception e)
            {
                Console.WriteLine("Помилка завантаження ключа: " + e.Message);
            }
        }

        static void GetCsr()
        {
            try
            {
                if (selectedKeyId == null)
                {
                    Console.WriteLine("Ключ не вибрано. Виконується select-key");
                    KeySelect();
                    if (selectedKeyId == null) return;
                }

                var result = Uapki.KeyGetCsr();
                File.WriteAllBytes(selectedKeyId + ".p10", Convert.FromBase64String((string)result.bytes));
                Console.WriteLine("Запит на формування сертифiкату збережено у файлi " + selectedKeyId + ".p10");
            }
            catch (Exception e)
            {
                Console.WriteLine("Помилка формування запиту на сертифiкат: " + e.Message);
            }
        }

        static void CertChainVerify(byte[] cert, string certId, bool useOCSP = false)
        {
            while (true)
            {
                Console.WriteLine("-------------------------------------------------------------------------------------------------");
                if (cert == null && certId == null)
                {
                    Console.WriteLine("Помилка валiдацiї: відсутній сертифікат");
                    return;
                }

                if (certId == null)
                    certId = Uapki.CertAddToCache(cert, false);

                cert = null;

                bool selfSigned = printShortCertInfo(certId);
                
                var result = Uapki.CertVerify(certId, useOCSP && !selfSigned);

                if (result.expired == true)
                {
                    Console.WriteLine("Сертифiкат не чинний за часом");
                    break;
                }

                if (result.statusSignature != "VALID")
                {
                    Console.WriteLine("Сертифiкат має не валідний підпис");
                    break;
                }

                Console.WriteLine("Сертифiкат чинний за часом та пiдписом");

                if (useOCSP && !selfSigned)
                {
                    if (result.validateByOCSP.status != "GOOD")
                    {
                        if (result.validateByOCSP.status == "REVOKED")
                        {
                            Console.WriteLine("Сертифiкат не чинний за запитом OSCP. Час скасування або блокування: " + result.validateByOCSP.revocationTime + ", причина: " + result.OCSP.revocationReason);
                        }
                        else
                        {
                            Console.WriteLine("Сертифiкат не визначено за запитом OSCP");
                        }
                        break;
                    }
                    Console.WriteLine("Сертифiкат чинний за запитом OSCP");
                }

                if (result.selfSigned == true)
                {
                    Console.WriteLine("Досягнуто кореневого (самопiдписаного) сертифiкату. Кiнець ланцюжку");
                    if (result.trusted != true)
                        Console.WriteLine("Увага! Кореневий сертифікат не є довіреним");
                    break;
                }
                certId = result.issuerCertId;
            }
        }

        static void CertVerify()
        {
            try
            {
                Console.Write("Введiть iм'я файлу сертифiката: ");
                string certFile = Console.ReadLine();
                var cert = File.ReadAllBytes(certFile);
                CertChainVerify(cert, null, true);
            }
            catch (Exception e)
            {
                Console.WriteLine("Помилка зчитування сертифiкату: " + e.Message);
            }
        }

        static void SignCms()
        {
            try
            {
                if (selectedKeyId == null)
                {
                    Console.WriteLine("Ключ не вибрано. Виконується select-key");
                    KeySelect();
                    if (selectedKeyId == null) return;
                }
                Console.Write("Введiть iм'я файлу для пiдпису: ");
                string dataFile = Console.ReadLine();
                var data = File.ReadAllBytes(dataFile);
                Console.Write("Додати сертифiкат пiдписувача до пiдпису [Y/N]: ");
                bool includeCert = Console.ReadLine().ToUpper() == "Y";
                Console.Write("Додати мiтку часу вiд даних [Y/N]: ");
                bool useTSP = Console.ReadLine().ToUpper() == "Y";
                Console.Write("Приєднати данi до пiдпису [Y/N]: ");
                bool detachedData = Console.ReadLine().ToUpper() != "Y";

                var signature = Uapki.SignCms(data, detachedData, includeCert, useTSP);

                File.WriteAllBytes(dataFile + ".p7s", signature);
                Console.WriteLine("Пiдпис збережено у файлi " + dataFile + ".p7s");
            }
            catch (Exception e)
            {
                Console.WriteLine("Помилка пiдпису: " + e.Message);
            }
        }

        static void VerifyCms()
        {
            try
            {
                Console.Write("Введiть iм'я файлу з пiдписом: ");
                var signatureFile = Console.ReadLine();
                var signature = File.ReadAllBytes(signatureFile);

                Console.Write("Введiть iм'я файлу з даними (у разi iнкапсульованих даних залиште порожнiм): ");
                var contentFile = Console.ReadLine();
                byte[] content = null;
                if (contentFile != null && contentFile != "")
                    content = File.ReadAllBytes(contentFile);

                var result = Uapki.VerifyCms(signature, content);

                int i = 1;
                foreach (dynamic sInfo in result.signatureInfos)
                {
                    Console.Write("Пiдпис " + i + ": ");
                    if (sInfo.status != "TOTAL-VALID")
                    {
                        Console.WriteLine("невiрний");
                        return;
                    }

                    Console.WriteLine("вiрний");
                    if (sInfo.contentTS != null)
                        Console.WriteLine("Позначка часу вiд даних присутня, час: " + sInfo.genTime);
                    else
                        Console.WriteLine("Позначка часу вiд даних вiдсутня");

                    Console.WriteLine("Перевiрка сертифiкату пiдписувача:");
                    CertChainVerify(null, (string)sInfo.signerCertId, true);
                    Console.WriteLine("-------------------------------------------------------------------------------------------------");
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("Помилка перевiрки пiдпису: " + e.Message);
            }
        }

        static void KeyGenerate()
        {
            try
            {
                if (selectedStorageMode == "RO")
                {
                    Console.WriteLine("Поточне сховище ключів відкрите тільки для читання");
                    return;
                }

                Console.Write("Введiть назву ключа: ");
                var label = Console.ReadLine();

                StorageOpen("RW");
                if (selectedStorage == null)
                    return;

                string keyId = Uapki.KeyGenerate(label);
                Console.WriteLine("Ключ створено. Id: " + keyId);
                selectedKeyId = keyId;
                GetCsr();
            }
            catch (Exception e)
            {
                Console.WriteLine("Помилка генерацiї ключа: " + e.Message);
            }
        }

        static void CertsList()
        {
            var certs = Uapki.CertsInCache();
            Console.WriteLine("Всього сертифікатів: " + certs.certIds.Count);
            foreach (var certId in certs.certIds)
            {
                Console.WriteLine("-------------------------------------------------------------------------------------------------");
                printShortCertInfo((string)certId);
            }
        }

        static void Help()
        {
            Console.WriteLine("new-key      - генерацiя нового ключа та додавання його до існуючого або нового контенер PKCS#12");
            Console.WriteLine("               для згенерованого ключа автоматично формується запит на сертифiкат, згененований ключ");
            Console.WriteLine("               автоматично доступний для подальшої роботи (не потребує виконання select-key)");
            Console.WriteLine("open-storage - відкриття сховища ключів (контенера PKCS#12, PKCS#8, JKS)");
            Console.WriteLine("select-key   - вибiр ключа з контенера PKCS#12, PKCS#8, JKS");
            Console.WriteLine("sign-cms     - пiдписати файл на вибраному ключi");
            Console.WriteLine("verify-cms   - перевiрити пiдпис");
            Console.WriteLine("verify-cert  - перевiрити сертифiкат");
            Console.WriteLine("get-csr      - формування запиту на сертифiкат для вибраного ключа");
            Console.WriteLine("certs-list   - перелік сертифікатів у кешу");
        }

        static void Main(string[] args)
        {
            Console.WriteLine("Тест бiблiотеки UAPKI");
            switch (Environment.OSVersion.Platform)
            {
                case PlatformID.Win32NT:
                    Console.InputEncoding = System.Text.Encoding.Unicode;
                    Console.OutputEncoding = System.Text.Encoding.UTF8;
                    break;
                case PlatformID.Unix:
                    Console.InputEncoding = System.Text.Encoding.UTF8;
                    Console.OutputEncoding = System.Text.Encoding.UTF8;
                    break;
            }

            string dir_data = "";
            if (args.Length > 0)
            {
                dir_data = args[0];
            }

            var version = Uapki.Version();
            var result = Uapki.Init(dir_data + "certs/", dir_data + "certs/crls/", "http://acskidd.gov.ua/services/tsp/", null);
            Console.WriteLine("Бiблiотку iнiцiалiзовано. Завантажено в кеш " + result.certCache.countCerts + " сертифiкатiв. Версiя: " + version);

            providersList = Uapki.Providers().providers;
            if (providersList != null && providersList.Count > 0)
            {
                string s = "Перелік завантажених провайдерів сховищ ключів:\n";
                for (int i = 0; i < providersList.Count; i++)
                {
                    s += (i + 1).ToString() + ": " + providersList[i].id + "\n";
                }
                Console.WriteLine(s);
            }

            while (true)
            {
                Console.WriteLine("\n=================================================================================================");
                Console.WriteLine("Введiть команду <new-key, get-csr, open-storage, select-key, sign, verify, verify-cert, ");
                Console.WriteLine("                 certs-list, help, exit> та натиснiть Enter");
                Console.Write("> ");
                string cmd = Console.ReadLine().ToLower();
                if (cmd == "exit") break;

                switch (cmd)
                {
                    case "open-storage": { StorageOpen(); continue; }
                    case "new-key": { KeyGenerate(); continue; }
                    case "select-key": { KeySelect(); continue; }
                    case "sign": { SignCms(); continue; }
                    case "verify": { VerifyCms(); continue; }
                    case "verify-cert": { CertVerify(); continue; }
                    case "get-csr": { GetCsr(); continue; }
                    case "certs-list": { CertsList(); continue; }
                    case "help": { Help(); continue; }
                }
                Console.WriteLine("Помилка: невiдома команда");
            }

            Uapki.Deinit();
        }
    }
}
