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

[Serializable]
public class UapkiException : Exception
{
    public int ErrorCode { get; }

    private static string ErrorCodeToString(int error)
    {
        switch(error)
        {
            case 0x1002:
                return "Помилка з'єднання з сервером";
            case 0x1003:
                return "Неправильний формат JSON запиту";
            case 0x1004:
                return "Неправильний метод";
            case 0x1005:
                return "Неправильний параметр";
            case 0x1006:
                return "Неправильний тип сховища ключів";
            case 0x1007:
                return "Потребує ім'я файлу як ідентифікатор сховища ключів";
            case 0x1008:
                return "Потребує ім'я користувача як ідентифікатор сховища ключів";
            case 0x1009:
                return "Бібліотеку не ініціалізовано";
            case 0x100A:
                return "Повторна ініціалізація бібліотеки";
            case 0x100B:
                return "Сховище ключів не відкрито";
            case 0x100C:
                return "Ключ не вибрано";
            case 0x100D:
                return "Ключ не може бути використаний для операції за призначенням";
            case 0x100E:
                return "Непідтримуваний алгоритм";
            case 0x100F:
                return "Неправильний розмір геш-значення";
            case 0x1010:
                return "Неправильний ідентифікатор ключа";
            case 0x1018:
                return "Встановлено режим офлайн";
            case 0x1019:
                return "Сховище ключів не відкрито";
            case 0x101A:
                return "Помилка завантаження бібліотеки роботи зі сховищем ключів";
            case 0x101B:
                return "Функція не підтримється бібліотекою роботи зі сховищем ключів";
            case 0x1020:
                return "Помилка відкриття файлу";
            case 0x1021:
                return "Помилка зчитування файлу";
            case 0x1022:
                return "Помилка запису файлу";
            case 0x1024:
                return "Помилка видалення файлу";
            case 0x1025:
                return "Помилковий статус HTTP протоколу";
            case 0x1030:
                return "Неправильна структура ContentInfo";
            case 0x1031:
                return "Неправильна структура документу";
            case 0x1032:
                return "Неправильна версія структури документу";
            case 0x1033:
                return "Відсутні дані";
            case 0x1034:
                return "Неправильний атрибут";
            case 0x1035:
                return "Відсутній атрибут";
            case 0x1036:
                return "Відсутнє розширення";
            case 0x1037:
                return "Розширення не позначено як критичне";
            case 0x1039:
                return "Неправильне геш-значення";
            case 0x103A:
                return "Ключ користувача не може бути застосований для розшифрування цього файлу";
            case 0x1040:
                return "Помилка завантаження сховища сертифікатів";
            case 0x1041:
                return "Сертифікат не знайдено";
            case 0x1042:
                return "Термін дії сертифікату не настав";
            case 0x1043:
                return "Термін дії сертифікату закінчився";
            case 0x1044:
                return "Сертифікат видавця не знайдено";
            case 0x1045:
                return "Сертифікат відкликано";
            case 0x1046:
                return "Статус сертифікату не визначено";
            case 0x1047:
                return "Кореневий сертифікат не довірений";
            case 0x1050:
                return "Помилка завантаження сховища СВС";
            case 0x1051:
                return "У сертифікаті відсутня точка доступу до СВС";
            case 0x1052:
                return "Помилка завантаження СВС з сервера";
            case 0x1053:
                return "СВС не знайдено";
            case 0x1054:
                return "Термін чинності СВС закінчився";
            case 0x1060:
                return "У сертифікаті відстуня точка доступу OCSP";
            case 0x1061:
                return "Сервер OCSP не відповідає";
            case 0x1062:
                return "Відповідь сервера OCSP не успішна";
            case 0x1063:
                return "Відповідь сервера OCSP пошкоджена";
            case 0x1064:
                return "Відповідь сервера OCSP неправильна";
            case 0x1065:
                return "Відповідь сервера OCSP з неправильним nonce";
            case 0x1066:
                return "Неправильна відповідь сервера OCSP";
            case 0x1070:
                return "У сертифікаті відстуня точка доступу TSP";
            case 0x1071:
                return "Сервер TSP не відповідає";
            case 0x1072:
                return "Відповідь сервера TSP \"не дозволено\"";
            case 0x1073:
                return "Відповідь сервера TSP не співпадає з запитом";
            case 0x1074:
                return "Відповідь сервера TSP пошкоджена";

            case 0x2001:
                return "Неправильна відповідь криптографічної бібліотеки";

            case 0x4001:
                return "Помилка перевірки підпису після підписання";

            case 0x0402:
                return "Неправильний параметр функції, зверніться до розробника";
            case 0x0403:
                return "Бібліотеку роботи зі сховищем ключів не знайдено";
            case 0x0406:
                return "Функція не підтримується бібліотекою роботи зі сховищем ключів";
            case 0x0407:
                return "Параметр не підтримується бібліотекою роботи зі сховищем ключів";
            case 0x0408:
                return "Сховище ключів не відкрито";
            case 0x0409:
                return "Алгоритм не підтримується";
            case 0x040B:
                return "Неправильний пароль або пошкоджений ключ";
            case 0x0411:
                return "Неправильний пароль";
            case 0x0412:
                return "Сховище ключів відкрито тільки для читання";
            case 0x0415:
                return "Сертифікат не знайдено";
            case 0x0416:
                return "Ключ не вибрано";
            case 0x0417:
                return "Алгоритм не підтримується";
            case 0x0423:
                return "Ключ пошкоджено";
            case 0x0429:
                return "Сховище ключів не відкрито";
            case 0x042A:
                return "Помилка сховища ключів";
            case 0x042C:
                return "У сховищі ключів закінчилось вільне місце";
            case 0x042F:
                return "Сховище ключів не знайдено";
            case 0x0436:
                return "Помилка встановлення пароля";
            case 0x0437:
                return "Неправильний сертифікат";
            case 0x0438:
                return "Неправильний ідентифікатор ключа";
        }
        return "Код помилки " + error.ToString("X");
    }

    public UapkiException(int error)
        : base("Помилка криптобібліотеки. " + ErrorCodeToString(error))
    {
        ErrorCode = error;
    }

    public UapkiException(string error)
        : base(error)
    {
        ErrorCode = 0;
    }

    public UapkiException(int error, Exception inner)
        : base("Помилка криптобібліотеки. " + ErrorCodeToString(error), inner)
    {
        ErrorCode = error;
    }

    public UapkiException(string error, Exception inner)
        : base(error, inner)
    {
        ErrorCode = 0;
    }
}
