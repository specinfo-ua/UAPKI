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

#define FILE_MARKER "common/pkix/iconv-utils.c"

#include "iconv-utils.h"
#include "uapkif.h"
#include "macros-internal.h"

char* utf8_to_cp1251(const char * utf8_str)
{
    if (utf8_str == NULL) return NULL;

    size_t len = strlen(utf8_str);
    /* Рядок CP1251 завжди коротший або рівний UTF-8 за байтами */
    char* cp1251_str = (char*)malloc(len + 1);
    if (cp1251_str == NULL) return NULL;

    size_t i = 0;
    size_t j = 0;

    while (utf8_str[i] != '\0') {
        unsigned char c1 = (unsigned char)utf8_str[i];

        /* 1-байтний символ (ASCII) */
        if (c1 < 0x80) {
            cp1251_str[j++] = (char)c1;
            i++;
        }
        /* 2-байтний символ (Кирилиця) */
        else if ((c1 & 0xE0) == 0xC0) {
            unsigned char c2 = (unsigned char)utf8_str[i + 1];

            /* Перевірка: продовжний байт має бути виду 10xxxxxx,
             * а також не може бути нульовим (кінець C-рядка) */
            if ((c2 & 0xC0) != 0x80) { free(cp1251_str); return NULL; }

            /* Обчислюємо Unicode codepoint */
            unsigned int unicode = ((c1 & 0x1F) << 6) | (c2 & 0x3F);

            /* Основний блок кирилиці (А–Я, а–я): U+0410 – U+044F */
            if (unicode >= 0x0410 && unicode <= 0x044F) {
                cp1251_str[j++] = (char)(unicode - 0x0410 + 0xC0);
            }
            /* Українські та спецсимволи */
            else {
                switch (unicode) {
                    case 0x0404: cp1251_str[j++] = (char)0xAA; break; /* Є */
                    case 0x0454: cp1251_str[j++] = (char)0xBA; break; /* є */
                    case 0x0406: cp1251_str[j++] = (char)0xB2; break; /* І */
                    case 0x0456: cp1251_str[j++] = (char)0xB3; break; /* і */
                    case 0x0407: cp1251_str[j++] = (char)0xAF; break; /* Ї */
                    case 0x0457: cp1251_str[j++] = (char)0xBF; break; /* ї */
                    case 0x0490: cp1251_str[j++] = (char)0xA5; break; /* Ґ */
                    case 0x0491: cp1251_str[j++] = (char)0xB4; break; /* ґ */
                    case 0x0401: cp1251_str[j++] = (char)0xA8; break; /* Ё */
                    case 0x0451: cp1251_str[j++] = (char)0xB8; break; /* ё */
                    default:     free(cp1251_str); return NULL; /* Невідомий символ */
                }
            }
            i += 2;
        }
        /* 3-байтні символи (знаки пунктуації тощо) */
        else if ((c1 & 0xF0) == 0xE0) {
            unsigned char c2 = (unsigned char)utf8_str[i + 1];
            unsigned char c3 = (unsigned char)utf8_str[i + 2];

            /* Перевірка продовжних байтів */
            if ((c2 & 0xC0) != 0x80 || (c3 & 0xC0) != 0x80) { free(cp1251_str); return NULL; }

            unsigned int unicode = ((c1 & 0x0F) << 12) | ((c2 & 0x3F) << 6) | (c3 & 0x3F);

            /* Сурогатні codepoint-и (U+D800–U+DFFF) є невалідними в Unicode */
            if (unicode >= 0xD800 && unicode <= 0xDFFF) { free(cp1251_str); return NULL; }

            switch (unicode) {
                case 0x2013: cp1251_str[j++] = (char)0x96; break; /* En dash (–)        */
                case 0x2014: cp1251_str[j++] = (char)0x97; break; /* Em dash (—)         */
                case 0x2018: cp1251_str[j++] = (char)0x91; break; /* Ліва одинарна лапка (') */
                case 0x2019: cp1251_str[j++] = (char)0x92; break; /* Права одинарна лапка / апостроф (') */
                case 0x201C: cp1251_str[j++] = (char)0x93; break; /* Ліва подвійна лапка (")  */
                case 0x201D: cp1251_str[j++] = (char)0x94; break; /* Права подвійна лапка (") */
                case 0x201E: cp1251_str[j++] = (char)0x84; break; /* Лапки-лапки („)     */
                case 0x2116: cp1251_str[j++] = (char)0xB9; break; /* Знак номера (№)     */
                default:     free(cp1251_str); return NULL;
            }
            i += 3;
        }
        /* Інші багатобайтні символи, які не підтримує CP1251 */
        else {
            free(cp1251_str);
            return NULL;
        }
    }

    cp1251_str[j] = '\0';
    return cp1251_str;
}

int utf8_to_utf16be (const char * in, unsigned char ** out, size_t * out_len)
{
    int ret = RET_OK;
    size_t in_len;
    size_t max_out_bytes;
    size_t i = 0; /* Індекс у вхідному рядку `in`    */
    size_t j = 0; /* Індекс у вихідному буфері `buf` */
    unsigned char *buf;

    CHECK_PARAM(in);
    CHECK_PARAM(out);
    CHECK_PARAM(out_len);

    in_len = strlen(in);

    /* Виділяємо буфер із запасом:
     * У найгіршому випадку кожен байт UTF-8 дає 2 байти UTF-16
     * (1 байт ASCII -> 2 байти; 4 байти UTF-8 -> 4 байти UTF-16 — не гірше).
     * +2 байти для нульового термінатора UTF-16 (0x00 0x00). */
    max_out_bytes = (in_len * 2) + 2;
    buf = (unsigned char *)malloc(max_out_bytes);
    if (buf == NULL) {
        SET_ERROR(RET_MEMORY_ALLOC_ERROR);
    }

    while (in[i] != '\0') {
        unsigned char c1 = (unsigned char)in[i];
        unsigned int codepoint = 0;
        int bytes_to_read = 0;
        int b;

        /* Визначаємо довжину UTF-8 символу та початкові біти codepoint */
        if (c1 < 0x80) {
            codepoint = c1;
            bytes_to_read = 1;
        } else if ((c1 & 0xE0) == 0xC0) {
            codepoint = c1 & 0x1F;
            bytes_to_read = 2;
        } else if ((c1 & 0xF0) == 0xE0) {
            codepoint = c1 & 0x0F;
            bytes_to_read = 3;
        } else if ((c1 & 0xF8) == 0xF0) {
            codepoint = c1 & 0x07;
            bytes_to_read = 4;
        } else {
            /* Невалідний початковий байт UTF-8 */
            free(buf);
            SET_ERROR(RET_INVALID_UTF8_STR);
        }

        /* Читаємо та перевіряємо продовжні байти */
        for (b = 1; b < bytes_to_read; b++) {
            unsigned char next_byte = (unsigned char)in[i + b];

            /* Перевірка на передчасний кінець C-рядка або невалідний продовжний байт */
            if (next_byte == '\0' || (next_byte & 0xC0) != 0x80) {
                free(buf);
                SET_ERROR(RET_INVALID_UTF8_STR);
            }
            codepoint = (codepoint << 6) | (next_byte & 0x3F);
        }

        i += bytes_to_read;

        /* Кодування у UTF-16 Big-Endian */
        if (codepoint <= 0xFFFF) {
            /* Сурогатні codepoint-и (U+D800–U+DFFF) є невалідними scalar values */
            if (codepoint >= 0xD800 && codepoint <= 0xDFFF) {
                free(buf);
                SET_ERROR(RET_INVALID_UTF8_STR);
            }
            /* Звичайний символ BMP -> 2 байти */
            buf[j++] = (unsigned char)((codepoint >> 8) & 0xFF);
            buf[j++] = (unsigned char)(codepoint & 0xFF);
        } else if (codepoint <= 0x10FFFF) {
            unsigned int high_surrogate;
            unsigned int low_surrogate;

            /* Символ поза BMP -> сурогатна пара, 4 байти */
            codepoint -= 0x10000;
            high_surrogate = 0xD800 + (codepoint >> 10);
            low_surrogate  = 0xDC00 + (codepoint & 0x3FF);

            buf[j++] = (unsigned char)((high_surrogate >> 8) & 0xFF);
            buf[j++] = (unsigned char)(high_surrogate & 0xFF);
            buf[j++] = (unsigned char)((low_surrogate >> 8) & 0xFF);
            buf[j++] = (unsigned char)(low_surrogate & 0xFF);
        } else {
            /* Codepoint за межами Unicode */
            free(buf);
            SET_ERROR(RET_INVALID_UTF8_STR);
        }
    }

    /* Нульовий термінатор UTF-16 */
    buf[j++] = 0x00;
    buf[j++] = 0x00;

    *out     = buf;
    *out_len = j - 2; /* Довжина корисних даних у байтах (без термінатора) */

cleanup:
    return ret;
}   /*  utf8_to_utf16be */

int utf16be_to_utf8 (const unsigned char * in, size_t in_len, char ** out)
{
    int ret = RET_OK;
    size_t max_out_bytes;
    size_t i = 0; /* Індекс у вхідному буфері `in`   */
    size_t j = 0; /* Індекс у вихідному рядку `buf`  */
    char *buf;

    CHECK_PARAM(in);
    CHECK_PARAM(out);

    if (in_len % 2 != 0) {
        SET_ERROR(RET_INVALID_PARAM); /* Довжина UTF-16 буфера має бути парною */
    }

    /* Виділяємо буфер із запасом:
     * У найгіршому випадку 2 байти UTF-16 (BMP) -> 3 байти UTF-8.
     * Сурогатна пара (4 байти UTF-16) -> 4 байти UTF-8 — не гірше.
     * +1 байт для термінатора '\0'. */
    max_out_bytes = (in_len / 2) * 3 + 1;
    buf = (char *)malloc(max_out_bytes);
    if (buf == NULL) {
        SET_ERROR(RET_MEMORY_ALLOC_ERROR);
    }

    while (i < in_len) {
        /* Збираємо перше 16-бітне слово з Big-Endian;
         * явне приведення до unsigned int перед зсувом захищає від UB
         * на платформах з 16-бітним int */
        unsigned int w1 = ((unsigned int)in[i] << 8) | (unsigned int)in[i + 1];
        unsigned int codepoint = w1;
        i += 2;

        /* High Surrogate (U+D800–U+DBFF) — початок сурогатної пари */
        if (w1 >= 0xD800 && w1 <= 0xDBFF) {
            unsigned int w2;

            if (i >= in_len) {
                free(buf);
                SET_ERROR(RET_INVALID_PARAM); /* Обірвана сурогатна пара */
            }

            w2 = ((unsigned int)in[i] << 8) | (unsigned int)in[i + 1];
            if (w2 < 0xDC00 || w2 > 0xDFFF) {
                free(buf);
                SET_ERROR(RET_INVALID_PARAM); /* Невалідний Low Surrogate */
            }
            i += 2;

            codepoint = (((w1 - 0xD800) << 10) | (w2 - 0xDC00)) + 0x10000;
        }
        /* Одинокий Low Surrogate (U+DC00–U+DFFF) — помилка структури */
        else if (w1 >= 0xDC00 && w1 <= 0xDFFF) {
            free(buf);
            SET_ERROR(RET_INVALID_PARAM);
        }

        /* Кодування Unicode codepoint у UTF-8 */
        if (codepoint <= 0x7F) {
            /* 1 байт (ASCII) */
            buf[j++] = (char)codepoint;
        } else if (codepoint <= 0x7FF) {
            /* 2 байти */
            buf[j++] = (char)(0xC0 | ((codepoint >> 6) & 0x1F));
            buf[j++] = (char)(0x80 | (codepoint & 0x3F));
        } else if (codepoint <= 0xFFFF) {
            /* 3 байти */
            buf[j++] = (char)(0xE0 | ((codepoint >> 12) & 0x0F));
            buf[j++] = (char)(0x80 | ((codepoint >> 6) & 0x3F));
            buf[j++] = (char)(0x80 | (codepoint & 0x3F));
        } else if (codepoint <= 0x10FFFF) {
            /* 4 байти (Supplementary Planes) */
            buf[j++] = (char)(0xF0 | ((codepoint >> 18) & 0x07));
            buf[j++] = (char)(0x80 | ((codepoint >> 12) & 0x3F));
            buf[j++] = (char)(0x80 | ((codepoint >> 6) & 0x3F));
            buf[j++] = (char)(0x80 | (codepoint & 0x3F));
        } else {
            free(buf);
            SET_ERROR(RET_INVALID_PARAM); /* Некоректний codepoint */
        }
    }

    buf[j] = '\0';
    *out = buf;

cleanup:
    return ret;
}   /*  utf16be_to_utf8 */
