
// CryptLib Project

/* CryptLib library for RusRoute firewall and other projects of
 * Andrey A. Moiseenko / IE Moiseenko A.A. (Russia)
 * e-mail: support@maasoftware.ru, maa2002@mail.ru
 * web: http://maasoftware.ru, http://maasoftware.com, http://maasoft.ru, http://maasoft.org
 * Author's full name: Andrey Alekseevitch Moiseenko
 * (russian name: Моисеенко Андрей Алексеевич)
 */

 // CryptLib/Kuzhechik_MAA.cpp

 /* Copyright (C) 2002-2024 Andrey A. Moiseenko (support@maasoftware.ru)
  * All rights reserved.
  *
  * This library contains the basic cryptography function,
  * prime numbers checks and generator, random number generator,
  * Mantgomery exponent, symmetric GOST and asymmetric RSA-like.
  * This file is GOST chiper implementation given from
  * the book Bruce Schneier "Applied Cryptography" with changes of
  * Andrey A. Moiseenko (support@maasoftware.ru).
  * This library and applications are
  * FREE FOR COMMERCIAL AND NON-COMMERCIAL USE
  * as long as the following conditions are aheared to.
  *
  * Copyright remains Andrey A. Moiseenko, and as such any Copyright notices in
  * the code are not to be removed.  If this code is used in a product,
  * Andrey A. Moiseenko should be given attribution as the author of the parts used.
  * This can be in the form of a textual message at program startup or
  * in documentation (online or textual) provided with the package.
  *
  * Redistribution and use in source and binary forms, with or without
  * modification, are permitted provided that the following conditions
  * are met:
  * 1. Redistributions of source code must retain the copyright
  *    notice, this list of conditions and the following disclaimer.
  * 2. Redistributions in binary form must reproduce the above copyright
  *    notice, this list of conditions and the following disclaimer in the
  *    documentation and/or other materials provided with the distribution.
  * 3. All advertising materials mentioning features or use of this software
  *    must display the following acknowledgement:
  *    This product includes software developed by Andrey A. Moiseenko (support@maasoftware.ru)
  *
  * THIS SOFTWARE IS PROVIDED BY ANDREY A. MOISEENKO ``AS IS'' AND
  * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
  * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
  * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
  * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
  * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
  * SUCH DAMAGE.
  *
  * The licence and distribution terms for any publically available version or
  * derivative of this code cannot be changed.  i.e. this code cannot simply be
  * copied and put under another distribution licence
  * [including the GNU Public Licence.]
  */

#include "stdafx.h"
  //#include "perm.h"
#include "temp.h"

//#define KUZNECHIK_DEBUG
#define KUZNECHIK_BYTE_S // no g++ bug

//#include <stdio.h>

// unsigned char, uint64_t
//#include <stdint.h>
// memcpy
//#include <string.h>

// https://rekovalev.site/kuznechik-crypto/
// git clone https://git.rekovalev.site/Crypto/C_Kuznechik_GOST_R_34.12-2015.git
//
// mod by MAA
//

// Таблица прямого нелинейного преобразования согластно ГОСТ 34.12-2015
const unsigned char CChipherKuznechik::Pi[256] =
{
    0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
    0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA, 0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,
    0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21, 0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F,
    0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0, 0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F,
    0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB, 0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC,
    0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12, 0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87,
    0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7, 0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1,
    0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E, 0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57,
    0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9, 0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,
    0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC, 0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A,
    0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44, 0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41,
    0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F, 0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B,
    0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7, 0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89,
    0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE, 0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61,
    0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B, 0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52,
    0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0, 0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6
};

// Таблица обратного нелинейного преобразования
//unsigned char CChipherKuznechik::Pi_reverse[256] = {};
const unsigned char CChipherKuznechik::Pi_reverse[256] = 
{
    0xA5, 0x2D, 0x32, 0x8F, 0x0E, 0x30, 0x38, 0xC0, 0x54, 0xE6, 0x9E, 0x39, 0x55, 0x7E, 0x52, 0x91,
    0x64, 0x03, 0x57, 0x5A, 0x1C, 0x60, 0x07, 0x18, 0x21, 0x72, 0xA8, 0xD1, 0x29, 0xC6, 0xA4, 0x3F,
    0xE0, 0x27, 0x8D, 0x0C, 0x82, 0xEA, 0xAE, 0xB4, 0x9A, 0x63, 0x49, 0xE5, 0x42, 0xE4, 0x15, 0xB7,
    0xC8, 0x06, 0x70, 0x9D, 0x41, 0x75, 0x19, 0xC9, 0xAA, 0xFC, 0x4D, 0xBF, 0x2A, 0x73, 0x84, 0xD5,
    0xC3, 0xAF, 0x2B, 0x86, 0xA7, 0xB1, 0xB2, 0x5B, 0x46, 0xD3, 0x9F, 0xFD, 0xD4, 0x0F, 0x9C, 0x2F,
    0x9B, 0x43, 0xEF, 0xD9, 0x79, 0xB6, 0x53, 0x7F, 0xC1, 0xF0, 0x23, 0xE7, 0x25, 0x5E, 0xB5, 0x1E,
    0xA2, 0xDF, 0xA6, 0xFE, 0xAC, 0x22, 0xF9, 0xE2, 0x4A, 0xBC, 0x35, 0xCA, 0xEE, 0x78, 0x05, 0x6B,
    0x51, 0xE1, 0x59, 0xA3, 0xF2, 0x71, 0x56, 0x11, 0x6A, 0x89, 0x94, 0x65, 0x8C, 0xBB, 0x77, 0x3C,
    0x7B, 0x28, 0xAB, 0xD2, 0x31, 0xDE, 0xC4, 0x5F, 0xCC, 0xCF, 0x76, 0x2C, 0xB8, 0xD8, 0x2E, 0x36,
    0xDB, 0x69, 0xB3, 0x14, 0x95, 0xBE, 0x62, 0xA1, 0x3B, 0x16, 0x66, 0xE9, 0x5C, 0x6C, 0x6D, 0xAD,
    0x37, 0x61, 0x4B, 0xB9, 0xE3, 0xBA, 0xF1, 0xA0, 0x85, 0x83, 0xDA, 0x47, 0xC5, 0xB0, 0x33, 0xFA,
    0x96, 0x6F, 0x6E, 0xC2, 0xF6, 0x50, 0xFF, 0x5D, 0xA9, 0x8E, 0x17, 0x1B, 0x97, 0x7D, 0xEC, 0x58,
    0xF7, 0x1F, 0xFB, 0x7C, 0x09, 0x0D, 0x7A, 0x67, 0x45, 0x87, 0xDC, 0xE8, 0x4F, 0x1D, 0x4E, 0x04,
    0xEB, 0xF8, 0xF3, 0x3E, 0x3D, 0xBD, 0x8A, 0x88, 0xDD, 0xCD, 0x0B, 0x13, 0x98, 0x02, 0x93, 0x80,
    0x90, 0xD0, 0x24, 0x34, 0xCB, 0xED, 0xF4, 0xCE, 0x99, 0x10, 0x44, 0x40, 0x92, 0x3A, 0x01, 0x26,
    0x12, 0x1A, 0x48, 0x68, 0xF5, 0x81, 0x8B, 0xC7, 0xD6, 0x20, 0x0A, 0x08, 0x00, 0x4C, 0xD7, 0x74
};

unsigned short * CChipherKuznechik::Pi2 = nullptr;
unsigned short * CChipherKuznechik::Pi2_reverse = nullptr;

// Вектор линейного преобразования
const unsigned char CChipherKuznechik::linear_vector[16] =
{
    0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB,
    0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94, 0x01
};

const unsigned char CChipherKuznechik::StaticKey[32] =
{
    0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
    0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef
};

CChipherKuznechik::CChipherKuznechik() noexcept
{
#ifdef  KUZNECHIK_DEBUG
    printf("%d %d\n", (int)sizeof(round_keys), 20 * (int)sizeof(_uqword));
#endif
    ClearRoundKeys();
    CreateTables();
}

CChipherKuznechik::~CChipherKuznechik()
{
    ClearRoundKeys();
}

void CChipherKuznechik::ClearRoundKeys() noexcept
{
    for (int i = 0; i < 10; i++)
    {
        round_keys[i].Zero();
    }
}

void CChipherKuznechik::CreateTables() noexcept
{
#ifndef KUZNECHIK_BYTE_S
    if (!Pi_reverse[0xff])
    {
        for (int i = 0; i < 0x100; i++)
        {
            Pi_reverse[Pi[i]] = i;
        }
        int j = 0;
        for (int i = 0; i < 0x100; i++)
        {
            if (!Pi_reverse[i])
            {
                j++;
            }
        }
        if (j != 1)
        {
            //printf("j = %d\n", j);
            exit(102);
        }
    }
    if (!Pi2)
    {
        unsigned short * p = new unsigned short[0x10000];
        if (!p)
        {
            exit(102);
        }
        memset(p, 0, 0x10000 * sizeof(unsigned short));
        Pi2 = p;
    }
    if (!Pi2_reverse)
    {
        unsigned short * p = new unsigned short[0x10000];
        if (!p)
        {
            exit(102);
        }
        memset(p, 0, 0x10000 * sizeof(unsigned short));
        Pi2_reverse = p;
    }
    if (!Pi2[0xffff])
    {
        for (int i = 0; i < 0x10000; i++)
        {
#ifdef TOOLSLIB_LITTLE_ENDIAN
            Pi2[i] = (unsigned short)((((unsigned short)Pi[i >> 8]) << 8) | Pi[i & 0xff]);
#else
            Pi2[i] = (unsigned short)(((unsigned short)Pi[i & 0xff] << 8) | Pi[i >> 8]);
#endif
        }
    }
    if (!Pi2_reverse[0xffff])
    {
        for (int i = 0; i < 0x10000; i++)
        {
#ifdef TOOLSLIB_LITTLE_ENDIAN
            Pi2_reverse[i] = (unsigned short)((((unsigned short)Pi_reverse[i >> 8]) << 8) | Pi_reverse[i & 0xff]);
#else
            Pi2_reverse[i] = (unsigned short)(((unsigned short)Pi_reverse[i & 0xff] << 8) | Pi_reverse[i >> 8]);
#endif
        }
    }
#endif
}

// Функция S
void CChipherKuznechik::S(_uqword* in_out) noexcept
{
#ifdef KUZNECHIK_BYTE_S
    // Переход к представлению в байтах
    unsigned char *b = (unsigned char*)in_out;
    for (int i = 0; i < KUZNECHIK_BLOCK_SIZE; i++)
    {
        b[i] = Pi[b[i]];
    }
#else
    // Переход к представлению в байтах
    unsigned short *w = (unsigned short*)in_out;
    for (int i = 0; i < KUZNECHIK_BLOCK_SIZE / 2; i++)
    {
        w[i] = Pi2[(unsigned)w[i]];
    }
#endif
}

//#define tst1 //  // g++ (Debian 12.2.0-14) 12.2.0 -O3 not -lto have a bug if tst1 not defined and print_chunk(***) is not exists in the tail
// Обратная функция S
void CChipherKuznechik::S_reverse(_uqword* in_out) noexcept
{
#ifdef KUZNECHIK_BYTE_S
    // no gcc bug
    // Переход к представлению в байтах
    unsigned char *b = (unsigned char*)in_out;
    for (int i = 0; i < KUZNECHIK_BLOCK_SIZE; i++)
    {
        b[i] = Pi_reverse[b[i]];
    }
#else
#ifdef tst1
    // Переход к представлению в байтах
    unsigned char b16[KUZNECHIK_BLOCK_SIZE];
    unsigned char *b = (unsigned char*)in_out;
    for (int i = 0; i < KUZNECHIK_BLOCK_SIZE; i++)
    {
        b16[i] = Pi_reverse[b[i]];
    }
#endif
    // Переход к представлению в байтах
    unsigned short *w = (unsigned short*)in_out;
    for (int i = 0; i < KUZNECHIK_BLOCK_SIZE / 2; i++)
    {
#ifdef tst1
        unsigned short ww = w[i];
#endif
        w[i] = Pi2_reverse[(unsigned)w[i]];
#ifdef tst1
        if (((unsigned short*)b16)[i] != w[i])
        {
            printf("[%04x] = %04x , != %04x\n", ww, w[i], ((unsigned short*)b16)[i]);
        }
#else
        // gcc bug
#endif
    }
#endif
    //print_chunk(b16);
    //print_chunk(in_out);
}

// Функция умножения в поле Галуа
unsigned char CChipherKuznechik::GF_mult(unsigned char a, unsigned char b) noexcept
{    
    unsigned char c = 0;

    while (b) 
    {        
        if ((b & 1))
        {
            c ^= a;
        }
        a = (a & 0x80) ? (a << 1) ^ 0xC3 : (a << 1);
        b >>= 1;
    }
        
    return c;
}

// Функция R
void CChipherKuznechik::R(unsigned char *in_out) noexcept
{
    // Аккумулятор
    unsigned char acc = in_out[15];
    // Переход к представлению в байтах
    unsigned char *b = (unsigned char*)in_out;
    for (int i = 14; i >= 0; i--) 
    {
        b[i + 1] = b[i];
        acc ^= GF_mult(b[i], linear_vector[i]);
    }
    b[0] = acc;
}

// Обратная функция R
void CChipherKuznechik::R_reverse(unsigned char *in_out) noexcept
{
    // Аккумулятор
    unsigned char acc = in_out[0];
    // Переход к представлению в байтах
    unsigned char *b = (unsigned char*)in_out;

    for (int i = 0; i < 15; i++) 
    {
        b[i] = b[i + 1];
        acc ^= GF_mult(b[i], linear_vector[i]);
    }

    b[15] = acc;
}

// Функция L
void CChipherKuznechik::L(unsigned char* in_out) noexcept
{
    for (int i = 0; i < KUZNECHIK_BLOCK_SIZE; i++)
    {
        R(in_out);
    }
}

// Обратная функция L
void CChipherKuznechik::L_reverse(unsigned char *in_out) noexcept
{
    for (int i = 0; i < KUZNECHIK_BLOCK_SIZE; i++)
    {
        R_reverse(in_out);
    }
}

// Генерация итерационных ключей
void CChipherKuznechik::gen_round_keys(const unsigned char* key, chunk* round_keys) noexcept
{
    // Счетчик
    int i;

    // Константы
    unsigned char cs[32][KUZNECHIK_BLOCK_SIZE] = {};

    // Генерация констант с помощью L-преобразования номера итерации
    for (i = 0; i < 32; i++) 
    {
        cs[i][15] = i + 1;
        L(cs[i]);
    }

    // Итерационные ключи (четный и нечетный)
    chunk ks[2] = {false, false};
    // Разместим ключ шифрования
    // результат = итерационный ключ = (преобразование к указателю на чанк)[номер чанка][часть чанка]
    round_keys[0][0] = ks[0][0] = ((const _uqword*)key)[0];
    round_keys[0][1] = ks[0][1] = ((const _uqword*)key)[1];
    round_keys[1][0] = ks[1][0] = ((const _uqword*)key)[2];
    round_keys[1][1] = ks[1][1] = ((const _uqword*)key)[3];

    // Генерация оставшихся ключей с использованием констант
    for (i = 1; i <= 32; i++) 
    {
        // Новый ключ
        chunk new_key = {false};

        // Преобразование X
        X(ks[0], (const _uqword*)cs[i - 1], new_key);
        // Преобразование S
        S(new_key);
        // Преобразование L
        L((unsigned char*)new_key);
        // Преобразование X
        X(new_key, ks[1], new_key);

        // Сдвигаем ключи
        ks[1] = ks[0];
        // Записываем новый ключ
        ks[0] = new_key;

        // Каждую 8 итерацию сети Фейстеля за исключением нулевой запишем ключи
        if ((i > 0) && (i % 8 == 0)) 
        {
            round_keys[(i >> 2)] = ks[0];
            round_keys[(i >> 2) + 1] = ks[1];
        }
    }
}

// Функция шифрования
// Поддерживает запись результата в исходный массив
void CChipherKuznechik::kuznechik_encrypt128(const chunk* round_keys, _uqword* p) noexcept
{
    // В течении 10 итераций
    for (int i = 0; i <= 8; i++)
    {
        // Преобразование X
        X(p, round_keys[i], p);
        // Преобразование S
        S(p);
        // Преобразование L
        L((unsigned char*)p);
    }
    // Преобразование X
    X(p, round_keys[9], p);
}

void CChipherKuznechik::kuznechik_decrypt128(const chunk* round_keys, _uqword* p) noexcept
{
    // Преобразование X
    X(p, round_keys[9], p);
    for (int i = 8; i >= 0; i--)
    {
        // Преобразование L
        L_reverse((unsigned char*)p);
        // Преобразование S
        S_reverse(p);
        // Преобразование X
        X(p, round_keys[i], p);
    }
}

// Функция шифрования
// Поддерживает запись результата в исходный массив
void CChipherKuznechik::kuznechik_encrypt(const chunk* round_keys, const _uqword* in, _uqword* out) noexcept
{
    // Буфер
    _uqword p[2];
    // Создадим копию входных данных
    p[0] = in[0];   //memcpy(p, in, sizeof(chunk));
    p[1] = in[1];

    kuznechik_encrypt128(round_keys, p);

    // Копируем полученный результат
    out[0] = p[0];  //memcpy(out, p, sizeof(chunk));
    out[1] = p[1];
}

void CChipherKuznechik::kuznechik_decrypt(const chunk* round_keys, const _uqword* in, _uqword* out) noexcept
{
    // Буфер
    _uqword p[2];
    // Создадим копию входных данных
    p[0] = in[0];   //memcpy(p, in, sizeof(chunk));
    p[1] = in[1];

    kuznechik_decrypt128(round_keys, p);

    // Копируем полученный результат
    out[0] = p[0];  //memcpy(out, p, sizeof(chunk));
    out[1] = p[1];
}

// Печать чанка
void CChipherKuznechik::print_chunk(const void* p) noexcept
{
    for (int i = 0; i < KUZNECHIK_BLOCK_SIZE; i++)
    {
        printf("0x%02X ", ((unsigned char*)p)[i]);
    }
    printf("\n");
}

void CChipherKuznechik::SetKey(const unsigned char* key) noexcept
{
    // Генерация итерационных ключей
    gen_round_keys(key ? key : StaticKey, round_keys);

#ifdef KUZNECHIK_DEBUG
    // Вывод итерационных ключей
    printf("Итерационные ключи:\n");
    for (int i = 0; i < 10; i++)
        print_chunk((const unsigned char*)round_keys[i]);
#endif
}

#if 1
void CChipherKuznechik::Encrypt1(const unsigned char* pIn, size_t Size, unsigned char* pOut) const noexcept
{
    while (Size >= KUZNECHIK_BLOCK_SIZE)
    {
        // Шифрование
        kuznechik_encrypt(round_keys, (const _uqword*)pIn, (_uqword*)pOut);

#ifdef KUZNECHIK_DEBUG
        // Вывод зашифрованных данных
        printf("Зашифрованные данные:\n");
        print_chunk(pOut);
#endif
        pIn += KUZNECHIK_BLOCK_SIZE;
        pOut += KUZNECHIK_BLOCK_SIZE;
        Size -= KUZNECHIK_BLOCK_SIZE;
    }
#if 0
    if (Size)
    {
        //Size = KUZNECHIK_BLOCK_SIZE;
        uint64_t t[2] = { 0,0 }, t2[2] = { 0,0 };
        memcpy(t, pIn, Size);
        // Шифрование
        kuznechik_encrypt(round_keys, t, t2);
#ifdef KUZNECHIK_DEBUG
        // Вывод зашифрованных данных
        printf("Зашифрованные данные:\n");
        print_chunk(t2);
#endif
        memcpy(pOut, t2, Size);
    }
#endif
}

void CChipherKuznechik::Decrypt1(const unsigned char* pIn, size_t Size, unsigned char* pOut) const noexcept
{
    while (Size >= KUZNECHIK_BLOCK_SIZE)
    {
        // Расшифровка
        kuznechik_decrypt(round_keys, (const _uqword*)pIn, (_uqword*)pOut);

#ifdef KUZNECHIK_DEBUG
        // Вывод зашифрованных данных
        printf("Расшифрованные данные:\n");
        print_chunk(pOut);
#endif
        pIn += KUZNECHIK_BLOCK_SIZE;
        pOut += KUZNECHIK_BLOCK_SIZE;
        Size -= KUZNECHIK_BLOCK_SIZE;
    }
#if 0
    if (Size)
    {
        //Size = KUZNECHIK_BLOCK_SIZE;
        uint64_t t[2] = { 0,0 }, t2[2] = { 0,0 };
        memcpy(t, pIn, Size);
        // Шифрование
        kuznechik_decrypt(round_keys, t, t2);
#ifdef KUZNECHIK_DEBUG
        // Вывод зашифрованных данных
        printf("Расшифрованные данные:\n");
        print_chunk(t2);
#endif
        memcpy(pOut, t2, Size);
    }
#endif
}
#endif

void CChipherKuznechik::Encrypt(const void* pIn_, size_t Size, const void* Salt, void* pOut_, void* OutSalt) const noexcept
{
/*
    Key = Key ? Key : (const _dword*)StaticKey;
#ifdef BIG_ENDIAN_ALGO
    _dword hKey[8];
    for (int j = 0; j < 8; j++)
    {
        hKey[j] = be_bswap32(Key[j]);
    }
    Key = hKey;
#endif
*/
    const _uqword* pIn = (_uqword*)pIn_;
    _uqword* pOut = pOut_ ? (_uqword*)pOut_ : (_uqword*)pIn_;
#ifdef BIG_ENDIAN_ALGO
    _uqword n12[2] = { be_bswap64(*(_uqword*)Salt), be_bswap64(*(1 + (_uqword*)Salt)) };
#else
    _uqword n12[2] = { *(_uqword*)Salt, *(1 + (_uqword*)Salt) };
#endif

    for (size_t i = (Size >> 4); i--; )
    {
        kuznechik_encrypt128(round_keys, n12);

#ifdef BIG_ENDIAN_ALGO
        *pOut++ = be_bswap64(n12[0] ^= be_bswap64(*pIn++));
        *pOut++ = be_bswap64(n12[1] ^= be_bswap64(*pIn++));
#else
        *pOut++ = (n12[0] ^= *pIn++);
        *pOut++ = (n12[1] ^= *pIn++);
#endif
    }
    if (Size & 0xf)
    {
        _uqword t[2] = { 0, 0 };
        memcpy(t, pIn, Size & 0xf);
        kuznechik_encrypt128(round_keys, n12);
#ifdef BIG_ENDIAN_ALGO
        n12[0] ^= be_bswap64(t[0]);
        n12[1] ^= be_bswap64(t[1]);
#else
        n12[0] ^= t[0];
        n12[1] ^= t[1];
#endif
        memcpy(pOut, n12, Size & 0xf);
        t[1] = t[0] = 0;
    }
    if (OutSalt)
    {
#ifdef BIG_ENDIAN_ALGO
        * (_uqword*)OutSalt = be_bswap64(n12[0]);
        *(1 + (_uqword*)OutSalt) = be_bswap64(n12[1]);
#else
        *(_uqword*)OutSalt = n12[0];
        *(1 + (_uqword*)OutSalt) = n12[1];
#endif
    }
/*
#ifdef BIG_ENDIAN_ALGO
    for (int j = 0; j < 8; j++)
    {
        hKey[j] = 0;
    }
#endif
*/
}

void CChipherKuznechik::Decrypt(const void* pIn_, size_t Size, const void* Salt, void* pOut_, void* OutSalt) const noexcept
{
/*
    Key = Key ? Key : (const _dword*)StaticKey;
#ifdef BIG_ENDIAN_ALGO
    _dword hKey[8];
    for (int j = 0; j < 8; j++)
    {
        hKey[j] = be_bswap32(Key[j]);
    }
    Key = hKey;
#endif
*/
    const _uqword* pIn = (_uqword*)pIn_;
    _uqword* pOut = pOut_ ? (_uqword*)pOut_ : (_uqword*)pIn_;
#ifdef BIG_ENDIAN_ALGO
    _uqword n12[2] = { be_bswap64(*(_uqword*)Salt), be_bswap64(*(1 + (_uqword*)Salt)) };
#else
    _uqword n12[2] = { *(_uqword*)Salt, *(1 + (_uqword*)Salt) };
#endif
    _uqword N12[2];

    for (size_t i = (Size >> 4); i--; )
    {
        kuznechik_encrypt128(round_keys, n12);

#ifdef BIG_ENDIAN_ALGO
        *pOut++ = be_bswap64(n12[0] ^ (N12[0] = be_bswap64(*pIn++)));
        *pOut++ = be_bswap64(n12[1] ^ (N12[1] = be_bswap64(*pIn++)));
#else
        *pOut++ = n12[0] ^ (N12[0] = *pIn++);
        *pOut++ = n12[1] ^ (N12[1] = *pIn++);
#endif

        n12[0] = N12[0];
        n12[1] = N12[1];
    }
    if (Size & 0xf)
    {
        _uqword t[2] = { 0, 0 };
        memcpy(t, pIn, Size & 0xf);
        kuznechik_encrypt128(round_keys, n12);
#ifdef BIG_ENDIAN_ALGO
        t[0] = be_bswap64(n12[0] ^ (N12[0] = be_bswap64(t[0])));
        t[1] = be_bswap64(n12[1] ^ (N12[1] = be_bswap64(t[1])));
#else
        t[0] = n12[0] ^ (N12[0] = t[0]);
        t[1] = n12[1] ^ (N12[1] = t[1]);
#endif
        n12[0] = N12[0];
        n12[1] = N12[1];
        memcpy(pOut, t, Size & 0xf);
        t[1] = t[0] = 0;
    }
    if (OutSalt)
    {
#ifdef BIG_ENDIAN_ALGO
        * (_uqword*)OutSalt = be_bswap64(n12[0]);
        *(1 + (_uqword*)OutSalt) = be_bswap64(n12[1]);
#else
        * (_uqword*)OutSalt = n12[0];
        *(1 + (_uqword*)OutSalt) = n12[1];
#endif
    }
/*
#ifdef BIG_ENDIAN_ALGO
    for (int j = 0; j < 8; j++)
    {
        hKey[j] = 0;
    }
#endif
*/
}

static int test1() noexcept
{
    printf("\nTest1:\n");

    int nErr = 0;

    // Ключ (256 бит = 32 байт)
    const unsigned char key[32] =
    {
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,  0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
    };

    // Открытые данные
    unsigned char data[KUZNECHIK_BLOCK_SIZE] =
    {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88
    };

    const unsigned char edata[KUZNECHIK_BLOCK_SIZE] =
    {
        0x7F, 0x67, 0x9D, 0x90, 0xBE, 0xBC, 0x24, 0x30, 0x5A, 0x46, 0x8D, 0x42, 0xB9, 0xD4, 0xED, 0xCD
    };

    // Вывод открытых данных
    printf("Ключ:\n");
    CChipherKuznechik::print_chunk(&key[0]);
    CChipherKuznechik::print_chunk(&key[16]);

    // Вывод открытых данных
    printf("Открытые данные:\n");
    CChipherKuznechik::print_chunk(data);

    CChipherKuznechik k;
    k.SetKey(key);

    /*
    printf("S_reverse-данные:\n");
    CChipherKuznechik::S_reverse((_uqword*)Sdata);
    CChipherKuznechik::print_chunk(Sdata);
    */
    /*
    Итерационные ключи:
    0x88 0x99 0xAA 0xBB 0xCC 0xDD 0xEE 0xFF 0x00 0x11 0x22 0x33 0x44 0x55 0x66 0x77
    0xFE 0xDC 0xBA 0x98 0x76 0x54 0x32 0x10 0x01 0x23 0x45 0x67 0x89 0xAB 0xCD 0xEF
    0xDB 0x31 0x48 0x53 0x15 0x69 0x43 0x43 0x22 0x8D 0x6A 0xEF 0x8C 0xC7 0x8C 0x44
    0x3D 0x45 0x53 0xD8 0xE9 0xCF 0xEC 0x68 0x15 0xEB 0xAD 0xC4 0x0A 0x9F 0xFD 0x04
    0x57 0x64 0x64 0x68 0xC4 0x4A 0x5E 0x28 0xD3 0xE5 0x92 0x46 0xF4 0x29 0xF1 0xAC
    0xBD 0x07 0x94 0x35 0x16 0x5C 0x64 0x32 0xB5 0x32 0xE8 0x28 0x34 0xDA 0x58 0x1B
    0x51 0xE6 0x40 0x75 0x7E 0x87 0x45 0xDE 0x70 0x57 0x27 0x26 0x5A 0x00 0x98 0xB1
    0x5A 0x79 0x25 0x01 0x7B 0x9F 0xDD 0x3E 0xD7 0x2A 0x91 0xA2 0x22 0x86 0xF9 0x84
    0xBB 0x44 0xE2 0x53 0x78 0xC7 0x31 0x23 0xA5 0xF3 0x2F 0x73 0xCD 0xB6 0xE5 0x17
    0x72 0xE9 0xDD 0x74 0x16 0xBC 0xF4 0x5B 0x75 0x5D 0xBA 0xA8 0x8E 0x4A 0x40 0x43
    */

    // Зашифрованные данные
    unsigned char encrypted[KUZNECHIK_BLOCK_SIZE] = {};
    k.Encrypt1(data, sizeof(data), encrypted);

    printf("Зашифрованные данные:\n");
    CChipherKuznechik::print_chunk(encrypted);
    bool b = !memcmp(encrypted, edata, sizeof(edata));
    nErr += !b;
    printf("%s\n", b ? "== (ok)" : "!= (fail)");

    // Результат расшифровки
    unsigned char decrypted[KUZNECHIK_BLOCK_SIZE] = {};
    k.Decrypt1((const unsigned char*)encrypted, sizeof(encrypted), decrypted);

    printf("Расшифрованные данные:\n");
    CChipherKuznechik::print_chunk(decrypted);
    b = !memcmp(decrypted, data, sizeof(data));
    nErr += !b;
    printf("%s\n", b ? "== (ok)" : "!= (fail)");

    return nErr;
}

static int test2() noexcept
{
    printf("\nTest2:\n");

    int nErr = 0;

    // Ключ (256 бит = 32 байт)
    const unsigned char key[32] =
    {
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        //0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10, 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef // ключ из test1
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xBA, 0xDC, 0xEF
    };

    // Открытые данные
    unsigned char data[KUZNECHIK_BLOCK_SIZE] =
    {
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11
    };

    const unsigned char edata[KUZNECHIK_BLOCK_SIZE] =
    {
        // 0xE4, 0xBA, 0xC9, 0x66, 0xA4, 0x9C, 0xB8, 0x01, 0xB4, 0xBB, 0xAA, 0xDC, 0x10, 0x57, 0x38, 0x2B // с ключом test1
        0x6C, 0xC6, 0xE9, 0xB4, 0x06, 0x7A, 0x53, 0x47, 0x80, 0xC3, 0x2A, 0xC8, 0xFC, 0xCF, 0x4E, 0x88
    };

    // Вывод открытых данных
    printf("Ключ:\n");
    CChipherKuznechik::print_chunk(&key[0]);
    CChipherKuznechik::print_chunk(&key[16]);

    // Вывод открытых данных
    printf("Открытые данные:\n");
    CChipherKuznechik::print_chunk(data);

    CChipherKuznechik k;
    k.SetKey(key);

    /*
    Итерационные ключи:
    0x88 0x99 0xAA 0xBB 0xCC 0xDD 0xEE 0xFF 0x00 0x11 0x22 0x33 0x44 0x55 0x66 0x77
    0xFE 0xDC 0xBA 0x98 0x76 0x54 0x32 0x10 0x01 0x23 0x45 0x67 0x89 0xBA 0xDC 0xEF
    0x6E 0x1E 0xE1 0xDA 0x18 0x29 0x16 0x5C 0xCA 0xA2 0xA2 0x9F 0xDD 0xCD 0x44 0xD7
    0x0B 0x99 0x15 0x0D 0xB0 0x0D 0x89 0xF0 0x0B 0x89 0x67 0xB5 0xE2 0x84 0x7C 0x32
    0x97 0x1C 0xD2 0x1B 0x99 0x80 0x6C 0xBD 0xFC 0x5F 0x2A 0x11 0x0B 0x90 0xEF 0xB1
    0x11 0xBF 0x81 0xC9 0xE7 0x68 0x57 0x46 0x72 0x55 0xE7 0xF9 0x00 0x8F 0x08 0x52
    0x29 0xC6 0x96 0x86 0x13 0x5C 0x8E 0xAD 0x43 0xAD 0x55 0x4B 0xFB 0xA1 0x18 0xB6
    0x77 0x02 0x07 0x73 0x7E 0x45 0xAC 0x4A 0x80 0x15 0x73 0xA3 0x76 0x88 0x8B 0xE7
    0x27 0xCF 0x3C 0x4A 0x83 0xB8 0x9E 0xF6 0x67 0x96 0x73 0xF2 0x18 0x04 0x86 0xD0
    0xC0 0x92 0x1E 0x46 0x2F 0x8D 0xDF 0x40 0x35 0xEF 0xAE 0x4D 0x8E 0xA3 0x45 0x5B
    */

    // Зашифрованные данные
    unsigned char encrypted[KUZNECHIK_BLOCK_SIZE] = {};
    k.Encrypt1(data, sizeof(data), encrypted);

    printf("Зашифрованные данные:\n");
    CChipherKuznechik::print_chunk(encrypted);
    bool b = !memcmp(encrypted, edata, sizeof(edata));
    nErr += !b;
    printf("%s\n", b ? "== (ok)" : "!= (fail)");

    // Результат расшифровки
    unsigned char decrypted[KUZNECHIK_BLOCK_SIZE] = {};
    k.Decrypt1((const unsigned char*)encrypted, sizeof(encrypted), decrypted);

    printf("Расшифрованные данные:\n");
    CChipherKuznechik::print_chunk(decrypted);
    b = !memcmp(decrypted, data, sizeof(data));
    nErr += !b;
    printf("%s\n", b ? "== (ok)" : "!= (fail)");

    return nErr;
}

static int test3() noexcept
{
    printf("\nTest3:\n");

    int nErr = 0;

    // Ключ (256 бит = 32 байт)
    const unsigned char key[32] =
    {
       0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
       0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE
    };

    // Открытые данные
    unsigned char data[KUZNECHIK_BLOCK_SIZE] =
    {
       0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11
    };

    const unsigned char edata[KUZNECHIK_BLOCK_SIZE] =
    {
       0xDF, 0x4B, 0x25, 0x6B, 0x59, 0xD4, 0x99, 0xA5, 0x52, 0xB7, 0x7E, 0xF7, 0x4C, 0x59, 0x0B, 0x8B
    };

    // Вывод открытых данных
    printf("Ключ:\n");
    CChipherKuznechik::print_chunk(&key[0]);
    CChipherKuznechik::print_chunk(&key[16]);

    // Вывод открытых данных
    printf("Открытые данные:\n");
    CChipherKuznechik::print_chunk(data);

    CChipherKuznechik k;
    k.SetKey(key);

    /*
    Итерационные ключи:
    0x77 0x66 0x55 0x44 0x33 0x22 0x11 0x00 0xFF 0xEE 0xDD 0xCC 0xBB 0xAA 0x99 0x88
    0xEF 0xCD 0xAB 0x89 0x67 0x45 0x23 0x01 0x10 0x32 0x54 0x76 0x98 0xBA 0xDC 0xFE
    0x14 0xC9 0xB7 0xB2 0xB3 0xCA 0x26 0x5D 0xFE 0x64 0x53 0x58 0x47 0x9D 0x10 0x3E
    0xF8 0x21 0xC1 0x62 0x83 0x09 0xAF 0xE1 0xAA 0xF2 0x06 0xF2 0x36 0x9B 0x26 0x6A
    0xC0 0x87 0x03 0x08 0x56 0xD9 0x6C 0xF3 0x43 0x88 0x12 0x61 0x5E 0x1B 0xCC 0x9B
    0x5B 0x86 0x07 0xAC 0xDE 0x79 0x53 0x88 0xE7 0x36 0x17 0x5A 0x9D 0x40 0xF8 0x74
    0xD4 0x51 0xAE 0x46 0xCD 0xBE 0x34 0x2B 0x97 0xFE 0x8A 0x72 0xDB 0xC8 0x48 0x93
    0x78 0x39 0xED 0xCA 0x72 0xCA 0x57 0x9E 0xFE 0x5A 0x64 0xFF 0x03 0xE1 0xDC 0x12
    0xA3 0x5B 0x90 0x35 0x43 0x5E 0x38 0x09 0x46 0x4D 0xED 0x01 0x31 0x77 0xAA 0xAB
    0x0E 0xB4 0x73 0x8D 0x85 0x93 0x91 0x99 0xBE 0xCE 0x10 0x92 0x37 0x31 0x91 0x4C
    */

    // Зашифрованные данные
    unsigned char encrypted[KUZNECHIK_BLOCK_SIZE] = {};
    k.Encrypt1(data, sizeof(data), encrypted);

    printf("Зашифрованные данные:\n");
    CChipherKuznechik::print_chunk(encrypted);
    bool b = !memcmp(encrypted, edata, sizeof(edata));
    nErr += !b;
    printf("%s\n", b ? "== (ok)" : "!= (fail)");

    // Результат расшифровки
    unsigned char decrypted[KUZNECHIK_BLOCK_SIZE] = {};
    k.Decrypt1((const unsigned char*)encrypted, sizeof(encrypted), decrypted);

    printf("Расшифрованные данные:\n");
    CChipherKuznechik::print_chunk(decrypted);
    b = !memcmp(decrypted, data, sizeof(data));
    nErr += !b;
    printf("%s\n", b ? "== (ok)" : "!= (fail)");

    return nErr;
}

int main_kuznechik(int argc, char *argv[])
{
    const int e1 = test1();
    const int e2 = test2();
    const int e3 = test3();
    
    printf("Test1.nErr = %d\n", e1);
    printf("Test2.nErr = %d\n", e2);
    printf("Test3.nErr = %d\n", e3);

    return e1 + e2 + e3;
}
