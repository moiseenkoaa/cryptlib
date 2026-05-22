
// CryptLib Project

/* CryptLib library for RusRoute firewall and other projects of
 * Andrey A. Moiseenko / IE Moiseenko A.A. (Russia)
 * e-mail: support@maasoftware.ru, maa2002@mail.ru
 * web: http://maasoftware.ru, http://maasoftware.com, http://maasoft.ru, http://maasoft.org
 * Author's full name: Andrey Alekseevitch Moiseenko
 * (russian name: Моисеенко Андрей Алексеевич)
 */

 // CryptLib/Kuzhechik_MAA.h

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


//#include <stdio.h>

// uint8_t, uint64_t
//#include <stdint.h>
// memcpy
//#include <string.h>

// https://rekovalev.site/kuznechik-crypto/
// git clone https://git.rekovalev.site/Crypto/C_Kuznechik_GOST_R_34.12-2015.git
//
// mod by MAA
//

// Длинна блока в байтах(16 байт = 128 бит)
#define KUZNECHIK_BLOCK_SIZE 16

class CChipherKuznechik
{
public:
    // Один блок (чанк) задается как массив двух беззнаковых целых по 64 бита
    struct chunk
    {
        _uqword m[2];
        chunk() noexcept {}
        chunk(bool b) noexcept : m{} {}
        _uqword& operator[](int idx) noexcept
        {
            return m[idx];
        }
        const _uqword& operator[](int idx) const noexcept
        {
            return m[idx];
        }
        chunk& operator=(const chunk& That) noexcept
        {
            m[0] = That.m[0];
            m[1] = That.m[1];
            return *this;
        }
        operator _uqword* () noexcept
        {
            return m;
        }
        operator const _uqword* () const noexcept
        {
            return m;
        }
        operator unsigned char* () noexcept
        {
            return (unsigned char*)m;
        }
        operator const unsigned char* () const noexcept
        {
            return (const unsigned char*)m;
        }
        void Zero() noexcept
        {
            m[1] = m[0] = 0;
        }
    };

protected:
//public:
    // Итерационные ключи
    chunk round_keys[10];

    // Таблица прямого нелинейного преобразования согластно ГОСТ 34.12-2015
    static const unsigned char Pi[256], Pi_reverse[256];
    //static unsigned char Pi_reverse[256];
    static unsigned short *Pi2, *Pi2_reverse;
    static const unsigned char linear_vector[16];
    static const unsigned char StaticKey[32];

    // Функция X 
    static constexpr void X(const _uqword *a, const _uqword* b, _uqword* c) noexcept
    {
        c[0] = a[0] ^ b[0];
        c[1] = a[1] ^ b[1];
    }
    static void S(_uqword* in_out) noexcept;
    static void S_reverse(_uqword* in_out) noexcept;
    static unsigned char GF_mult(unsigned char a, unsigned char b) noexcept;
    static void R(unsigned char* in_out) noexcept;
    static void R_reverse(unsigned char* in_out) noexcept;
    static void L(unsigned char* in_out) noexcept;
    static void L_reverse(unsigned char* in_out) noexcept;
    static void gen_round_keys(const unsigned char* key, chunk* round_keys) noexcept;
    static void kuznechik_encrypt(const chunk* round_keys, const _uqword* in, _uqword* out) noexcept;
    static void kuznechik_decrypt(const chunk* round_keys, const _uqword* in, _uqword* out) noexcept;
    static void kuznechik_encrypt128(const chunk* round_keys, _uqword* p) noexcept;
    static void kuznechik_decrypt128(const chunk* round_keys, _uqword* p) noexcept;
    void ClearRoundKeys() noexcept;
    static void CreateTables() noexcept;
public:
    static void print_chunk(const void* p) noexcept;
    CChipherKuznechik() noexcept;
    ~CChipherKuznechik();
    void SetKey(const unsigned char* key) noexcept;
    void Encrypt1(const unsigned char* pIn, size_t Size, unsigned char* pOut) const noexcept;
    void Decrypt1(const unsigned char* pIn, size_t Size, unsigned char* pOut) const noexcept;
    
    void Encrypt(const void* pIn, size_t Size, const void* Salt, void* pOut = nullptr, void* OutSalt = nullptr) const noexcept;
    void Decrypt(const void* pIn, size_t Size, const void* Salt, void* pOut = nullptr, void* OutSalt = nullptr) const noexcept;
};
