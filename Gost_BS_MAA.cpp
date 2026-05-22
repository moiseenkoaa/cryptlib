
// CryptLib Project

/* CryptLib library for RusRoute firewall and other projects of
 * Andrey A. Moiseenko / IE Moiseenko A.A. (Russia)
 * e-mail: support@maasoftware.ru, maa2002@mail.ru
 * web: http://maasoftware.ru, http://maasoftware.com, http://maasoft.ru, http://maasoft.org
 * Author's full name: Andrey Alekseevitch Moiseenko
 * (russian name: Моисеенко Андрей Алексеевич)
 */

// CryptLib/Gost_BS_MAA.cpp

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

//#ifdef _WIN32
#define register
//#endif

#ifndef TOOLSLIB_LITTLE_ENDIAN
#define BIG_ENDIAN_ALGO
#define be_bswap32 my_htonl_le
#define be_bswap16 my_htons_le
#endif

/*
//#define LE_BE_TEST
#ifdef LE_BE_TEST
#define BIG_ENDIAN_ALGO
#define be_bswap32 my_htonl_le
#define be_bswap16 my_htons_le
#endif
*/

//CGostBsMaa gGostBsMaa;

void GostMain() noexcept;

// GOST
//

//typedef  unsigned   long   u4;
typedef  _dword   u4;
typedef  unsigned  char  byte;

#ifdef        alpha      //  Any  other   64-bit  machines?
typedef  unsigned  int  word32;
#else
//typedef unsigned long word32;
typedef _dword word32;
#endif

#if 0
struct gost_ctx
{
    //u4   k[8];
    //   Constant   s-boxes   --  set   up   in   gost_init().
    //
    // Брюс Шнайдер:
    // char  k87[256],k65[256],k43[256],k21[256];
    //
    // Моисеенко Андрей:
    // unsigned char  k87[256],k65[256],k43[256],k21[256];
    //

    _dword k87[256], k65[256], k43[256], k21[256];
    unsigned char StaticKey[32];

    gost_ctx() noexcept;
    ~gost_ctx();

    word32
#ifdef _WIN32
    //_fastcall
#endif
    //f(_dword x) const noexcept { return k87[x >> 24 & 255] | k65[x >> 16 & 255] | k43[x >> 8 & 255] | k21[x & 255]; }
    f(_dword x) const noexcept { return k21[x & 255] | k43[x >> 8 & 255] | k65[x >> 16 & 255] | k87[x >> 24 & 255]; }

    void gostcrypt(const _dword* key, _dword *d) const noexcept;
    void gostcrypt16(const _dword * key, _dword *d) const noexcept;
    void gostdecrypt(const _dword * key, _dword * d) const noexcept;
    void gost_enc(const _dword * key, _dword *, int) const noexcept;
    void gost_dec(const _dword * key, _dword *, int) const noexcept;
    //void  gost_key(gost_ctx *, u4 *);

    // High level functions
    void Encrypt(const _dword* Key, const _dword* pIn, size_t Size, const _dword* Salt, _dword* pOut, _dword* OutSalt) const noexcept;
    void Decrypt(const _dword* Key, const _dword* pIn, size_t Size, const _dword* Salt, _dword* pOut, _dword* OutSalt) const noexcept;
    void Imito(const _dword* Key, const _dword* pIn, size_t Size, _dword* ImitoValue, const _dword* Salt, const void* End) const noexcept;
};
#endif
#ifdef _WIN32
#ifndef _WIN64

/*
static word32 __declspec(naked) _fastcall // edx = x, ecx = c
    F(const gost_ctx* c, word32 x) noexcept
    {
        // return k87[x >> 24 & 255] | k65[x >> 16 & 255] | k43[x >> 8 & 255] | k21[x & 255];
    __asm
    {
        push esi
        push ebx
        push ecx
        mov esi, ecx // dword ptr[esp + 10h] // для word32 __declspec(naked) F(const gost_ctx * c, word32 x) noexcept
        mov ecx, edx // dword ptr[esp + 14h] // для word32 __declspec(naked) F(const gost_ctx * c, word32 x) noexcept
        xor ebx, ebx
        mov bl, cl
        mov eax, dword ptr[esi + 3 * 400h + 4 * ebx]
        shr ecx, 8
        mov bl, cl
        or eax, dword ptr[esi + 2 * 400h + 4 * ebx]
        shr ecx, 8
        mov bl, cl
        or eax, dword ptr[esi + 400h + 4 * ebx]
        shr ecx, 8
        mov bl, cl
        or eax, dword ptr[esi + 4 * ebx]
        pop ecx
        pop ebx
        pop esi
        ret
    }
        //return c->k87[x >> 24 & 255] | c->k65[x >> 16 & 255] | c->k43[x >> 8 & 255] | c->k21[x & 255]; 
    }
#define f(x) F(this, x)
*/
#endif
#endif
//#define FFF(n, tt) x = tt, n ^= k87[x >> 24 & 255] | k65[x >> 16 & 255] | k43[x >> 8 & 255] | k21[x & 255];

/*   Note:     encrypt  and  decrypt   expect   full   blocks—padding  blocks   is
                        caller's   responsibility.      All  bulk  encryption   is  done   in
                        ECB  node by   these  calls.      Other  modes  may  be  added  easily
                        enough.
*/
gost_ctx::gost_ctx() noexcept
{
    int   i;
#if 1
    // permutation block from Bruce Schneier "Applied Cryptography" book (possible for Sberbank)
    const byte k8[16] = { 14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7 };
    const byte k7[16] = { 15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10 };
    const byte k6[16] = { 10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8 };
    const byte k5[16] = {  7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15 };
    const byte k4[16] = {  2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9 };
    const byte k3[16] = { 12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11 };
    const byte k2[16] = {  4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1 };
    const byte k1[16] = { 13,  2,  8,  4,  6, 15, 11,  1,  10, 9,  3, 14,  5,  0, 12,  7 };
#else
    // the other permutation block, git clone https://github.com/faddistr/GOST28147.git
    const byte k8[16] = {  4,  2, 15,  5,  9,  1,  0,  8, 14,  3, 11, 12, 13,  7, 10,  6 };
    const byte k7[16] = { 12,  9, 15, 14,  8,  1,  3, 10,  2,  7,  4, 13,  6,  0, 11,  5 };
    const byte k6[16] = { 13,  8, 14, 12,  7,  3,  9, 10,  1,  5,  2,  4,  6, 15,  0, 11 };
    const byte k5[16] = { 14,  9, 11,  2,  5, 15,  7,  1,  0, 13, 12,  6, 10,  4,  3,  8 };
    const byte k4[16] = {  3, 14,  5,  9,  6,  8,  0, 13, 10, 11,  7, 12,  2,  1, 15,  4 };
    const byte k3[16] = {  8, 15,  6, 11,  1,  9, 12,  5, 13,  3,  7, 10,  0, 14,  2,  4 };
    const byte k2[16] = {  9, 11, 12,  0,  3,  6,  7,  5,  4,  8, 14, 15,  1, 10,  2, 13 };
    const byte k1[16] = { 12,  6,  5,  2, 11,  0,  9, 13,  3, 14,  7, 10, 15,  4,  1,  8 };
#endif

    for (i = 0; i < 256; i++)
    {
        k87[i] = (k8[i >> 4] << 4 | k7[i & 15]) << 24;
        k65[i] = (k6[i >> 4] << 4 | k5[i & 15]) << 16;
        k43[i] = (k4[i >> 4] << 4 | k3[i & 15]) << 8;
        k21[i] = (k2[i >> 4] << 4 | k1[i & 15]);

        k87[i] = k87[i] << 11 | k87[i] >> (32 - 11);
        k65[i] = k65[i] << 11 | k65[i] >> (32 - 11);
        k43[i] = k43[i] << 11 | k43[i] >> (32 - 11);
        k21[i] = k21[i] << 11 | k21[i] >> (32 - 11);
    }

    for (i = 0; i < 32; i++)
    {
        StaticKey[i] = i + 1;
    }
}
gost_ctx::~gost_ctx()
{
    memset(k87, 0, sizeof(k87));
    memset(k65, 0, sizeof(k65));
    memset(k43, 0, sizeof(k43));
    memset(k21, 0, sizeof(k21));
    memset(StaticKey, 0, 32);
}

/*word32 gost_ctx::f(word32 x) const noexcept
{
     //return k87[x >> 24 & 255] | k65[x >> 16 & 255] | k43[x >> 8 & 255] | k21[x & 255];
     
     //x = k87[x >> 24 & 255] | k65[x >> 16 & 255] | k43[x >> 8 & 255] | k21[x & 255];
     //   Rotate   left   11  bits
     //return  x << 11 | x >> (32 - 11);
}
*/

void gost_ctx::gostcrypt(const u4* key, word32* d) const noexcept
{
    register  word32  n1, n2;   //   As named in the GOST
    n1 = d[0];
    n2 = d[1];

    // Instead of swapping halves, swap names each round
#ifdef FFF
    register word32 x;
    FFF(n2, n1 + key[0]); FFF(n1, n2 + key[1]);
    FFF(n2, n1 + key[2]); FFF(n1, n2 + key[3]);
    FFF(n2, n1 + key[3]); FFF(n1, n2 + key[5]);
    FFF(n2, n1 + key[4]); FFF(n1, n2 + key[7]);
    FFF(n2, n1 + key[0]); FFF(n1, n2 + key[1]);
    FFF(n2, n1 + key[2]); FFF(n1, n2 + key[3]);
    FFF(n2, n1 + key[4]); FFF(n1, n2 + key[5]);
    FFF(n2, n1 + key[6]); FFF(n1, n2 + key[7]);
    FFF(n2, n1 + key[0]); FFF(n1, n2 + key[1]);
    FFF(n2, n1 + key[2]); FFF(n1, n2 + key[3]);
    FFF(n2, n1 + key[4]); FFF(n1, n2 + key[5]);
    FFF(n2, n1 + key[6]); FFF(n1, n2 + key[7]);
    FFF(n2, n1 + key[7]); FFF(n1, n2 + key[6]);
    FFF(n2, n1 + key[5]); FFF(n1, n2 + key[4]);
    FFF(n2, n1 + key[3]); FFF(n1, n2 + key[2]);
    FFF(n2, n1 + key[1]); FFF(n1, n2 + key[0]);
#else
    n2 ^= f(n1 + key[0]);  n1 ^= f(n2 + key[1]);
    n2 ^= f(n1 + key[2]);  n1 ^= f(n2 + key[3]);
    n2 ^= f(n1 + key[4]);  n1 ^= f(n2 + key[5]);
    n2 ^= f(n1 + key[6]);  n1 ^= f(n2 + key[7]);
    n2 ^= f(n1 + key[0]);  n1 ^= f(n2 + key[1]);
    n2 ^= f(n1 + key[2]);  n1 ^= f(n2 + key[3]);
    n2 ^= f(n1 + key[4]);  n1 ^= f(n2 + key[5]);
    n2 ^= f(n1 + key[6]);  n1 ^= f(n2 + key[7]);
    n2 ^= f(n1 + key[0]);  n1 ^= f(n2 + key[1]);
    n2 ^= f(n1 + key[2]);  n1 ^= f(n2 + key[3]);
    n2 ^= f(n1 + key[4]);  n1 ^= f(n2 + key[5]);
    n2 ^= f(n1 + key[6]);  n1 ^= f(n2 + key[7]);
    n2 ^= f(n1 + key[7]);  n1 ^= f(n2 + key[6]);
    n2 ^= f(n1 + key[5]);  n1 ^= f(n2 + key[4]);
    n2 ^= f(n1 + key[3]);  n1 ^= f(n2 + key[2]);
    n2 ^= f(n1 + key[1]);  n1 ^= f(n2 + key[0]);
#endif

    d[0] = n2;
    d[1] = n1;
}
void gost_ctx::gostcrypt16(const u4 * key, word32 *d) const noexcept
{
    register  word32  n1, n2;   //   As naned in the GOST
    n1 = d[0];
    n2 = d[1];

    // Instead of swapping halves, swap names each round
#ifdef FFF
    register word32 x;
    FFF(n2, n1 + key[0]); FFF(n1, n2 + key[1]);
    FFF(n2, n1 + key[2]); FFF(n1, n2 + key[3]);
    FFF(n2, n1 + key[4]); FFF(n1, n2 + key[5]);
    FFF(n2, n1 + key[6]); FFF(n1, n2 + key[7]);
    FFF(n2, n1 + key[0]); FFF(n1, n2 + key[1]);
    FFF(n2, n1 + key[2]); FFF(n1, n2 + key[3]);
    FFF(n2, n1 + key[4]); FFF(n1, n2 + key[5]);
    FFF(n2, n1 + key[6]); FFF(n1, n2 + key[7]);
#else
    n2 ^= f(n1 + key[0]);  n1 ^= f(n2 + key[1]);
    n2 ^= f(n1 + key[2]);  n1 ^= f(n2 + key[3]);
    n2 ^= f(n1 + key[4]);  n1 ^= f(n2 + key[5]);
    n2 ^= f(n1 + key[6]);  n1 ^= f(n2 + key[7]);
    n2 ^= f(n1 + key[0]);  n1 ^= f(n2 + key[1]);
    n2 ^= f(n1 + key[2]);  n1 ^= f(n2 + key[3]);
    n2 ^= f(n1 + key[4]);  n1 ^= f(n2 + key[5]);
    n2 ^= f(n1 + key[6]);  n1 ^= f(n2 + key[7]);
#endif

    d[0] = n2;
    d[1] = n1;
}

void gost_ctx::gostdecrypt(const u4 * key, u4 *d) const noexcept
{
    register word32 n1, n2;   // As naned in the GOST
    n1 = d[0];
    n2 = d[1];

#ifdef FFF
    register word32 x;
    FFF(n2, n1 + key[0]); FFF(n1, n2 + key[1]);
    FFF(n2, n1 + key[2]); FFF(n1, n2 + key[3]);
    FFF(n2, n1 + key[4]); FFF(n1, n2 + key[5]);
    FFF(n2, n1 + key[6]); FFF(n1, n2 + key[7]);
    FFF(n2, n1 + key[7]); FFF(n1, n2 + key[6]);
    FFF(n2, n1 + key[5]); FFF(n1, n2 + key[4]);
    FFF(n2, n1 + key[3]); FFF(n1, n2 + key[2]);
    FFF(n2, n1 + key[1]); FFF(n1, n2 + key[0]);
    FFF(n2, n1 + key[7]); FFF(n1, n2 + key[6]);
    FFF(n2, n1 + key[5]); FFF(n1, n2 + key[4]);
    FFF(n2, n1 + key[3]); FFF(n1, n2 + key[2]);
    FFF(n2, n1 + key[1]); FFF(n1, n2 + key[0]);
    FFF(n2, n1 + key[7]); FFF(n1, n2 + key[6]);
    FFF(n2, n1 + key[5]); FFF(n1, n2 + key[4]);
    FFF(n2, n1 + key[3]); FFF(n1, n2 + key[2]);
    FFF(n2, n1 + key[1]); FFF(n1, n2 + key[0]);
#else
    n2 ^= f(n1 + key[0]);  n1 ^= f(n2 + key[1]);
    n2 ^= f(n1 + key[2]);  n1 ^= f(n2 + key[3]);
    n2 ^= f(n1 + key[4]);  n1 ^= f(n2 + key[5]);
    n2 ^= f(n1 + key[6]);  n1 ^= f(n2 + key[7]);
    n2 ^= f(n1 + key[7]);  n1 ^= f(n2 + key[6]);
    n2 ^= f(n1 + key[5]);  n1 ^= f(n2 + key[4]);
    n2 ^= f(n1 + key[3]);  n1 ^= f(n2 + key[2]);
    n2 ^= f(n1 + key[1]);  n1 ^= f(n2 + key[0]);
    n2 ^= f(n1 + key[7]);  n1 ^= f(n2 + key[6]);
    n2 ^= f(n1 + key[5]);  n1 ^= f(n2 + key[4]);
    n2 ^= f(n1 + key[3]);  n1 ^= f(n2 + key[2]);
    n2 ^= f(n1 + key[1]);  n1 ^= f(n2 + key[0]);
    n2 ^= f(n1 + key[7]);  n1 ^= f(n2 + key[6]);
    n2 ^= f(n1 + key[5]);  n1 ^= f(n2 + key[4]);
    n2 ^= f(n1 + key[3]);  n1 ^= f(n2 + key[2]);
    n2 ^= f(n1 + key[1]);  n1 ^= f(n2 + key[0]);
#endif

    d[0] = n2;
    d[1] = n1;
}

void gost_ctx::gost_enc(const u4 * key, u4 *d, int blocks) const noexcept
{
    int i;
    for (i=0; i < blocks; i++)
    {
        gostcrypt(key, d);
        d+=2;
    }
}

void gost_ctx::gost_dec(const u4 * key, u4 *d, int blocks) const noexcept
{
    int i;
    for (i=0; i < blocks; i++)
    {
        gostdecrypt(key, d);
        d+=2;
    }
}

// high level Encrypt function // gamma with feedack
// Key - 32 bytes, Salt - 8 bytes, OutSalt - 8 bytes, Size in bytes
void gost_ctx::Encrypt(const _dword* Key, const _dword* pIn, size_t Size, const _dword* Salt, _dword* pOut, _dword* OutSalt) const noexcept
{
    Key = Key ? Key : (const _dword*)StaticKey;
#ifdef BIG_ENDIAN_ALGO
    _dword hKey[8];
    for (int j = 0; j < 8; j++)
    {
        hKey[j] = be_bswap32(Key[j]);
    }
    Key = hKey;
#endif
    pOut = pOut ? pOut : (_dword*)pIn;
#ifdef BIG_ENDIAN_ALGO
    _dword n12[2] = { be_bswap32(Salt[0]), be_bswap32(Salt[1]) };
#else
    _dword n12[2] = { Salt[0], Salt[1] };
#endif

    for (size_t i = (Size >> 3); i--; )
    {
        gostcrypt(Key, n12);
        
#ifdef BIG_ENDIAN_ALGO
        *pOut++ = be_bswap32(n12[0] ^= be_bswap32(*pIn++));
        *pOut++ = be_bswap32(n12[1] ^= be_bswap32(*pIn++));
#else
        *pOut++ = (n12[0] ^= *pIn++);
        *pOut++ = (n12[1] ^= *pIn++);
#endif
    }
    if  (Size & 7)
    {
        _dword t[2] = { 0, 0 };
        memcpy(t, pIn, Size & 7);
        gostcrypt(Key, n12);
#ifdef BIG_ENDIAN_ALGO
        n12[0] ^= be_bswap32(t[0]);
        n12[1] ^= be_bswap32(t[1]);
#else
        n12[0] ^= t[0];
        n12[1] ^= t[1];
#endif
        memcpy(pOut, n12, Size & 7);
        t[1] = t[0] = 0;
    }
    if  (OutSalt)
    {
#ifdef BIG_ENDIAN_ALGO
        OutSalt[0] = be_bswap32(n12[0]);
        OutSalt[1] = be_bswap32(n12[1]);
#else
        OutSalt[0] = n12[0];
        OutSalt[1] = n12[1];
#endif
    }
#ifdef BIG_ENDIAN_ALGO
    for (int j = 0; j < 8; j++)
    {
        hKey[j] = 0;
    }
#endif
}

// DecryptXX.OutSalt == EncryptXX.OutSalt <== if (Size % 8 == 0)

// high level Decrypt function // gamma with feedack
// Key - 32 bytes, Salt - 8 bytes, OutSalt - 8 bytes, Size in bytes
void gost_ctx::Decrypt(const _dword* Key, const _dword* pIn, size_t Size, const _dword* Salt, _dword* pOut, _dword* OutSalt) const noexcept
{
    Key = Key ? Key : (const _dword*)StaticKey;
#ifdef BIG_ENDIAN_ALGO
    _dword hKey[8];
    for (int j = 0; j < 8; j++)
    {
        hKey[j] = be_bswap32(Key[j]);
    }
    Key = hKey;
#endif
    pOut = pOut ? pOut : (_dword*)pIn;
#ifdef BIG_ENDIAN_ALGO
    _dword n12[2] = { be_bswap32(Salt[0]), be_bswap32(Salt[1]) };
#else
    _dword n12[2] = { Salt[0], Salt[1] };
#endif
    _dword N12[2];

    for (size_t i = (Size >> 3); i--; )
    {
        gostcrypt((u4*)Key, (word32*)n12);
        
#ifdef BIG_ENDIAN_ALGO
        *pOut++ = be_bswap32(n12[0] ^ (N12[0] = be_bswap32(*pIn++)));
        *pOut++ = be_bswap32(n12[1] ^ (N12[1] = be_bswap32(*pIn++)));
#else
        *pOut++ = n12[0] ^ (N12[0] = *pIn++);
        *pOut++ = n12[1] ^ (N12[1] = *pIn++);
#endif

        n12[0] = N12[0];
        n12[1] = N12[1];
    }
    if  (Size & 7)
    {
        _dword t[2] = { 0, 0 };
        memcpy(t, pIn, Size & 7);
        gostcrypt((u4*)Key, (word32*)n12);
#ifdef BIG_ENDIAN_ALGO
        t[0] = be_bswap32(n12[0] ^ (N12[0] = be_bswap32(t[0])));
        t[1] = be_bswap32(n12[1] ^ (N12[1] = be_bswap32(t[1])));
#else
        t[0] = n12[0] ^ (N12[0] = t[0]);
        t[1] = n12[1] ^ (N12[1] = t[1]);
#endif
        n12[0] = N12[0];
        n12[1] = N12[1];
        memcpy(pOut, t, Size & 7);
        t[1] = t[0] = 0;
    }
    if  (OutSalt)
    {
#ifdef BIG_ENDIAN_ALGO
        OutSalt[0] = be_bswap32(n12[0]);
        OutSalt[1] = be_bswap32(n12[1]);
#else
        OutSalt[0] = n12[0];
        OutSalt[1] = n12[1];
#endif
    }
#ifdef BIG_ENDIAN_ALGO
    for (int j = 0; j < 8; j++)
    {
        hKey[j] = 0;
    }
#endif
}

// high level Imito function
void gost_ctx::Imito(const _dword* Key, const _dword* pIn, size_t Size, _dword* ImitoValue, const _dword* Salt, const _dword* End) const noexcept
{
    Key = Key ? Key : (const _dword*)StaticKey;
#ifdef BIG_ENDIAN_ALGO
    _dword hKey[8];
    for (int j = 0; j < 8; j++)
    {
        hKey[j] = be_bswap32(Key[j]);
    }
    Key = hKey;
#endif
    _dword n12[2], t[2];
    if  (Salt)
    {
#ifdef BIG_ENDIAN_ALGO
        n12[0] = be_bswap32(Salt[0]);
        n12[1] = be_bswap32(Salt[1]);
#else
        n12[0] = Salt[0];
        n12[1] = Salt[1];
#endif
    }
    else
    {
        n12[1] = n12[0] = 0;
    }

    for (size_t i = (Size >> 3); i--; )
    {
#ifdef BIG_ENDIAN_ALGO
        n12[0] ^= be_bswap32(*pIn++);
        n12[1] ^= be_bswap32(*pIn++);
#else
        n12[0] ^= *pIn++;
        n12[1] ^= *pIn++;
#endif
        gostcrypt16(Key, n12);
    }
    if  (Size & 7)
    {
        if  (End)
        {
            t[0] = End[0];
            t[1] = End[1];
        }
        else
        {
            t[0] = t[1] = 0;
        }
        memcpy(t, pIn, Size & 7);
#ifdef BIG_ENDIAN_ALGO
        n12[0] ^= be_bswap32(t[0]);
        n12[1] ^= be_bswap32(t[1]);
#else
        n12[0] ^= t[0];
        n12[1] ^= t[1];
#endif
        gostcrypt16(Key, n12);
        t[0] = t[1] = 0;
    }
#ifdef BIG_ENDIAN_ALGO
    ImitoValue[0] = be_bswap32(n12[0]);
    ImitoValue[1] = be_bswap32(n12[1]);
#else
    ImitoValue[0] = n12[0];
    ImitoValue[1] = n12[1];
#endif
#ifdef BIG_ENDIAN_ALGO
    for (int j = 0; j < 8; j++)
    {
        hKey[j] = 0;
    }
#endif
}

// high level Encrypt function // gamma with feedack
// Key - 32 bytes, Salt - 8 bytes, OutSalt - 8 bytes, Size in bytes
void gost_ctx::EncryptImito(const _dword* Key, const _dword* pIn, size_t Size, const _dword* Salt, _dword* pOut, _dword* OutSalt, _dword* ImitoValue, const _dword* End) const noexcept
{
    Key = Key ? Key : (const _dword*)StaticKey;
#ifdef BIG_ENDIAN_ALGO
    _dword hKey[8];
    for (int j = 0; j < 8; j++)
    {
        hKey[j] = be_bswap32(Key[j]);
    }
    Key = hKey;
#endif
    pOut = pOut ? pOut : (_dword*)pIn;
#ifdef BIG_ENDIAN_ALGO
    _dword n12[2] = { be_bswap32(Salt[0]), be_bswap32(Salt[1]) };
    _dword i12[2] = { be_bswap32(Salt[0]), be_bswap32(Salt[1]) };
#else
    _dword n12[2] = { Salt[0], Salt[1] };
    _dword i12[2] = { Salt[0], Salt[1] };
#endif

    for (size_t i = (Size >> 3); i--; )
    {
#ifdef BIG_ENDIAN_ALGO
        i12[0] ^= be_bswap32(pIn[0]);
        i12[1] ^= be_bswap32(pIn[1]);
#else
        i12[0] ^= pIn[0];
        i12[1] ^= pIn[1];
#endif
        gostcrypt16(Key, i12);
        gostcrypt(Key, n12);
#ifdef BIG_ENDIAN_ALGO
        *pOut++ = be_bswap32(n12[0] ^= be_bswap32(*pIn++));
        *pOut++ = be_bswap32(n12[1] ^= be_bswap32(*pIn++));
#else
        *pOut++ = (n12[0] ^= *pIn++);
        *pOut++ = (n12[1] ^= *pIn++);
#endif
    }
    if (Size & 7)
    {
        _dword t[2];
        if (End)
        {
            //memcpy(t, End, sizeof(t));
            t[0] = End[0];
            t[1] = End[1];
        }
        else
        {
            t[1] = t[0] = 0;
        }
        memcpy(t, pIn, Size & 7);
#ifdef BIG_ENDIAN_ALGO
        i12[0] ^= be_bswap32(t[0]);
        i12[1] ^= be_bswap32(t[1]);
#else
        i12[0] ^= t[0];
        i12[1] ^= t[1];
#endif
        gostcrypt16(Key, i12);
        //-----------------------
        t[1] = t[0] = 0;
        memcpy(t, pIn, Size & 7);
        gostcrypt(Key, n12);
#ifdef BIG_ENDIAN_ALGO
        n12[0] ^= be_bswap32(t[0]);
        n12[1] ^= be_bswap32(t[1]);
#else
        n12[0] ^= t[0];
        n12[1] ^= t[1];
#endif
        memcpy(pOut, n12, Size & 7);
        t[1] = t[0] = 0;
    }
#ifdef BIG_ENDIAN_ALGO
    ImitoValue[0] = be_bswap32(i12[0]);
    ImitoValue[1] = be_bswap32(i12[1]);
    if (OutSalt)
    {
        OutSalt[0] = be_bswap32(n12[0]);
        OutSalt[1] = be_bswap32(n12[1]);
    }
#else
    ImitoValue[0] = i12[0];
    ImitoValue[1] = i12[1];
    if (OutSalt)
    {
        OutSalt[0] = n12[0];
        OutSalt[1] = n12[1];
    }
#endif
#ifdef BIG_ENDIAN_ALGO
    for (int j = 0; j < 8; j++)
    {
        hKey[j] = 0;
    }
#endif
}

// DecryptXX.OutSalt == EncryptXX.OutSalt <== if (Size % 8 == 0)

void gost_ctx::DecryptImito(const _dword* Key, const _dword* pIn, size_t Size, const _dword* Salt, _dword* pOut, _dword* OutSalt, _dword* ImitoValue, const _dword* End) const noexcept
{
    Key = Key ? Key : (const _dword*)StaticKey;
#ifdef BIG_ENDIAN_ALGO
    _dword hKey[8];
    for (int j = 0; j < 8; j++)
    {
        hKey[j] = be_bswap32(Key[j]);
    }
    Key = hKey;
#endif
    pOut = pOut ? pOut : (_dword*)pIn;
#ifdef BIG_ENDIAN_ALGO
    _dword n12[2] = { be_bswap32(Salt[0]), be_bswap32(Salt[1]) };
    _dword i12[2] = { be_bswap32(Salt[0]), be_bswap32(Salt[1]) };
#else
    _dword n12[2] = { Salt[0], Salt[1] };
    _dword i12[2] = { Salt[0], Salt[1] };
#endif
    _dword N12[2];

    for (size_t i = (Size >> 3); i--; )
    {
        gostcrypt((u4*)Key, (word32*)n12);

#ifdef BIG_ENDIAN_ALGO
        pOut[0] = be_bswap32(n12[0] ^ (N12[0] = be_bswap32(*pIn++)));
        pOut[1] = be_bswap32(n12[1] ^ (N12[1] = be_bswap32(*pIn++)));
#else
        pOut[0] = n12[0] ^ (N12[0] = *pIn++);
        pOut[1] = n12[1] ^ (N12[1] = *pIn++);
#endif

        n12[0] = N12[0];
        n12[1] = N12[1];

#ifdef BIG_ENDIAN_ALGO
        i12[0] ^= be_bswap32(*pOut++);
        i12[1] ^= be_bswap32(*pOut++);
#else
        i12[0] ^= *pOut++;
        i12[1] ^= *pOut++;
#endif
        gostcrypt16(Key, i12);
    }
    if (Size & 7)
    {
        _dword t[2] = { 0, 0 };
        memcpy(t, pIn, Size & 7);
        gostcrypt((u4*)Key, (word32*)n12);
#ifdef BIG_ENDIAN_ALGO
        t[0] = be_bswap32(n12[0] ^ (N12[0] = be_bswap32(t[0])));
        t[1] = be_bswap32(n12[1] ^ (N12[1] = be_bswap32(t[1])));
#else
        t[0] = n12[0] ^ (N12[0] = t[0]);
        t[1] = n12[1] ^ (N12[1] = t[1]);
#endif
        n12[0] = N12[0];
        n12[1] = N12[1];
        memcpy(pOut, t, Size & 7);
        //-----------------------
        if (End)
        {
            //memcpy(t, End, sizeof(t));
            t[0] = End[0];
            t[1] = End[1];
        }
        else
        {
            t[1] = t[0] = 0;
        }
        memcpy(t, pOut, Size & 7);
#ifdef BIG_ENDIAN_ALGO
        i12[0] ^= be_bswap32(t[0]);
        i12[1] ^= be_bswap32(t[1]);
#else
        i12[0] ^= t[0];
        i12[1] ^= t[1];
#endif
        gostcrypt16(Key, i12);
        t[1] = t[0] = 0;
    }
#ifdef BIG_ENDIAN_ALGO
    ImitoValue[0] = be_bswap32(i12[0]);
    ImitoValue[1] = be_bswap32(i12[1]);
    if (OutSalt)
    {
        OutSalt[0] = be_bswap32(n12[0]);
        OutSalt[1] = be_bswap32(n12[1]);
    }
#else
    ImitoValue[0] = i12[0];
    ImitoValue[1] = i12[1];
    if (OutSalt)
    {
        OutSalt[0] = n12[0];
        OutSalt[1] = n12[1];
    }
#endif
#ifdef BIG_ENDIAN_ALGO
    for (int j = 0; j < 8; j++)
    {
        hKey[j] = 0;
    }
#endif
}


/*
void  gost_key(gost_ctx   *c,   u4   *k)
{
        int  i;
        for(i=0;i<8;i++)  c->k[i]=k[i];
}
*/

/*
void  gost_init(gost_ctx *c)
{
        kboxinit(c);
}
*/

/*
void gost_destroy(gost_ctx *c)
{
        //memset(c->k, 0, 32);
        memset(c->StaticKey, 0, 32);
}
*/

CGostBsMaa::CGostBsMaa() noexcept
{
    /*
    m_gc = TL_NEW gost_ctx;
    if   (!m_gc)
    {
        throw 1;
    }
    */
    ////gost_init(m_gc);
}

CGostBsMaa::~CGostBsMaa()
{
    ////gost_destroy(m_gc);
    //delete m_gc;
}
#ifdef _WIN32
#ifndef _WIN64

#ifdef f
#undef f
#endif

#endif
#endif
/*
-------------------------------------------------------------------------------------------------------
    Need opt like https://www.securitylab.ru/analytics/480357.php  07:21 / 25 Марта, 2016
-------------------------------------------------------------------------------------------------------
https://xakep.ru/2013/10/19/shifrovanie-gost-28147-89/
-------------------------------------------------------------------------------------------------------
Скоростное поточное шифрование. 08:59 / 24 Января, 2013 https://www.securitylab.ru/analytics/436620.php

Основной цикл шифрования на SSE в восемь потоков.
SSE0, SSE1, SSE6, SSE7 содержат поочередно накопители1 и накопители2 (восемь накопителей по 4 байта каждый)
Сначала готовятся индексные регистры для работы коммутатора
Пример кода не оптимизирован по быстродействию, но максимально удобен для понимания.
Ключи шифрования находятся в ОП, но можно и загружать в неиспользуемые регистры процессора (MMX).

Use64

 macro zxmm kl
 {
 ;/////подготовка блока замен 1 накопитель
 vpsrlq xmm3,xmm5,4;
 pand xmm5,[esp+080h]; технологическая маска выделения младших тетрад
 pand xmm3,[esp+080h]; технологическая маска выделения младших тетрад
 ;/////замена 1-2байт -м.т. 3-4байт с.т.
 vpblendw xmm2,xmm3,xmm5,055h;
 ;/////замена 1-2байт - с.т. 3-4байт м.т.
 pblendw xmm5,xmm3,0aah;
 ;/////////блок замен 1-2 байты - 1 накопитель
 vpshufb xmm15,xmm8,xmm2;
 pand xmm15,[esp];
 vpshufb xmm14,xmm9,xmm2;
 pand xmm14,[esp+20h];
 por xmm14,xmm15;
 ;/////////блок замен 3-4 байты - 1 накопитель
 vpshufb xmm12,xmm10,xmm5;
 pand xmm12,[esp+40h];
 por xmm12,xmm14;
 vpshufb xmm13,xmm11,xmm5;
 pand xmm13,[esp+60h];
 ;/////подготовка блока замен -2 накопитель
 vpsrlq xmm3,xmm4,4;
 pand xmm4,[esp+80h];
 pand xmm3,[esp+080h];
 ;/////замена 1-2байт -м.т. 3-4байт с.т.
 vpblendw xmm2,xmm3,xmm4,055h;
 ;/////замена 1-2байт - с.т. 3-4байт м.т.
 pblendw xmm4,xmm3,0aah;
 ;/////////блок замен 1-2 байты - 2 накопитель
 vpshufb xmm14,xmm8,xmm2;
 pand xmm14,[esp];
 vpshufb xmm15,xmm9,xmm2;
 pand xmm15,[esp+20h];
 por xmm14,xmm15;
 ;/////////блок замен 3-4 байты - 2 накопитель
 vpshufb xmm3,xmm10,xmm4;
 pand xmm3,[esp+40h];
 por xmm14,xmm3;
 vpshufb xmm15,xmm11,xmm4;
 pand xmm15,[esp+60h];
 }

 ;///////////////////////////////тестовый модуль 1 проход


 macro c1 kl;
 {
 zxmm kl;
 ;/////циклический сдвиг на 11 влево - 1 накопитель
 por xmm13,xmm12;
 vpslld xmm12,xmm13,11;
 psrld xmm13,21;
 xorps xmm7,xmm12;
 xorps xmm7,xmm13; суммирование заполнение1 1 накопитель
 vpaddd xmm5,xmm7,[esp+100h+kl*32]; сложить заполнение с ключом
 ;/////циклический сдвиг на 11 влево - 2 накопитель
 por xmm15,xmm14;
 vpslld xmm14,xmm15,11;
 psrld xmm15,21;
 xorps xmm1,xmm14;
 xorps xmm1,xmm15; суммирование заполнение1 2 накопитель
 vpaddd xmm4,xmm1,[esp+120h+kl*32]; сложить заполнение с ключом
 }

 ;///////////////////////////////тестовый модуль 2 проход
 macro c2 kl;
 {
 zxmm kl;
 ;/////циклический сдвиг на 11 влево - 1 накопитель
 por xmm13,xmm12;
 vpslld xmm12,xmm13,11;
 psrld xmm13,21;
 xorps xmm6,xmm12;
 xorps xmm6,xmm13; суммирование заполнение 0 1 накопитель
 vpaddd xmm5,xmm6,[esp+100h+kl*32]; сложить заполнение с ключом
 ;/////циклический сдвиг на 11 влево - 2 накопитель
 por xmm15,xmm14;
 vpslld xmm14,xmm15,11;
 psrld xmm15,21;
 xorps xmm0,xmm14;
 xorps xmm0,xmm15; суммирование заполнение 0 2 накопитель
 vpaddd xmm4,xmm0,[esp+120h+kl*32]; сложить заполнение с ключом
 }

-------------------------------------------------------------------------------------------------------
    Need opt like https://www.securitylab.ru/analytics/480357.php  07:21 / 25 Марта, 2016
    Skylake: регистры УММ

Для перехода на регистры УММ пришлось в ассемблерном коде изменить только тип регистров, для чего поменять в названиях регистров букву «Х» на букву «У».
После чего скорость преобразования увеличилась вдвое автоматически.
Но вдвое, это существенно меньше, чем заветные 1гбайт/сек., потому пришлось еще «немного» оптимизировать алгоритм. Теперь он выглядит для одного вычислительного потока так (всего потоков два):

     ;ymm12-ymm15 - регистры хранения блоков замен
     ; ymm11 - маска сборки байт
     ; ymm5 - маска старших тетрад
     ; ymm0,ymm1 -  регистры чередующихся накопителей первого потока
     ; ymm2-ymm4 -  регистры промежуточных вычислений первого потока

     ;/////подготовка блока замен

      vpsrlw ymm2,ymm0,4;                старшие тетрады в младшие
       vpand ymm2,ymm2,ymm5;             сбросить старшие тетрады
        vpand ymm0,ymm0,ymm5;            сбросить старшие тетрады

     ;////////////////совместить выборку актуальных тетрад

     vpblendw ymm3,ymm0,ymm2,0aah;    замена 1-2байт м.тетрады и 3-4байт с.тетрады
      vpblendw ymm0,ymm0,ymm2,055h;   замена 1-2байт с.тетрады и 3-4байт м.тетрады

     ;////////////блок замен

      vpshufb ymm4,ymm12,ymm3;
       vpshufb ymm3,ymm13,ymm3;
        vpblendvb ymm4,ymm4,ymm3,ymm11;  совместить актуальные байты

      vpshufb ymm2,ymm14,ymm0;
       vpshufb ymm0,ymm15,ymm0;
        vpblendvb ymm0,ymm0,ymm2,ymm11;  совместить актуальные байты

     ;////////сборка результата

      vpand ymm4,ymm4,[rsp];                   очистить неиспользуемые тетрады
       vpand ymm0,ymm0,[rsp+20h];              очистить неиспользуемые тетрады
        vpor ymm0,ymm0,ymm4;                   собрать результат замены

     ;/////циклический сдвиг на 11 влево

      vpslld ymm2,ymm0,11;
       vpsrld ymm3,ymm0,21;
        vpxor ymm0,ymm1,ymm2;
         vpxor ymm0,ymm1,ymm3;                 суммирование накопителей
       vpaddd ymm1,ymm0,[rsp+40h+kl*32];    сложить накопитель с ключом
------------------------------------------------------------------------------
Реализация ГОСТ 28147-89 на УММ регистрах, как и любая «хорошо» сделанная вещь, позволяет перейти на 128битное преобразование по ГОСТ 28147-89 без потери быстродействия, и практически ничего не меняя в коде.
В примере, приведенном выше, нужно в модуле циклического сдвига выполнять операции с 64битными блоками, а не с 32битными, как сейчас.
Вот как это будет выглядеть для 128битного преобразования:

    ;/////циклический сдвиг на 11 влево

      vpsllq ymm2,ymm0,11;
       vpsrlq ymm3,ymm0,21;
        vpxor ymm0,ymm1,ymm2;
         vpxor ymm0,ymm1,ymm3;                 суммирование накопителей
       vpaddq ymm1,ymm0,[rsp+40h+kl*32];    сложить накопитель с ключем

Как видите, в трех командах изменилась всего лишь последняя буква, «d» - 32битная операция, заменена на «q» - 64битная операция.
      
*/
// Key - 32 bytes, Salt - 8 bytes, OutSalt - 8 bytes
void CGostBsMaa::Encrypt(const void * Key, const void * InData, size_t Size, const void * Salt, void * OutData, void *OutSalt) const noexcept
{
    m_gc.Encrypt((const _dword*)Key, (const _dword*)InData, Size, (const _dword*)Salt, (_dword*)OutData, (_dword*)OutSalt);
#if 0
    Key = Key ? Key : m_gc->StaticKey;
    OutData = OutData ? OutData : (void *)InData;
    _dword n12[2] = { *(const _dword *)Salt, *((const _dword *)Salt + 1) };
    const _dword* pIn = (const _dword*)InData;
    _dword* pOut = (_dword*)OutData;

    for (size_t i = (Size >> 3); i--; )
    {
        m_gc->gostcrypt((u4 *)Key, (word32 *)n12);
        n12[0] ^= *pIn++;
        n12[1] ^= *pIn++;
        *pOut++ = n12[0];
        *pOut++ = n12[1];
    }
    if  (Size & 7)
    {
        _dword t[2] = {0, 0};
        memcpy(t, pIn, Size & 7);
        m_gc->gostcrypt((u4 *)Key, (word32 *)n12);
        t[0] ^= n12[0];
        t[1] ^= n12[1];
        memcpy(pOut, t, Size & 7);
    }
    if  (OutSalt)
    {
        *(_dword *)OutSalt = n12[0];
        *((_dword *)OutSalt + 1) = n12[1];
    }
#endif
}
// Key - 32 bytes, Salt - 8 bytes, OutSalt - 8 bytes
void CGostBsMaa::Decrypt(const void * Key, const void * InData, size_t Size, const void * Salt, void * OutData, void *OutSalt) const noexcept
{
    m_gc.Decrypt((const _dword*)Key, (const _dword*)InData, Size, (const _dword*)Salt, (_dword*)OutData, (_dword*)OutSalt);
#if 0
    Key = Key ? Key : m_gc->StaticKey;
    OutData = OutData ? OutData : (void *)InData;
    _dword n12[2] = { *(const _dword *)Salt, *((const _dword *)Salt + 1) };
    _dword N12[2];
    const _dword* pIn = (const _dword*)InData;
    _dword* pOut = (_dword*)OutData;

    for (size_t i = (Size >> 3); i--; )
    {
        m_gc->gostcrypt((u4 *)Key, (word32 *)n12);
        N12[0] = *pIn++;
        N12[1] = *pIn++;

        *pOut++ = n12[0] ^ N12[0];
        *pOut++ = n12[1] ^ N12[1];

        n12[0] = N12[0];
        n12[1] = N12[1];
    }
    if  (Size & 7)
    {
        _dword t[2] = {0, 0};
        memcpy(t, pIn, Size & 7);
        m_gc->gostcrypt((u4 *)Key, (word32 *)n12);
        t[0] ^= n12[0];
        t[1] ^= n12[1];
        memcpy(pOut, t, Size & 7);
    }
    if  (OutSalt)
    {
        *(_dword *)OutSalt = n12[0];
        *((_dword *)OutSalt + 1) = n12[1];
    }
#endif
}

void CGostBsMaa::Imito(const void * Key, const void * InData, size_t Size, void * ImitoValue, const void * Salt, const void * End) const noexcept
{
    m_gc.Imito((const _dword*)Key, (const _dword*)InData, Size, (_dword*)ImitoValue, (const _dword*)Salt, (const _dword*)End);
#if 0
    Key = Key ? Key : m_gc->StaticKey;
    _dword n12[2], t[2];
    if  (Salt)
    {
        memcpy(n12, Salt, sizeof(n12));
    }
    else
    {
        n12[0] = n12[1] = 0;
    }
    const _dword* pIn = (const _dword*)InData;

    for (size_t i = (Size >> 3); i--; )
    {
        n12[0] ^= *pIn++;
        n12[1] ^= *pIn++;
        m_gc->gostcrypt16((u4 *)Key, (word32 *)n12);
    }
    if  (Size & 7)
    {
        if  (End)
        {
            memcpy(t, End, sizeof(t));
        }
        else
        {
            t[0] = t[1] = 0;
        }
        memcpy(t, pIn, Size & 7);
        n12[0] ^= t[0];
        n12[1] ^= t[1];
        m_gc->gostcrypt16((u4 *)Key, (word32 *)n12);
        t[0] = t[1] = 0;
    }
    *(_dword *)ImitoValue = n12[0];
    *(((_dword *)ImitoValue) + 1) = n12[1];
#endif
}

void CGostBsMaa::EncryptImito(const void* Key, const void* InData, size_t Size, void* ImitoValue, const void* Salt, void* OutData, void* OutSalt, const void* End) const noexcept
{
    m_gc.EncryptImito((const _dword*)Key, (const _dword*)InData, Size, (const _dword*)Salt, (_dword*)OutData, (_dword*)OutSalt, (_dword*)ImitoValue, (const _dword*)End);
}

void CGostBsMaa::DecryptImito(const void* Key, const void* InData, size_t Size, void* ImitoValue, const void* Salt, void* OutData, void* OutSalt, const void* End) const noexcept
{
    m_gc.DecryptImito((const _dword*)Key, (const _dword*)InData, Size, (const _dword*)Salt, (_dword*)OutData, (_dword*)OutSalt, (_dword*)ImitoValue, (const _dword*)End);
}

void CGostBsMaa::Hash(const void * Key, const void * InData, size_t Size, const void * Salt, void * Hash, int HashSize /* = 32*/) const noexcept
{
    Key = Key ? Key : m_gc.StaticKey;
#ifdef BIG_ENDIAN_ALGO
    //const void* Key0 = Key;
    _dword hKey[8];
    for (int j = 0; j < 8; j++)
    {
        hKey[j] = be_bswap32(((_dword *)Key)[j]);
    }
    //Key = hKey;
#else
    const void* hKey = Key;
#endif
#ifdef BIG_ENDIAN_ALGO
    _dword n12[2] = { be_bswap32(*(const _dword*)Salt), be_bswap32(*((const _dword*)Salt + 1)) };
#else
    _dword n12[2] = { *(const _dword*)Salt, *((const _dword*)Salt + 1) };
#endif
    unsigned char Sum = 0;
    const unsigned char * p = (unsigned char *)n12;

    size_t i, s3 = (Size >> 3);
    for (i = 0; i < s3; i++)
    {
        m_gc.gostcrypt((u4 *)hKey, (word32 *)n12);
#ifdef BIG_ENDIAN_ALGO
        n12[0] ^= be_bswap32(((const _dword*)InData)[i * 2]);
        n12[1] ^= be_bswap32(((const _dword*)InData)[i * 2 + 1]);
#else
        n12[0] ^= ((const _dword*)InData)[i * 2];
        n12[1] ^= ((const _dword*)InData)[i * 2 + 1];
#endif
        //((_dword *) OutData)[i * 2] = n12[0];
        //((_dword *) OutData)[i * 2 + 1] = n12[1];
#ifdef LE_BE_TEST
        Sum += ((const unsigned char*)InData)[8 * i + 3] + ((const unsigned char*)InData)[8 * i + 4 + 3];
#else
        Sum += ((const unsigned char*)InData)[8 * i] + ((const unsigned char*)InData)[8 * i + 4];
#endif
    }
    if  (Size & 7)
    {
        _dword t[2] = {0,0};
        memcpy(t, ((const _dword * )InData) + i * 2, Size & 7);
        m_gc.gostcrypt((u4 *)hKey, (word32 *)n12);
#ifdef BIG_ENDIAN_ALGO
        n12[0] ^= be_bswap32(t[0]);
        n12[1] ^= be_bswap32(t[1]);
#else
        n12[0] ^= t[0];
        n12[1] ^= t[1];
#endif
        //memcpy(((_dword *) OutData) + i * 2, &t, Size & 7);
#ifdef LE_BE_TEST
        Sum += ((unsigned char*)t)[0 + 3] + ((unsigned char*)t)[4 + 3];
#else
        Sum += ((unsigned char*)t)[0] + ((unsigned char*)t)[4];
#endif
    }
#ifdef BIG_ENDIAN_ALGO
    _dword SmallBuffer[2] = { be_bswap32(Sum), be_bswap32((_dword)Size) };
#else
    _dword SmallBuffer[2] = { Sum, (_dword)Size };
#endif
    Sum = 0;
#ifdef BIG_ENDIAN_ALGO
    n12[0] = be_bswap32(n12[0]);
    n12[1] = be_bswap32(n12[1]);
#endif
    Encrypt(Key, SmallBuffer, sizeof(SmallBuffer), n12, SmallBuffer, n12);
    unsigned char Buffer [16 * 1024];
    if  ((int)sizeof(Buffer) > HashSize)
    {
        unsigned short * p = (unsigned short *)Buffer;
#ifdef LE_BE_TEST
        for (int i = 0; i < (int)(sizeof(Buffer) / sizeof(short)); i++)
        {
            p[i] = i;
        }
        for (int i = 0; i < (int)(sizeof(Buffer) / sizeof(_IP)); i++)
        {
            *(i + (_IP *)p) = be_bswap32(*(i + (_IP*)p));
        }
#else
        for (int i = 0; i < (int)(sizeof(Buffer) / sizeof(short)); i++)
        {
#ifdef BIG_ENDIAN_ALGO
            p[i] = be_bswap16(i);
#else
            p[i] = i;
#endif
        }
#endif
        Encrypt(Key, Buffer, sizeof(Buffer), n12, Buffer);
        memcpy(Hash, Buffer + sizeof(Buffer) - HashSize, HashSize);
    }
    else
    {
        *((char *)Hash + HashSize - 1) = 0;
        unsigned short * p = (unsigned short *)Hash;
#ifdef LE_BE_TEST
        for (int i = 0; i < (int)(HashSize / sizeof(short)); i++)
        {
            p[i] = i;
        }
        for (int i = 0; i < (int)(HashSize / sizeof(_IP)); i++)
        {
            *(i + (_IP*)p) = be_bswap32(*(i + (_IP*)p));
        }
#else
        for (int i = 0; i < HashSize / (int)sizeof(short); i++)
        {
#ifdef BIG_ENDIAN_ALGO
            p[i] = be_bswap16(i);
#else
            p[i] = i;
#endif
        }
#endif
        Encrypt(Key, Hash, HashSize, n12, Hash);
    }
    for (i = 0; (int)i < HashSize; i++)
    {
        if  (*((char*)Hash + i))
        {
            break;
        }
    }
    if  ((int)i >= HashSize)
    {
        *(char *)Hash = 1;
    }
#ifdef BIG_ENDIAN_ALGO
    for (int j = 0; j < 8; j++)
    {
        hKey[j] = 0;
    }
#endif
}

void CGostBsMaa::JoinHash(const void * Key, const void * Hash1, const void * Hash2, int HashSize, const void * Salt, void * OutHash, void * OutSalt) const noexcept
{
    Key = Key ? Key : m_gc.StaticKey;
    char key[32];
    char __data_buffer[1024 * 2];
    memcpy(key + 16, Key, 16);
    memcpy(key, 16 + (const char *)Key, 16);
    CMaaPtr_<char, 1> __Data(HashSize <= 1024 ? 0 : 2 * HashSize);
    char * pData = HashSize <= 1024 ? __data_buffer : (char *)__Data;
    memcpy(pData, Hash2, HashSize);
    memcpy(HashSize + pData, Hash1, HashSize);
    const _qword _Salt = htonq(1);
    Salt = Salt ? Salt : &_Salt;
    OutSalt = OutSalt ? OutSalt : (void *)Salt;
    //Encrypt(Key, pData, 2 * HashSize, Salt, pData, OutSalt);
    Encrypt(key, pData, 2 * HashSize, Salt, pData, OutSalt);
    memcpy(OutHash, pData, HashSize); // !!! 2021: memcpy(OutHash, pData + HashSize, HashSize); ???
    memset(key, 0, 32);
    memset(pData, 0, 2 * HashSize);
}

void CGostBsMaa::GenSalt(void *OutSalt) const
{
    memset(OutSalt, 0, 8);
    GetRnd(OutSalt, 8);
    const _dword _0[2] = {0, 0};
    if  (!ConstMemcmp(OutSalt, _0, 8))
    {
        *(char *)OutSalt = 1;
    }
}

void CGostBsMaa::GenKey(void *OutKey) const
{
    memset(OutKey, 0, 32);
    GetRnd(OutKey, 32);
    int i;
    for (i = 0; i < 32; i++)
    {
        if  (*((char*)OutKey + i))
        {
            break;
        }
    }
    if  (i >= 32)
    {
        *(char *)OutKey = 1;
    }
}

void CGostBsMaa::GenKeyByPassword(CMaaString strPassword, void *OutKey, void * Salt, int VariableSalt) const
{
    _qword Salt_ = htonq(12345);
    if  (Salt)
    {
        if  (VariableSalt < 0)
        {
            // use existed
        }
        else if (VariableSalt)
        {
            /*gGostBsMaa.*/GenSalt(Salt);
        }
        else
        {
            *(_qword *)Salt = htonq(918273645);
        }
        Salt_ = *(_qword *)Salt;
    }
    /*
    if (strPassword.IsEmpty())
    {
        memcpy(OutKey, m_gc.StaticKey, 32);
    }
    else
    */
    {
        /*gGostBsMaa.*/Hash(nullptr, strPassword, strPassword.Length(), &Salt_, OutKey, 32);
    }
    char zero[32];
    memset(zero, 0, 32);
    if  (!ConstMemcmp(OutKey, zero, 32))
    {
        *(char *)OutKey = 1;
    }
    //return;
}

CMaaString CGostBsMaa::GeneratePassword(int len) const
{
    if  (len < 1 || len > 10 * 1024)
    {
        len = 32;
    }
    //CMaaString Alphabet = "ABCDEFGHIJKLMNPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890";
    const int AlphabetsCount = 2;
    int StrictMode = 1;
    CMaaString Alphabet[AlphabetsCount] =
    {
        "ABCDEFGHIJKLMNPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "0123456789"
    };
    int Probability[AlphabetsCount] = {70, 30};
    CMaaString ResultedPassword(nullptr, len);
    for (int nnn = 0; nnn < 1000; nnn++)
    {
        ResultedPassword.Fill();
        int Mask = 0;
        for (int i = 0; i < len; i++)
        {
            unsigned int random = 0;
            GetRnd(&random, (int)sizeof(random));
            int alpha = random % (unsigned)AlphabetsCount;

            random = 0;
            GetRnd(&random, (int)sizeof(random));
            int index = random % (unsigned)Alphabet[alpha].Length();
            ResultedPassword[i] = /*(char)*/Alphabet[alpha][index];
            Mask |= (1 << alpha);
        }
        if  (!StrictMode || len < 2 || Mask + 1 == (1 << AlphabetsCount))
        {
            break;
        }
    }
    return ResultedPassword;
}

CMaaString CGostBsMaa::EncryptByPassword(CMaaString strPassword, CMaaString Data) const
{
    char key[32];
    _qword Salt;
    _qword Imito_ = 0;
    CMaaString _data(nullptr, (int)(sizeof(Salt) + Data.Length() + sizeof(Imito_)));
#define dbg_write(filename, ptr, size) {}//{CMaaFile f(filename, CMaaFile::eWCD_SrSw, eNoExcept); f.Write(ptr, size); }
    if  (_data.Length() == (int)(sizeof(Salt) + Data.Length() + sizeof(Imito_)))
    {
        char * p = (char *)(const char *)_data;

        GenKeyByPassword(strPassword, key, &Salt);

        _qword ImitoSalt = htonq(ntohq(Salt) + 1);
        ImitoSalt = ImitoSalt ? ImitoSalt : htonq(1);
        Imito(key, Data, Data.Length(), &Imito_, &ImitoSalt);
        Encrypt(key, Data, Data.Length(), &Salt, p + sizeof(Salt), nullptr);
        dbg_write("e.key", key, 32);
        memset(key, 0, 32);
        *(_qword *)p = Salt;
        *(_qword *)(p + sizeof(_qword) + Data.Length()) = Imito_;
        dbg_write("e.Salt", &Salt, 8);
        dbg_write("e.Imito", &Imito_, 8);
        Salt = Imito_ = ImitoSalt = 0;
        return _data;
    }
    CMaaString Empty;
    return Empty;
}

CMaaString CGostBsMaa::DecryptByPassword(CMaaString strPassword, CMaaString Data, bool &bResult) const
{
    bResult = false;

    const StrInt DataLength = Data.Length() - 2 * (int)sizeof(_qword);
    if  (DataLength >= 0)
    {
        char key[32];
        _qword Salt;
        _qword Imito_ = 0;
        CMaaString _data(nullptr, DataLength);
        if  (_data.Length() == DataLength)
        {
            const char * psrc = Data;
            char * p = (char *)(const char *)_data;

            Salt = *((_qword *)psrc);
            GenKeyByPassword(strPassword, key, &Salt, -1);
            Salt = *((_qword *)psrc);
            _qword ImitoSalt = htonq(ntohq(Salt) + 1);
            ImitoSalt = ImitoSalt ? ImitoSalt : htonq(1);
            Decrypt(key, sizeof(Salt) + (const char *)Data, DataLength, &Salt, p, nullptr);
            Imito(key, p, DataLength, &Imito_, &ImitoSalt);
            dbg_write("d.key", key, 32);
            dbg_write("d.Salt", &Salt, 8);
            dbg_write("d.Imito", &Imito_, 8);
            dbg_write("d.data", p, DataLength);
            memset(key, 0, 32);
            if  (Imito_ == *(_qword *)(psrc + DataLength + sizeof(Salt)))
            {
                Salt = Imito_ = ImitoSalt = 0;
                bResult = true;
                return _data;
            }
            Salt = Imito_ = ImitoSalt = 0;
        }
    }
    CMaaString Empty;
    return Empty;
}

extern "C" int gggCryptSection1(int x);

extern "C" int gExtData;

int gExtData = 11;

int gggCryptSection1(int x)
{
    return x + gExtData;
}

#ifndef __unix__

void GostTest()
{
    {
        HANDLE hp = GetCurrentProcess();
        //DWORD Id = GetCurrentProcessId();
        //GetCurrentProcessHandle(&hp);
        unsigned char Buffer[128];
        SIZE_T s = 0;
        unsigned char * p = (unsigned char *)&gggCryptSection1;
        if  (*p == 0xe9)
        {
            printf("jump\n");
            p += 5 + *(_dword *)(p + 1);
        }
        ReadProcessMemory(hp, p, Buffer, 128, &s);
        printf("s = %d\n", (int)s);
        int i;
        for (i = 0; i < (int)s; i++)
        {
            printf("%02x ", Buffer[i]);
        }
        printf("\n    %d\n", Buffer[35]);
        int index = 8;
#ifdef _DEBUG
        index  = 35;
#endif
        if  (Buffer[index] == 1)
        {
            printf("fixing ...");
            Buffer[index] = Buffer[index] + 100;
        }
        else
        {
            printf("pattern not matched\n");
        }
        s = 0;
        WriteProcessMemory(hp, p, Buffer, index + 1, &s);
        printf("%d bytes written.\n", (int)s);
        printf("gggCryptSection1(11) = %d\n", gggCryptSection1(11));
        static int aa = 0;
        aa++;
    }

    //GostMain();   return;

    return;

    CGostBsMaa g;

#define N 10000

    u4   k[8], data[N], data2[N], Salt[2];
    for (int i = 0; i < 1000; i++)
    {
        GetRnd(k, sizeof(k));
        //for   (int j = 0; j < 100; j++)
        {
            GetRnd(data, sizeof(data));
            GetRnd(Salt, sizeof(Salt));

            g.Encrypt(k, data, sizeof(data), Salt, data2);
            g.Decrypt(k, data2, sizeof(data2), Salt, data2);

            if  (!ConstMemcmp(data, data2, sizeof(data)))
            {
                printf("\r%d --> OK", i);
            }
            else
            {
                printf("\r%d - FAIL enc->dec\n", i);
            }

            g.Decrypt(k, data, sizeof(data), Salt, data2);
            g.Encrypt(k, data2, sizeof(data2), Salt, data2);

            if  (!ConstMemcmp(data, data2, sizeof(data)))
            {
                printf("\r%d <-- OK", i);
            }
            else
            {
                printf("\r%d - FAIL dec->enc\n", i);
            }
        }
    }
    printf("\nDone\n");
}

#endif

#if 0
void GostMain()
{
    gost_ctx   gc;
    u4   k[8], k2[8], data[10], data2[10];
    int   i ;
    /* Initialize GOST context. */
    gost_init (&gc);
    /* Prepare key—a simple key should be 0K, with this many rounds! */
    for (i=0;i<8;i++)
    {
        k[i] = i;
        k2[i] = htonl(k[i]);
    }
    k[1]=0;
    k2[1] = htonl(k[1]);

    gost_key(&gc,k);
    /*   Try   some   test  vectors.   */
    data[0]   = 0;   data[1]   =  0;
    gostcrypt(&gc,data);
    printf("Enc   of   zero vector:      %08lx   %08lx\n",data[0],data[1]);
    gostcrypt(&gc,data);
    printf("Enc of above:       %08lx %08lx\n",data[0],data[1]);
    data[0] = 0xffffffff; data[1] = 0xffffffff;
    gostcrypt (&gc,data) ;
    printf("Enc   of  ones  vector:      %08lx   %08lx\n",data[0],data[1]);
    gostcrypt(&gc,data);
    printf("Enc  of above:             %08lx  %08lx\n",data[0],data[1]);
    /* Does gost dec () properly reverse gost enc [) '-
        we deal OK with single-block lengths passed in gost dec()? Do we deal OK with different lengths passed in? */
    /* Init data */
    for (i=0;i<10;i++) data[i]=data2[i]=i;
    data[1]=data2[1] = 0;
    /* Encrypt data as 5 blocks. */
    gost_enc (&gc,data,5);
    __SimpleSubstEncrypt(gc.k, data2, 5, data2);

    /* Display encrypted data. */
    for (i=0;i<10;i+=2) printf("Block %02d = %08lx %08lx (%08lx %08lx)\n", i/2, data[i],data[i+1], data2[i],data2[i+1]);
    /* Decrypt in different sized chunks. */
    gost_dec(&gc,data,1);
    gost_dec(&gc,data+2,4);
    __SimpleSubstDecrypt(gc.k, data2, 5, data2);
    printf("\n");
    /*   Display  decrypted data.    */
    for (i=0;i<10;i+=2) printf("Block %02d = %08lx %08lx (%08lx %08lx)\n", i/2, data[i],data[i+1], data2[i],data2[i+1]);
    gost_destroy(&gc);
}
#endif

#if 0
// GetSystemFixedKey
bool GetSFKey(void * p, const void * Salt = nullptr)
{
    unsigned long Salt2[2];
    if  (!Salt)
    {
        Salt = Salt2;
        Salt2[0] = 0x12345678;
        Salt2[1] = 0x9abcdef0;
    }

    CMaaString RootPathName = CMaaFile::GetWindowsDirectory();
    if  (RootPathName.IsEmpty())
    {
        RootPathName = "C:\\";
    }
    if  (RootPathName[0] != '\\')
    {
        int n = RootPathName.Find('\\');
        if  (n >= 0)
        {
            RootPathName = RootPathName.Left(n + 1);
        }
    }
    else
    {
        if  (RootPathName[1] == '\\')
        {
            int n = RootPathName.Find(2, '\\');
            if  (n >= 0)
            {
                n = RootPathName.Find(n + 1, '\\');
                if  (n >= 0)
                {
                    RootPathName = RootPathName.Left(n + 1);
                }
                else
                {
                    RootPathName += "\\";
                }
            }
        }
    }

    TCHAR VolumeNameBuffer[MAX_PATH + 10];

    DWORD VolumeSerialNumber = 0, MaximumComponentLength, FileSystemFlags;

    TCHAR FileSystemNameBuffer[MAX_PATH + 10];

    BOOL Ret = GetVolumeInformation(
         MkFs_cast(MkFsNative(MkFsCompatible(RootPathName))),
         VolumeNameBuffer, sizeof(VolumeNameBuffer) / sizeof(TCHAR),
         &VolumeSerialNumber,
         &MaximumComponentLength,
         &FileSystemFlags,
         FileSystemNameBuffer, sizeof(FileSystemNameBuffer) / sizeof(TCHAR)
         );
    if  (!Ret)
    {
        DWORD x = GetLastError();
        memset(p, 0, 32);
    }
    else
    {
        gGostBsMaa.Hash(nullptr, &VolumeSerialNumber, sizeof(VolumeSerialNumber), Salt, p, 32);
    }
    return Ret ? true : false;
}

bool DecryptSFK(CMaaString &ttt)
{
    CMaaString txt = ttt.NewCopy();
    if  (txt.Length() >= 5 * sizeof(long))
    {
        const char * p = txt;
        const void * Salt = p;
        const void * Imito = p + 2 * sizeof(long);
        p += 4 * sizeof(long);
        char Key[32];
        if  (GetSFKey(Key, Salt))
        {
            gGostBsMaa.Decrypt(Key, p, txt.Length() - 4 * sizeof(long), Salt);
            long Imito2[2] = {0, 0};
            gGostBsMaa.Imito(Key, p, txt.Length() - 4 * sizeof(long), Imito2, Salt);
            if  (!ConstMemcmp(Imito, Imito2, sizeof(Imito2)))
            {
                Imito2[0] = Imito2[1] = 0;
                int Len = ntohl(*(long *)p);
                if  (Len <= txt.Length() - 5 * (int)sizeof(long))
                {
                    ttt = txt.Mid(5 * sizeof(long), Len);
                    if  (ttt.Length() == Len)
                    {
                        return true;
                    }
                }
            }
            Imito2[0] = Imito2[1] = 0;
        }
    }
    txt.Fill(0);
    ttt.Empty();
    return false;
}

bool EncryptSFK(CMaaString &ttt, int MinTextLen = 256)
{
    int Len2 = ttt.Length() > MinTextLen ? ttt.Length() : MinTextLen;
    CMaaString txt = CMaaString(nullptr, Len2 + 5 * sizeof(long));
    if  (txt.Length() == Len2 + 5 * sizeof(long))
    {
        char * p = (char *)(const char *)txt;
        void * Salt = p;
        void * Imito = p + 2 * sizeof(long);
        p += 4 * sizeof(long);
        *(long *)p = htonl(ttt.Length());
        memcpy(p + sizeof(long), ttt, ttt.Length());
        if  (Len2 > ttt.Length())
        {
            GetRnd(p + sizeof(long) + ttt.Length(), Len2 - ttt.Length());
        }
        char Key[32];
        gGostBsMaa.GenSalt(Salt);
        if  (GetSFKey(Key, Salt))
        {
            gGostBsMaa.Imito(Key, p, Len2 + sizeof(long), Imito, Salt);
            gGostBsMaa.Encrypt(Key, p, Len2 + sizeof(long), Salt);
            ttt.Fill(0);
            ttt = txt;
            return true;
        }
    }
    txt.Fill(0);
    ttt.Fill(0);
    ttt.Empty();
    return false;
}

bool EncryptSFK2(CMaaString &ttt)
{
    if  (EncryptSFK(ttt))
    {
        ttt = ::Export(ttt, ttt.Length());
        return true;
    }
    return false;
}

bool DecryptSFK2(CMaaString &ttt)
{
    LongInt2 p(ttt.Length() / 2);
    if  (::Import(p, ttt) >= 0)
    {
        ttt = CMaaString(p(), p.GetSize());
        return DecryptSFK(ttt);
    }
    return false;
}
#endif

void GostMain() noexcept
{
    CGostBsMaa g;
    _dword k[8];
    int i;
    for (i = 0; i < 8; i++) k[i] = i;
    _dword Data[21], Data2[21], Data3[21];
    for (i = 0; i < 21; i++) Data[i] = i;
    const _dword Salt[2] = {1, 2};
    _dword Salt2[2];
    const size_t NN = 20 * sizeof(_dword);

    g.Encrypt(k, Data, NN / 2, Salt, Data2, Salt2);
    g.Encrypt(k, Data + 10, NN / 2 + 4, Salt2, Data2 + 10, nullptr);
    g.Decrypt(k, Data2, NN + 4, Salt, Data3, nullptr);

    for (i = 0; i < 21; i++)
    {
        printf("%02d. %08x %08x %08x\n", i, Data[i], Data2[i], Data3[i]);
    }
}


// test class for comparison opt
struct gost_ctx_tst
{
    //u4   k[8];
    //   Constant   s-boxes   --  set   up   in   gost_init().
    //
    // Брюс Шнайдер:
    // char  k87[256],k65[256],k43[256],k21[256];
    //
    // Моисеенко Андрей:
    // unsigned char  k87[256],k65[256],k43[256],k21[256];
    //
    unsigned char k87[256], k65[256], k43[256], k21[256];
    unsigned char StaticKey[32];

    gost_ctx_tst();
    ~gost_ctx_tst();
    word32 f(word32 x);
    void gostcrypt(u4* key, word32* d);
    void gostcrypt16(u4* key, word32* d);
    void gostdecrypt(u4* key, u4* d);
    void gost_enc(u4* key, u4*, int);
    void gost_dec(u4* key, u4*, int);
    //void  gost_key(gost_ctx *, u4 *);
};
/*   Note:     encrypt  and  decrypt   expect   full   blocks—padding  blocks   is
                        caller's   responsibility.      All  bulk  encryption   is  done   in
                        ECB  node by   these  calls.      Other  modes  may  be  added  easily
                        enough.
*/
gost_ctx_tst::gost_ctx_tst()
{
    int   i;
    const byte k8[16] = { 14,    4,   13,    1,    2,   15, 11,  8,  3, 10,  6,   12,    5,    9,    0,    7 };
    const byte k7[16] = { 15,    1,    8,   14,    6,   11,  3,  4,  9,  7,  2,   13,   12,    0,    5,   10 };
    const byte k6[16] = { 10,    0,    9,   14,    6,    3, 15,  5,  1, 13, 12,    7,   11,    4,    2,    8 };
    const byte k5[16] = { 7,   13,   14,    3,    0,    6,  9, 10,  1,  2,  8,    5,   11,   12,    4,   15 };
    const byte k4[16] = { 2,   12,    4,    1,    7,   10, 11,  6,  8,  5,  3,   15,   13,    0,   14,    9 };
    const byte k3[16] = { 12,    1,   10,   15,    9,    2,  6,  8,  0, 13,  3,    4,   14,    7,    5,   11 };
    const byte k2[16] = { 4,   11,    2,   14,   15,    0,  8, 13,  3, 12,  9,    7,    5,   10,    6,    1 };
    const byte k1[16] = { 13,    2,    8,    4,    6,   15, 11,  1,  10, 9,  3,   14,    5,    0,   12,    7 };

    for (i = 0; i < 256; i++)
    {
        k87[i] = (k8[i >> 4] << 4 | k7[i & 15]);
        k65[i] = (k6[i >> 4] << 4 | k5[i & 15]);
        k43[i] = (k4[i >> 4] << 4 | k3[i & 15]);
        k21[i] = (k2[i >> 4] << 4 | k1[i & 15]);
    }

    for (i = 0; i < 32; i++)
    {
        StaticKey[i] = i + 1;
    }
}
gost_ctx_tst::~gost_ctx_tst()
{
    memset(StaticKey, 0, 32);
}

word32 gost_ctx_tst::f(word32 x)
{
    x = k87[x >> 24 & 255] << 24 | k65[x >> 16 & 255] << 16 | k43[x >> 8 & 255] << 8 | k21[x & 255];
    //   Rotate   left   11  bits
    return  x << 11 | x >> (32 - 11);
}

void gost_ctx_tst::gostcrypt(u4* key, word32* d)
{
    register  word32  n1, n2;   //   As naned in the GOST
    n1 = d[0];
    n2 = d[1];
    // Instead of swapping halves, swap names each round
    n2 ^= f(n1 + key[0]);  n1 ^= f(n2 + key[1]);
    n2 ^= f(n1 + key[2]);  n1 ^= f(n2 + key[3]);
    n2 ^= f(n1 + key[4]);  n1 ^= f(n2 + key[5]);
    n2 ^= f(n1 + key[6]);  n1 ^= f(n2 + key[7]);
    n2 ^= f(n1 + key[0]);  n1 ^= f(n2 + key[1]);
    n2 ^= f(n1 + key[2]);  n1 ^= f(n2 + key[3]);
    n2 ^= f(n1 + key[4]);  n1 ^= f(n2 + key[5]);
    n2 ^= f(n1 + key[6]);  n1 ^= f(n2 + key[7]);
    n2 ^= f(n1 + key[0]);  n1 ^= f(n2 + key[1]);
    n2 ^= f(n1 + key[2]);  n1 ^= f(n2 + key[3]);
    n2 ^= f(n1 + key[4]);  n1 ^= f(n2 + key[5]);
    n2 ^= f(n1 + key[6]);  n1 ^= f(n2 + key[7]);
    n2 ^= f(n1 + key[7]);  n1 ^= f(n2 + key[6]);
    n2 ^= f(n1 + key[5]);  n1 ^= f(n2 + key[4]);
    n2 ^= f(n1 + key[3]);  n1 ^= f(n2 + key[2]);
    n2 ^= f(n1 + key[1]);  n1 ^= f(n2 + key[0]);
    d[0] = n2;
    d[1] = n1;
}

void gost_ctx_tst::gostcrypt16(u4* key, word32* d)
{
    register  word32  n1, n2;   //   As naned in the GOST
    n1 = d[0];
    n2 = d[1];
    // Instead of swapping halves, swap names each round
    n2 ^= f(n1 + key[0]);  n1 ^= f(n2 + key[1]);
    n2 ^= f(n1 + key[2]);  n1 ^= f(n2 + key[3]);
    n2 ^= f(n1 + key[4]);  n1 ^= f(n2 + key[5]);
    n2 ^= f(n1 + key[6]);  n1 ^= f(n2 + key[7]);
    n2 ^= f(n1 + key[0]);  n1 ^= f(n2 + key[1]);
    n2 ^= f(n1 + key[2]);  n1 ^= f(n2 + key[3]);
    n2 ^= f(n1 + key[4]);  n1 ^= f(n2 + key[5]);
    n2 ^= f(n1 + key[6]);  n1 ^= f(n2 + key[7]);
    d[0] = n2;
    d[1] = n1;
}

void gost_ctx_tst::gostdecrypt(u4* key, u4* d)
{
    register word32 n1, n2;   // As naned in the GOST
    n1 = d[0];
    n2 = d[1];
    n2 ^= f(n1 + key[0]);  n1 ^= f(n2 + key[1]);
    n2 ^= f(n1 + key[2]);  n1 ^= f(n2 + key[3]);
    n2 ^= f(n1 + key[4]);  n1 ^= f(n2 + key[5]);
    n2 ^= f(n1 + key[6]);  n1 ^= f(n2 + key[7]);
    n2 ^= f(n1 + key[7]);  n1 ^= f(n2 + key[6]);
    n2 ^= f(n1 + key[5]);  n1 ^= f(n2 + key[4]);
    n2 ^= f(n1 + key[3]);  n1 ^= f(n2 + key[2]);
    n2 ^= f(n1 + key[1]);  n1 ^= f(n2 + key[0]);
    n2 ^= f(n1 + key[7]);  n1 ^= f(n2 + key[6]);
    n2 ^= f(n1 + key[5]);  n1 ^= f(n2 + key[4]);
    n2 ^= f(n1 + key[3]);  n1 ^= f(n2 + key[2]);
    n2 ^= f(n1 + key[1]);  n1 ^= f(n2 + key[0]);
    n2 ^= f(n1 + key[7]);  n1 ^= f(n2 + key[6]);
    n2 ^= f(n1 + key[5]);  n1 ^= f(n2 + key[4]);
    n2 ^= f(n1 + key[3]);  n1 ^= f(n2 + key[2]);
    n2 ^= f(n1 + key[1]);  n1 ^= f(n2 + key[0]);
    d[0] = n2;
    d[1] = n1;
}

void gost_ctx_tst::gost_enc(u4* key, u4* d, int blocks)
{
    int i;
    for (i = 0; i < blocks; i++)
    {
        gostcrypt(key, d);
        d += 2;
    }
}

void gost_ctx_tst::gost_dec(u4* key, u4* d, int blocks)
{
    int i;
    for (i = 0; i < blocks; i++)
    {
        gostdecrypt(key, d);
        d += 2;
    }
}

CGostBsMaa_tst::CGostBsMaa_tst()
{
    m_gc = TL_NEW gost_ctx_tst;
    if  (!m_gc)
    {
        throw 1;
    }
    //gost_init(m_gc);
}

CGostBsMaa_tst::~CGostBsMaa_tst()
{
    //gost_destroy(m_gc);
    delete m_gc;
}
// Key - 32 bytes, Salt - 8 bytes, OutSalt - 8 bytes
void CGostBsMaa_tst::Encrypt(const void* Key, const void* InData, size_t Size, const void* Salt, void* OutData, void* OutSalt)
{
    Key = Key ? Key : m_gc->StaticKey;
    OutData = OutData ? OutData : (void*)InData;
    _dword n12[2] = { *(const _dword*)Salt, *((const _dword*)Salt + 1) };

    size_t i;
    for (i = 0; i < (Size >> 3); i++)
    {
        m_gc->gostcrypt((u4*)Key, (word32*)n12);
        n12[0] ^= ((const _dword*)InData)[i * 2];
        n12[1] ^= ((const _dword*)InData)[i * 2 + 1];
        ((_dword*)OutData)[i * 2] = n12[0];
        ((_dword*)OutData)[i * 2 + 1] = n12[1];
    }
    if  (Size & 7)
    {
        _dword t[2] = { 0,0 };
        memcpy(t, ((const _dword*)InData) + i * 2, Size & 7);
        m_gc->gostcrypt((u4*)Key, (word32*)n12);
        t[0] ^= n12[0];
        t[1] ^= n12[1];
        memcpy(((_dword*)OutData) + i * 2, &t, Size & 7);
    }
    if  (OutSalt)
    {
        *(_dword*)OutSalt = n12[0];
        *((_dword*)OutSalt + 1) = n12[1];
    }
}
// Key - 32 bytes, Salt - 8 bytes, OutSalt - 8 bytes
void CGostBsMaa_tst::Decrypt(const void* Key, const void* InData, size_t Size, const void* Salt, void* OutData, void* OutSalt)
{
    Key = Key ? Key : m_gc->StaticKey;
    OutData = OutData ? OutData : (void*)InData;
    _dword n12[2] = { *(const _dword*)Salt, *((const _dword*)Salt + 1) };
    _dword N12[2];

    size_t i;
    for (i = 0; i < (Size >> 3); i++)
    {
        m_gc->gostcrypt((u4*)Key, (word32*)n12);
        N12[0] = ((const _dword*)InData)[i * 2];
        N12[1] = ((const _dword*)InData)[i * 2 + 1];

        ((_dword*)OutData)[i * 2] = n12[0] ^ N12[0];
        ((_dword*)OutData)[i * 2 + 1] = n12[1] ^ N12[1];

        n12[0] = N12[0];
        n12[1] = N12[1];
    }
    if  (Size & 7)
    {
        _dword t[2] = { 0,0 };
        memcpy(t, ((const _dword*)InData) + i * 2, Size & 7);
        m_gc->gostcrypt((u4*)Key, (word32*)n12);
        t[0] ^= n12[0];
        t[1] ^= n12[1];
        memcpy(((_dword*)OutData) + i * 2, &t, Size & 7);
    }
    if  (OutSalt)
    {
        *(_dword*)OutSalt = n12[0];
        *((_dword*)OutSalt + 1) = n12[1];
    }
}

void CGostBsMaa_tst::Imito(const void* Key, const void* InData, size_t Size, void* ImitoValue, const void* Salt, const void* End)
{
    Key = Key ? Key : m_gc->StaticKey;
    _dword n12[2], t[2];
    if  (Salt)
    {
        memcpy(n12, Salt, sizeof(n12));
    }
    else
    {
        n12[0] = n12[1] = 0;
    }

    size_t i;
    for (i = 0; i < (Size >> 3); i++)
    {
        n12[0] ^= ((_dword*)InData)[i * 2];
        n12[1] ^= ((_dword*)InData)[i * 2 + 1];
        m_gc->gostcrypt16((u4*)Key, (word32*)n12);
    }
    if  (Size & 7)
    {
        if  (End)
        {
            memcpy(t, End, sizeof(t));
        }
        else
        {
            t[0] = t[1] = 0;
        }
        memcpy(t, ((_dword*)InData) + i * 2, Size & 7);
        n12[0] ^= t[0];
        n12[1] ^= t[1];
        m_gc->gostcrypt16((u4*)Key, (word32*)n12);
        t[0] = t[1] = 0;
    }
    *(_dword*)ImitoValue = n12[0];
    *(((_dword*)ImitoValue) + 1) = n12[1];
}

#if 0
//#define BE_ON_LE_TEST
static int test_gost_speed()
{
    const char* a = "12345678";
    const char* b = "abcdefgh";
    const char* ab = "12345678abcdefgh";
    _dword Salta[2] = { 1234, 5678 };
    _uqword Imitoa, Imitob, Imitoab;
    CGostBsMaa gab;
    gab.Imito(nullptr, a, 8, &Imitoa, Salta);
    gab.Imito(nullptr, b, 8, &Imitob, &Imitoa);
    gab.Imito(nullptr, ab, 16, &Imitoab, Salta);
    __utf8_printf("%08llW %08llW %d\n", Imitob, Imitoab, Imitob == Imitoab);

    //return 0;
    unsigned char StaticKey[32]
#ifdef BE_ON_LE_TEST
        , StaticKeySw[32]
#endif
        ;
    //#define _StaticKey nullptr
    //#define _StaticKeySw nullptr
#define _StaticKey StaticKey
#ifdef BE_ON_LE_TEST
#define _StaticKeySw StaticKeySw
#else
#define _StaticKeySw _StaticKey
#endif

    int i;
    for (i = 0; i < 32; i++)
    {
        StaticKey[i] = i + 1;
    }
#ifdef BE_ON_LE_TEST
    for (i = 0; i < 8; i++)
    {
        *(i + (_IP*)StaticKeySw) = my_htonl_le(*(i + (_IP*)StaticKey));
    }
#endif

    if (0)
    {
#ifdef BE_ON_LE_TEST
        _dword Salt[2] = { my_htonl_le(1), my_htonl_le(2) };
#else
        _dword Salt[2] = { 1, 2 }; _qword so1 = 0, so1_ = 0;
#endif
        CMaaString D = (char*)"abcdefgh", H(nullptr, 32);
#ifdef BE_ON_LE_TEST
        * (_dword*)D.GetBuffer() = my_htonl_le(*(_dword*)D.GetBuffer());
        *(1 + (_dword*)D.GetBuffer()) = my_htonl_le(*(1 + (_dword*)D.GetBuffer()));
#endif
        CGostBsMaa g;
        g.Hash(_StaticKeySw, D, D.Length(), Salt, H.GetBuffer(), H.Length());
#ifdef BE_ON_LE_TEST
        for (i = 0; i < 8; i++)
        {
            *(i + (_dword*)(H.GetBuffer())) = my_htonl_le(*(i + (_dword*)(H.GetBuffer())));
        }
#endif
        __utf8_printf("Hash = %m", (const char*)H, H.Length());
        /*
        61 D0 5E 00 AB 0C 4C BB 61 B2 07 F2 90 A3 57 BD
        EA 0C 41 BE 51 A7 3C 07 04 FC F6 7F EB D0 FA 3E
        */
    }

    const int len = 100 * 1024 * 1024 - 1;
    unsigned char* t1 = new unsigned char[len + 1];
    unsigned char* t2 = new unsigned char[len];
    unsigned char* t1_ = new unsigned char[len];
    unsigned char* t2_ = new unsigned char[len];
    if (!t1 || !t2 || !t1_ || !t2_)
    {
        delete[] t2_;
        delete[] t1_;
        delete[] t2;
        delete[] t1;
        return -1;
    }
    t1[len] = 0;
    memset(t1, 123, len);
#ifdef BE_ON_LE_TEST
    for (i = 0; i < len / 4; i++)
    {
        *(i + (_IP*)t1) = my_htonl_le(*(i + (_IP*)t1));
    }
#endif
    CMaaTime tx = GetHRTime();
    tx.StartWatch();
    while (tx.GetTime(1000000) < 4000000);
#ifdef BE_ON_LE_TEST
    _dword Salt1[2] = { my_htonl_le(1), my_htonl_le(2) }; _qword so1 = 0, so1_ = 0;
#else
    _dword Salt1[2] = { 1, 2 }; _qword so1 = 0, so1_ = 0;
#endif
    _dword Salt2[2] = { 1, 2 }; _qword so2 = 0, so2_ = 0;
    CGostBsMaa g;
    _dword Imito1[2], Imito1_[2];
    tx.StartWatch();
    //g.Imito(_StaticKey, t1, len, Imito1, Salt1);
    //g.Encrypt(_StaticKey, t1, len, Salt1);

    g.EncryptImito(_StaticKeySw, t1, len, Imito1, Salt1, nullptr, &so1);
    //_dword i2[2], s2[2];
    //g.EncryptImito(_StaticKeySw, t1, len / 2, i2, Salt1, nullptr, &s2);
    //g.EncryptImito(_StaticKeySw, t1 + len / 2, len / 2, Imito1, s2, nullptr, &so1);

    //g.Decrypt(_StaticKey, c1text, len, Salt1, o1text);
    _qword u = tx.GetTime(1000000);

    g.DecryptImito(_StaticKeySw, t1, len, Imito1_, Salt1, t1_, &so1_);
    //g.DecryptImito(_StaticKeySw, t1, len / 2, i2, Salt1, t1_, &s2);
    //g.DecryptImito(_StaticKeySw, t1 + len / 2, len / 2, Imito1_, s2, t1_ + len / 2, &so1_);

    const double x1 = (double)len / u * 1000000.0;
    __utf8_printf("so1=%0llW, so1_=%0llW, *m=%0llW\n", so1, so1_, *(_qword*)(t1 + len - 7));
    printf("CGostBsMaa::Encrypt():      x1 = %.0lf B/s = %.2lf KB/s = %.3lf MB/s = %.3lf mbits/s\n", x1, x1 / 1024, x1 / 1024 / 1024, x1 * 8 / 1000000);
#ifdef BE_ON_LE_TEST
    Imito1[0] = my_htonl_le(Imito1[0]);
    Imito1[1] = my_htonl_le(Imito1[1]);
    Imito1_[0] = my_htonl_le(Imito1_[0]);
    Imito1_[1] = my_htonl_le(Imito1_[1]);
    for (i = 0; i < len / 4; i++)
    {
        *(i + (_IP*)t1) = my_htonl_le(*(i + (_IP*)t1));
        *(i + (_IP*)t1_) = my_htonl_le(*(i + (_IP*)t1_));
    }
#endif
    memset(t2, 123, len);

    //CGostBsMaa_tst g_tst;
    CGostBsMaa g_tst;
    _dword Imito2[2], Imito2_[2];
    tx.StartWatch();
    g_tst.Imito(_StaticKey, t2, len, Imito2, Salt2);
    g_tst.Encrypt(_StaticKey, t2, len, Salt2, nullptr, &so2);
    //GOST_Crypt_GF_Data(t2, len, (uint8_t*)Salt2, _GOST_Mode_Encrypt, Gost_Table_BS, StaticKey); // mismatch and slower
    //g.Decrypt(nullptr, c1text, len, Salt1, o1text);
    u = tx.GetTime(1000000);
    g_tst.Decrypt(_StaticKey, t2, len, Salt2, t2_, &so2_);
    g_tst.Imito(_StaticKey, t2_, len, Imito2_, Salt2);
    const double x2 = (double)len / u * 1000000.0;
    //__utf8_printf("so2=%0llW, so2_=%0llW\n", so2, so2_);
    printf("CGostBsMaa_tst::Encrypt():  x2 = %.0lf B/s = %.2lf KB/s = %.3lf MB/s = %.3lf mbits/s\n", x2, x2 / 1024, x2 / 1024 / 1024, x2 * 8 / 1000000);

    printf("x2/x1 = %.6lf, x1/x2 = %.6lf\n", x2 / x1, x1 / x2);

    if (ConstMemcmp(t2, t1, len))
    {
        printf("t2 != t1\n");
    }
    if (ConstMemcmp(t2_, t1_, len))
    {
        printf("t2_ != t1_\n");
    }
    if (ConstMemcmp(Imito2, Imito1, sizeof(Imito1)))
    {
        __utf8_printf("Imito2 != Imito1: %0llW != %0llW\n", *(_qword*)Imito2, *(_qword*)Imito1);
    }
    if (ConstMemcmp(Imito2_, Imito1_, sizeof(Imito1_)))
    {
        __utf8_printf("Imito2_ != Imito1_: %0llW != %0llW\n", *(_qword*)Imito2_, *(_qword*)Imito1_);
    }
    if (ConstMemcmp(Imito2, Imito2_, sizeof(Imito2)))
    {
        __utf8_printf("Imito2 != Imito2_: %0llW != %0llW\n", *(_qword*)Imito2, *(_qword*)Imito2_);
    }

    delete[] t2_;
    delete[] t1_;
    delete[] t2;
    delete[] t1;
    return 0;
}
#endif
