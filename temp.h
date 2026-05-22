
// CryptLib Project

/* CryptLib library for RusRoute firewall and other projects of
 * Andrey A. Moiseenko / IE Moiseenko A.A. (Russia)
 * e-mail: support@maasoftware.ru, maa2002@mail.ru
 * web: http://maasoftware.ru, http://maasoftware.com, http://maasoft.ru, http://maasoft.org
 * Author's full name: Andrey Alekseevitch Moiseenko
 * (russian name: ћоисеенко јндрей јлексеевич)
 */

// CryptLib/temp.h

/* Copyright (C) 2002-2024 Andrey A. Moiseenko (support@maasoftware.ru)
 * All rights reserved.
 *
 * This library contains the basic cryptography function,
 * prime numbers checks and generator, random number generator,
 * Mantgomery exponent, symmetric GOST and asymmetric RSA-like.
 * The library implementation written
 * by Andrey A. Moiseenko (support@maasoftware.ru).
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

#ifndef __CRYPTLIB_TEMP_H
#define __CRYPTLIB_TEMP_H

#ifdef _WIN32
#pragma pack( push, temp_pack_id_1, 1) // using (=1 byte) pack value
#endif

#include "Gost_BS_MAA.h"
#include "Kuznechik_MAA.h"
#include "longint2.h"
#include "RSA.h"
//#include "exp3.h"
//#include "exp4.h"
#include "exp5.h"
//#include "e1.h"
#ifdef __unix__
#include "des/des.h"
#else
#include "des\des.h"
#endif
//#include "ntlm_proxy_auth.h"

void pr(const char * txt, const void * p, int l, int c = 1);
void pr(const char * txt, LongInt2 &x);

#ifndef CRYPTLIB_USE_ASM64
// 0 - p1[] == p2[],  != 0 - p1[] != p2[]
_dword ConstMemcmp(const void* p1, const void* p2, size_t len) noexcept;
#endif

void GetRnd(void *ptr, int s);

class CCryptRandom
{
    int m_Mode;
#ifdef _WIN32
    HCRYPTPROV m_hProv;
#endif
#ifdef __unix__
    CMaaFile m_file;
    int m_nRequestsProcessed;
    CMaaString m_SeedFn;
#endif
    char m_gost_key_and_salt[2 * 32 + 8];
    CGostBsMaa m_gost;
    //CMaaAutoInitObject<bool, true> m_b1st;
    bool m_b1st = true;
    CMaaMutex m_Mutex;
public:
    enum eMode
    {
        eOSCryptFunctionsOnly = 0,
        eOSCryptFunctionsForStartingKey = 0x01,
        eAllowRunTimeRandForStartingKey = 0x02,
        eForcedOSCryptFunctionsForStartingKeyOnly = 0x04,
        eSyncronizeThreads = 0x08,
        eDefaultFast =
#ifdef _WIN32
        eOSCryptFunctionsOnly         | eAllowRunTimeRandForStartingKey
#else
        eOSCryptFunctionsForStartingKey | eAllowRunTimeRandForStartingKey | eForcedOSCryptFunctionsForStartingKeyOnly
#endif
        ,
        eDefaultSyncronized = eDefaultFast | eSyncronizeThreads,
        eDefault = eDefaultSyncronized
    };
    CCryptRandom(int Mode = eDefault, bool bThrow = true);
    int GetSeed(void * ptr, int size);
    int FlushSeed(const void * ptr, int size);
    virtual ~CCryptRandom();
    bool Get(void * ptr, int len); // noexcept
};

class CMyExponent2
{
    int m_Size;
    char * m_P;
    enum
    {
        MUL_TABLE_SIZE = 255
    };
    LongInt2 * m_MulTable [ MUL_TABLE_SIZE ];
public:
    //------------------------------------------------------------------------------
    //   P    -    простое число по модулю которого производитс€ умножение
    //   Size -    размер в байтах простого числа, показател€ и т.п.
    //------------------------------------------------------------------------------
    CMyExponent2 ( void * P = nullptr, _dword Size = 64 );
    ~CMyExponent2 ();
    void Exponent ( void * A, void * X, void * Y );
};

//#define CMyExponent2 CMyExponent3
#define CMyExponent CMyExponent5

int IsPrime(LongInt2 &p, int pass = 0, bool (* ProgressProc)(int pass, int n, int m, void * Param) = nullptr, void * Param = nullptr);
int GenPrime(LongInt2 &p, int R = 0, bool (* ProgressProc)(int pass, int n, int m, void * Param) = nullptr, void * Param = nullptr);
void GetRnd(void *ptr, int size);
void GenRnd(LongInt2 &p, int R = 0);

#include "AntiRobotCaptcha.h"

#ifdef _WIN32
#pragma pack( pop, temp_pack_id_1 )
#endif


#include "sha256/sha.h"
#include "sha256/sha_iface.h"

#define USE_NTLMV1  1
#define USE_NTLM2SESSION   2
#define USE_NTLMV2  3
CMaaString make_type1_msg(const CMaaString& domain_, const CMaaString& host_, int ntlm_resp_type);
CMaaString make_type3_msg(const CMaaString& username_, const CMaaString& password_, const CMaaString& domain_, const CMaaString& host_, const CMaaString& msg2_b64_buff, int ntlm_resp_type);
//#include "ntlm.h"
//#include "util.h"
#include "ntlm_proxy_auth.h"

#endif //__CRYPTLIB_TEMP_H
