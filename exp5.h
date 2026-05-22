
// CryptLib Project

/* CryptLib library for RusRoute firewall and other projects of
 * Andrey A. Moiseenko / IE Moiseenko A.A. (Russia)
 * e-mail: support@maasoftware.ru, maa2002@mail.ru
 * web: http://maasoftware.ru, http://maasoftware.com, http://maasoft.ru, http://maasoft.org
 * Author's full name: Andrey Alekseevitch Moiseenko
 * (russian name: Моисеенко Андрей Алексеевич)
 */

// CryptLib/exp5.h

/* Copyright (C) 2002-2024 Andrey A. Moiseenko (support@maasoftware.ru)
 * All rights reserved.
 *
 * This library contains the basic cryptography function,
 * prime numbers checks and generator, random number generator,
 * Mantgomery exponent, symmetric GOST and asymmetric RSA-like.
 * This file is Mantgomery exponent implementation written
 * by Andrey A. Moiseenko (support@maasoftware.ru).
 * Algorithm is given from a book Michael Welschenbach "Kryotographie
 * in C and C++" 1998, 2001 (Михаил Вельшенбах "Криптография на Си и С++
 в действии").
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

class CMyExponent5
{
    void Init(const LongInt2 &P);
protected:
    int m_InitSize;
public:

    _dword m_RealSize;
    _dword m_BSize;
    _dword m_DWSize;

    // k, complexity, calculated reduce count, real reduce count, mul count, sqr count
    int m_k, m_complexity, m_crc, m_rrc, m_mulc, m_sqrc;

    LongInt2 * m_P;
    //LongInt2 * m_R;
    LongInt2 * m_R2;
    LongInt2 * m_MulTable[255];
    unsigned char m_Back;

    int m_TwoTab[256], m_OddTab[256];
    unsigned char m_MulIndex[256];

    void MonMul(const LongInt2 &A, const LongInt2 &B, LongInt2 &Result, LongInt2 &WorkBuffer);
    void MonSqr(const LongInt2 &A, LongInt2 &Result, LongInt2 &WorkBuffer);
    void Reduce(LongInt2 &Result);
    void CreateR_2R();
public:
    CMyExponent5(const LongInt2 &P); // P - odd number for modulo arithmetics
    ~CMyExponent5();
    bool Exponent(const LongInt2 &A, const LongInt2 &X, LongInt2 &Y);

    CMyExponent5(void * P, _dword Size = 64);
    bool Exponent(void * A, void * X, void * Y); // all sizes is m_InitSize==Size
};
