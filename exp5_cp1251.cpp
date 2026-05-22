
// CryptLib Project

/* CryptLib library for RusRoute firewall and other projects of
 * Andrey A. Moiseenko / IE Moiseenko A.A. (Russia)
 * e-mail: support@maasoftware.ru, maa2002@mail.ru
 * web: http://maasoftware.ru, http://maasoftware.com, http://maasoft.ru, http://maasoft.org
 * Author's full name: Andrey Alekseevitch Moiseenko
 * (russian name: РњРѕРёСЃРµРµРЅРєРѕ РђРЅРґСЂРµР№ РђР»РµРєСЃРµРµРІРёС‡)
 */

// CryptLib/exp5.cpp

/* Copyright (C) 2002-2024 Andrey A. Moiseenko (support@maasoftware.ru)
 * All rights reserved.
 *
 * This library contains the basic cryptography function,
 * prime numbers checks and generator, random number generator,
 * Mantgomery exponent, symmetric GOST and asymmetric RSA-like.
 * This file is Mantgomery exponent implementation written
 * by Andrey A. Moiseenko (support@maasoftware.ru).
 * Algorithm is given from a book Michael Welschenbach "Kryotographie
 * in C and C++" 1998, 2001 (РњРёС…Р°РёР» Р’РµР»СЊС€РµРЅР±Р°С… "РљСЂРёРїС‚РѕРіСЂР°С„РёСЏ РЅР° РЎРё Рё РЎ++
 РІ РґРµР№СЃС‚РІРёРё").
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
#include "temp.h"

/*
void pr(const char * txt, const void * p, int l, int c)
{
     const unsigned char * pp = (const unsigned char *)p;
     if   (c == 1)
     {
          printf("%s", txt);
          for  (int i = 0; i < l; i++)
          {
               printf("%02X", pp[l - i - 1]);
          }
          printf("\n");
     }
     else
     {
          for (int i = 0; i < c; i++)
          {
               printf("%s[%d] ", txt, i);
               pr("", pp + i * l, l, 1);
          }
     }
}

void pr(const char * txt, LongInt2 &x)
{
     pr(txt, x(), x.GetSize());
}
*/


//#if 0
//------------------------------------------------------------------------------
// Инициализация возводителя
//
// Параметры:
//   P    -    простое число по модулю которого производится умножение
//   Size -    размер в байтах простого числа, показателя и т.п.
// 1. выделяется память под рабочие буфера,
// 2. считается (при необходимости) R по модулю P, и R в квадрате по модулю P
// 3. вычисляется отрицание элемента, обратного младшему байту числа P, это
//    необходимо для преобразования Монтгомери
// 4. Создается таблица умножения числа P от P до P*255
//------------------------------------------------------------------------------
CMyExponent5::CMyExponent5(void * P, _dword Size)
{
    LongInt2 lP(P, m_InitSize = Size);
    Init(lP);
}
CMyExponent5::CMyExponent5(LongInt2 &P)
{
    m_InitSize = P.GetSize();
    Init(P);
}

static int InvMon1(_dword n, int Log2Q)
{
    _dword x = 2, y = 1;

    if  (!(n & 1) || Log2Q > (int)(sizeof(_dword) * 8))
    {
        return 0;
    }

    for (int i = 1; i < Log2Q; i++, x <<= 1)
    {
        if  (((n * y) & ((x << 1) - 1)) >= x)
        {
            y += x;
        }
    }
    return (x - y) & (x - 1);
}

void CMyExponent5::Init(LongInt2 &P)
{
    // получение отрицания числа, обратного к младшему байту P
    /*
     m_Back = 1;
     while(1)
     {
          if   ((unsigned char)(P[0] * m_Back) == 1)
          {
               break;
          }
          if   ((unsigned char)(m_Back += 2) == 1)
          {
               throw "CMyExponent5::Init() error: even number";
          }
     }
     m_Back ^= 255;
     ++m_Back;
     */
    m_Back = InvMon1(P[0], 8);
    if  (!m_Back)
    {
        throw "CMyExponent5::Init() error: even number P";
    }


    // выделяется память под рабочие буфера,
    m_RealSize = P.GetRealSize();
    m_DWSize = (m_RealSize + 3) >> 2;
    m_BSize = m_DWSize << 2;

    int i;
    m_P = NULL;
    //m_R = NULL;
    m_R2 = NULL;
    for (i = 0; i < 255; i++)
    {
        m_MulTable[i] = NULL;
    }

    try
    {
        m_P = TL_NEW LongInt2(m_BSize);
        //m_R = TL_NEW LongInt2(m_BSize);

        m_R2 = TL_NEW LongInt2(m_BSize);

        //m_MulTable = NULL;//( unsigned char * ) calloc ( 255, m_BSize + 4 );

        // если P задан то расчитываем для него соответствующие R и квадрат R
        // иначе используем уже заданные P, R и R в квадрате длины 64 байта
        *m_P = P;

        //------------------------------------------------------------------------------
        // Подготовка таблицы умножения необходимой для преобразования Монтгомери
        //------------------------------------------------------------------------------
        // P, 2*P, 3*P, ... 255*P

        m_MulTable[0] = TL_NEW LongInt2(m_BSize + 4);
        *m_MulTable[0] = *m_P;

        m_MulIndex[0] = 0;
        for (int i = 1; i < 255; i++)
        {
            m_MulTable[i] = TL_NEW LongInt2(m_BSize + 4);
            *m_MulTable[i] = *m_MulTable[i - 1];
            *m_MulTable[i] += *m_P;

            if  (i < 5)
            {
                //pr("mult = ", *m_MulTable[i - 1]);
            }
            m_MulIndex[i] = (unsigned char)(((i * m_Back) & 0xff) - 1);
        }
        m_MulIndex[255] = (unsigned char)(((255 * m_Back) & 0xff) - 1);

        // считается R по модулю P, и R в квадрате по модулю P
        CreateR_2R ();
    }
    catch(...)
    {
        delete m_P;
        //delete m_R;
        delete m_R2;
        for (i = 0; i < 255; i++)
        {
            delete m_MulTable[i];
        }
        throw;
    }
    for (int i = 0; i < 256; i++)
    {
        int j = 0;
        if  (i > 0)
        {
            while((i & (1 << j)) == 0)
            {
                j++;
            }
        }
        m_TwoTab[i] = j;
        m_OddTab[i] = i >> j;
    }
}

//------------------------------------------------------------------------------
// Деструктор возводителя
//
// освобождает ранее выделенные буфера
//------------------------------------------------------------------------------
CMyExponent5::~CMyExponent5 ()
{
    delete m_P;
    //delete m_R;
    delete m_R2;
    for (int i = 0; i < 255; i++)
    {
        delete m_MulTable[i];
    }
}

//------------------------------------------------------------------------------
// Расчет R и R в квадрате по модулю P
//------------------------------------------------------------------------------
void CMyExponent5::CreateR_2R ()
{
    /*
     LongInt2 Buffer1(m_BSize + 1);
     Buffer1[m_BSize] = 1;
     Buffer1 %= *m_P;
     *m_R = Buffer1;
     */
    //pr("m_R = ", *m_R);

    LongInt2 Buffer2((m_BSize << 1) + 1);
    Buffer2[m_BSize << 1] = 1;
    Buffer2 %= *m_P;
    *m_R2 = Buffer2;
    //pr("m_R2 = ", *m_R2);
}


//------------------------------------------------------------------------------
// Умножение больших чисел и преобразование результата по алгоритму Монтгомери
// A      -    первый множитель
// B      -    второй множитель
// Result -    результат
//------------------------------------------------------------------------------
void CMyExponent5::MonMul(LongInt2 &A, LongInt2 &B, LongInt2 &Result, LongInt2 &WorkBuffer)
{
    WorkBuffer.Mul(A, B);

    // Преобразование Монтгомери
    Reduce(WorkBuffer);

    Result = WorkBuffer;
}

//------------------------------------------------------------------------------
// Получение квадрата числа и преобразование результата по алгоритму Монтгомери
// A           -    число которое надо возвести в квадрат
// Result      -    результат
// WorkBuffer  -    рабочий буфер
//------------------------------------------------------------------------------
void CMyExponent5::MonSqr(LongInt2 &A, LongInt2 &Result, LongInt2 &WorkBuffer)
{
    //pr("MonSqr(): A = ", A);
    WorkBuffer.Mul(A, A);

    // Преобразование Монтгомери
    Reduce(WorkBuffer);

    Result = WorkBuffer;
}

//------------------------------------------------------------------------------
// Преобразование Монтгомери
// Result -    уазатель на исходные данные, туда же будет записан результат
//------------------------------------------------------------------------------
void CMyExponent5::Reduce(LongInt2 &Result)
{
    //pr("Reduce(): in: ", Result);
    m_rrc++;

    if  (Result.GetSize() >= (int)(2 * m_BSize + 4))
    {
        int tmp = Result.m_Size2;
        int i = 0;
        try
        {
            for (i = 0; i < (int)m_BSize; i++)
            {
                // определение элемента таблицы умножение P, с которым необходимо
                // сложить, чтобы обнулился младший байт, точнее определение
                // такого K, что K*P + Result [] дает в младшем байте 0
                int a = Result[0];
                if  (a != 0)
                {
                    //a = ((a * m_Back) & 0xff) - 1;
                    //Result += *(m_MulTable[a]);
                    Result += *(m_MulTable[m_MulIndex[a]]);
                }
                Result.m_Number++;
                Result.m_Size--;
                Result.m_TotalSize--;
                //Result.m_Size2 -= (i & 1);
                Result.m_Size2 = (Result.m_Size + sizeof(short) - 1) / sizeof(short);
                //Result >>= 8;
                //memmove(Result(), Result() + 1, Result.GetSize() - 1);
                //Result[Result.GetSize() - 1] = 0;
            }
        }
        catch(const char * msg)
        {
            Result.m_Number -= i;
            Result.m_Size += i;
            Result.m_TotalSize += i;
            Result.m_Size2 = tmp;
            throw msg;
        }
        catch(...)
        {
            Result.m_Number -= i;
            Result.m_Size += i;
            Result.m_TotalSize += i;
            Result.m_Size2 = tmp;
            throw;
        }
        Result.m_Number -= i;
        Result.m_Size += i;
        Result.m_TotalSize += i;
        Result.m_Size2 = tmp;
        Result >>= 8 * i;
    }
    else
    {
        for (int i = 0; i < (int)m_BSize; i++)
        {
            // определение элемента таблицы умножение P, с которым необходимо
            // сложить, чтобы обнулился младший байт, точнее определение
            // такого K, что K*P + Result [] дает в младшем байте 0
            int a = Result[0];
            if  (a != 0)
            {
                //a = ((a * m_Back) & 0xff) - 1;
                //Result += *(m_MulTable[a]);
                Result += *(m_MulTable[m_MulIndex[a]]);
            }
            //Result >>= 8;
            memmove(Result(), Result() + 1, Result.GetSize() - 1);
            Result[Result.GetSize() - 1] = 0;
        }
    }
    //pr("temp Result = ", Result);

    //Result %= *m_P;
    if  (Result >= *m_P)
    {
        Result -= *m_P;
    }
    //pr(" ret Result = ", Result);
}

//------------------------------------------------------------------------------
// Возведение в степень
// A      -    основание
// X      -    показатель
// Y      -    результат
//------------------------------------------------------------------------------
bool CMyExponent5::Exponent(void * A, void * X, void * Y)
{
    LongInt2 a(m_BSize);     a.LoadFromMem(A, m_InitSize);
    LongInt2 x(m_BSize);     x.LoadFromMem(X, m_InitSize);
    LongInt2 y(m_BSize);

    bool bRet = Exponent(a, x, y);
    if  (bRet)
    {
        memcpy(Y, y(), m_InitSize);
    }
    return bRet;
}

void pr(const char * txt, LongInt2 &x);

bool CMyExponent5::Exponent(LongInt2 &A, LongInt2 &X, LongInt2 &Y)
{
    LongInt2 &P = *m_P;

    // Test
    /*
     if(0)
     {
          LongInt2 &R = *m_R;
          LongInt2 b(m_BSize * 2 + 4);
          b[m_BSize * 2] = 1;
          b %= P;
          LongInt2 R2(m_BSize); R2 = b;
          b.Mul(A, R);
          b %= P;
          LongInt2 x1(m_BSize);
          x1 = b;
          MonMul(A, R2, b);
          if   (x1 == b)
          {
               printf("(A * R) mod P == A x (R2 mod P)  -- ok\n");
          }
     }
     if(0)
     {
          // Montgomery multiplication: A * B (mod m) = A * r (mod m) x B, r = 2 ^ s > m
          LongInt2 &R = *m_R;
          LongInt2 b(m_BSize * 2 + 4);
          b.Mul(A, X);
          b %= P;
          LongInt2 x1(m_BSize);
          x1 = b;
          b = A;
          b <<= m_BSize * 8;
          b %= P;
          MonMul(b, X, b);
          if   (b == x1)
          {
               printf("Test2 - ok\n");
          }
     }
     */

    if  (P.GetRealSize() == 0)
    {
        throw "div by 0";
        return false;
    }

    if  (P.GetRealSize() == 1 && P[0] == 1)
    {
        Y.Zero();
        return true;
    }

    if  (X.GetRealSize() == 0)
    {
        Y.Zero();
        Y[0] = 1;
        return true;
    }

    if  (A.GetRealSize() == 0)
    {
        Y.Zero();
        return true;
    }

    LongInt2 &E = X;

    int i = E.GetRealSize();
    int lge = E.GetRealSizeBits();

    int opt_k = -1, opt_complexity = -1, opt_mulc = -1, opt_sqrc = -1;
    int k, t, akx;
    for (k = 1; k < 8; k++)
    {
        int b = lge - 1;
        int idx = b / 8;
        _dword x = E[idx];
        int bit = b & 7;
        int sqrc = 0, mulc = 0;
        while(b >= 0)
        {
            if  ((x & (1 << bit)))
            {
                while(bit + 1 < k && idx > 0)
                {
                    x = (x << 8) | E[--idx];
                    bit += 8;
                }
                int y;
                int kk;
                if  (bit + 1 >= k)
                {
                    y = x >> (bit + 1 - k);
                    kk = k;
                }
                else
                {
                    y = x;
                    kk = bit + 1;
                }
                if  ((bit -= kk) < 0 && idx > 0)
                {
                    x = (x << 8) | E[--idx];
                    bit += 8;
                }
                y &= ((1 << kk) - 1);

                t = m_TwoTab[y];
                akx = m_OddTab[y];

                if  (b != lge - 1)
                {
                    sqrc += kk - t;
                    mulc++;
                }
                sqrc += t;
                b -= kk;
            }
            else
            {
                sqrc++;
                b--;
                if  (--bit < 0 && idx > 0)
                {
                    x = (x << 8) | E[--idx];
                    bit += 8;
                }
            }
        }

        if  (k == 1)
        {
            mulc++;
        }
        else
        {
            mulc += 1 << (k - 1);
            sqrc++;
        }
        //int complexity = (sqrc + 2 * mulc);
        double cmplx = ((double)sqrc + 1.07781562 * mulc);
        int complexity = (int)cmplx;

        if  (k == 1)
        {
            opt_k = k;
            opt_complexity = complexity;
            opt_mulc = mulc;
            opt_sqrc = sqrc;
        }
        else
        {
            if  (complexity < opt_complexity)
            {
                opt_k = k;
                opt_complexity = complexity;
                opt_mulc = mulc;
                opt_sqrc = sqrc;
            }
        }
    }
    m_k = opt_k;
    m_complexity = opt_complexity;
    m_mulc = opt_mulc;
    m_sqrc = opt_sqrc;
    m_crc = opt_mulc + opt_sqrc + 1;
    m_rrc = 0;

    k = opt_k;


#define F(k) ((1 << (k - 1)) + (lge - 1 - k * (int)((lge - 1) / k)) + ((lge - 1) / k)*(k + (k + 1)*((1 << k) - 1))/(1 << k))
#define F2(k) ((1 << (k - 1)) + (lge - 1 - k * (int)((lge - 1) / k)) + ((lge - 1) / k)*(k + (k + 2*1)*((1 << k) - 1))/(1 << k))
    /*
     int k = 1;
     for  (i = 2; i <= 8; i++)
     {
          if   (F2(i) < F2(k))
          {
               k = i;
          }
     }
     g_kkkk = k;
     g_Fkkkk = F(k);
     */

    int pow2k = 1 << k;
    int k_mask = pow2k - 1;

    LongInt2 * ak[128];
    for (i = 0; i < 128; i++)
    {
        ak[i] = NULL;
    }

    //Y.Zero();
    //int logB_r = P.GetRealSize(); // P.GetSize()
    //LongInt2 &R = *m_R;
    /*
     R[logB_r] = 1;
     R %= P;
     if   (R != *m_R)
     {
          static int aa = 0;
          aa++;
     }
     */
    //int mprime = m_Back;

    LongInt2 &R2 = *m_R2;

    try
    {
        LongInt2 Buffer((m_BSize * 2) + 4);
        //Buffer.Mul(A, R);
        //Buffer %= P;
        ak[0] = TL_NEW LongInt2(m_BSize);
        /*
          // LongInt2::LongInt2() throw exception on memory allocation error
          if   (!ak[0])
          {
               throw "Alloc error";
          }
          */

        //*(ak[0]) = Buffer;
        MonMul(A, R2, *(ak[0]), Buffer);
        //          pr("ak[0] =", *(ak[0]));

        if  (k > 1)
        {
            //if   (!ak[2])
            LongInt2 a2(m_BSize);
            /*
               {
                    DWORD s = GetTickCount();
                    int i;
                    for  (i = 0; i < 30000; i++)
                    {
                         MonSqr(*(ak[0]), a2, Buffer);
                    }
                    s = GetTickCount() - s;

                    DWORD m = GetTickCount();
                    for  (i = 0; i < 30000; i++)
                    {
                         MonMul(a2, *(ak[0]), Buffer);
                         a2 = Buffer;
                    }
                    m = GetTickCount() - m;

                    printf("mul = %d, sqr = %d, mul/sqr = %lf\n", m, s, (double)m/(double)s);

                    FILE * f = fopen("m_s.txt", "a+b");
                    if   (f)
                    {
                         static int aa = 0;
                         aa++;
                         fprintf(f, "%d\t%lf\n", aa, (double)m/(double)s);
                         fclose(f);
                    }
               }
               */

            MonSqr(*(ak[0]), a2, Buffer);
            //sqrmon_l (a1, md_l, mprime, logB_r, ak[2]);

            //               pr("a2 =", a2);

            for (i = 1; i < (int)pow2k / 2; i++)
            {
                //if   (!ak[i])
                ak[i] = TL_NEW LongInt2(m_BSize);
                /*
                    if   (!ak[i])
                    {
                         throw "Alloc error";
                    }
                    */

                MonMul(a2, *(ak[i - 1]), *(ak[i]), Buffer);
                //*(ak[i]) = Buffer;
                /*
                    if   (0 && i <= 5)
                    {
                         printf("ak[%d] =", i);
                         pr("", *(ak[i]));
                    }
                    */
                //mulmon_l (ak[2], ak[i - 2], md_l, mprime, logB_r, ak[i]);
            }
        }

        LongInt2 Acc(m_BSize);

        int b = lge - 1;
        int idx = b / 8;
        _dword x = E[idx];
        int bit = b & 7;
        while(b >= 0)
        {
            if  ((x & (1 << bit)))
            {
                while(bit + 1 < k && idx > 0)
                {
                    x = (x << 8) | E[--idx];
                    bit += 8;
                }
                int y;
                int kk;
                if  (bit + 1 >= k)
                {
                    y = x >> (bit + 1 - k);
                    kk = k;
                }
                else
                {
                    y = x;
                    kk = bit + 1;
                    //pow2k = 1 << kk;
                }
                if  ((bit -= kk) < 0 && idx > 0)
                {
                    x = (x << 8) | E[--idx];
                    bit += 8;
                }
                y &= ((1 << kk) - 1);

                t = m_TwoTab[y];
                akx = m_OddTab[y];

                if  (b == lge - 1)
                {
                    Acc = *(ak[akx >> 1]);
                }
                else
                {
                    for (int s = kk - 1; s >= t; s--)
                    {
                        MonSqr(Acc, Acc, Buffer);
                    }

                    MonMul(Acc, *(ak[akx >> 1]), Acc, Buffer);
                    //Acc = Buffer;
                }
                for (; t > 0; t--)
                {
                    MonSqr(Acc, Acc, Buffer);
                }
                b -= kk;
            }
            else
            {
                MonSqr(Acc, Acc, Buffer);
                b--;
                if  (--bit < 0 && idx > 0)
                {
                    x = (x << 8) | E[--idx];
                    bit += 8;
                }
            }
        }
        Buffer = Acc; // need approximately 4 bytes more then Acc have (need m_BSize + 4)
        Reduce(Buffer);
        Y = Buffer;
        //mulmon_l (Acc, one_l, md_l, mprime, logB_r, p_l);
    }
    catch(...)
    {
        for (i = (int)pow2k / 2 - 1; i >= 0; i--)
        {
            delete ak[i];
        }
        throw;
        return false;
    }
    for (i = (int)pow2k / 2 - 1; i >= 0; i--)
    {
        delete ak[i];
    }

    return true;
}

//==============================================================================

//#endif
