
// CryptLib Project

/* CryptLib library for RusRoute firewall and other projects of
 * Andrey A. Moiseenko / IE Moiseenko A.A. (Russia)
 * e-mail: support@maasoftware.ru, maa2002@mail.ru
 * web: http://maasoftware.ru, http://maasoftware.com, http://maasoft.ru, http://maasoft.org
 * Author's full name: Andrey Alekseevitch Moiseenko
 * (russian name: Моисеенко Андрей Алексеевич)
 */

// CryptLib/longint2.cpp

/* Copyright (C) 2002-2024 Andrey A. Moiseenko (support@maasoftware.ru)
 * All rights reserved.
 *
 * This library contains the basic cryptography function,
 * prime numbers checks and generator, random number generator,
 * Mantgomery exponent, symmetric GOST and asymmetric RSA-like.
 * This file is large integer number ariphmetic implementation written
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


// Арифметика длинных целых беззнаковых чисел
// Автор: Моисеенко А.А.
// Version 1.5 // 28.05.2007
// Version 1.6 // Move constructor, operator =, fix operator <<= -x; // 20.05.2026
// Для всех платформ


#include "stdafx.h"
#include "temp.h"

#pragma warning(disable:4731)

#ifdef  _DEBUG
     #define DebugPrintf( string ) printf( "\n%s\n", string )
//; getch()
#else
     #define DebugPrintf( string ) // Nothing to do
#endif

#if defined(_DEBUG1) || !defined(_WIN32)
#define lGet(i) Get(i)
#define rGet(r, i) r.Get(i)
#define lSet(i, x) Set(i,x)
#define rSet(r, i, x) r.Set(i, x)
#else
#if !defined(_WIN64) && !defined(_____AMD64_____)
#ifdef _WIN32
#define USE_ASM
#endif
#endif
#define lGet(i) ((_dword)*(_word *)&m_Number[i])
#define rGet(r, i) ((_dword)*(_word *)&r.m_Number[i])
#define lSet(i, x) (*(_word *)&m_Number[i] = (_word)(x))
#define rSet(r, i, x) (*(_word *)&r.m_Number[i] = (_word)(x))
#endif

#define Throw(x) throw x

//---------------------------------------------------------------------------
LongInt2::StatCount LongInt2::sStatCount;
LongInt2::StatTime LongInt2::sStatTime;
//---------------------------------------------------------------------------
LongInt2::LongInt2(int Size)
{
    Init(Size);
}
//---------------------------------------------------------------------------
LongInt2::LongInt2(const LongInt2 & Copy_)
{
    Init(Copy_.GetSize());
    LoadFromMem(Copy_.m_Number, Copy_.GetSize());
}
//---------------------------------------------------------------------------
LongInt2::LongInt2(LongInt2&& Copy) noexcept
:   m_Number(nullptr),
    m_Size(0),
    m_Size2(0),
    m_TotalSize(0)
#ifdef CRYPTLIB_USE_ASM64
    , m_Size8(0)
#endif
{
    Swap(Copy);
}
//---------------------------------------------------------------------------
LongInt2 & LongInt2::operator = (const LongInt2 &That)
{
    LONG_INT2_INC_STAT(m_Copy);
    const int Size = That.GetRealSize();
    if  (Size > m_Size)
    {
        Throw("LongInt2 & LongInt2::operator = (const LongInt2 &Second)");
    }
    LoadFromMem(That.m_Number, Size);
    return *this;
}
//---------------------------------------------------------------------------
LongInt2 & LongInt2::operator = (LongInt2&& That) noexcept
{
    LONG_INT2_INC_STAT(m_Move);
    Swap(That);
    return *this;
}
//---------------------------------------------------------------------------
bool LongInt2::operator==(const LongInt2 &That) const noexcept
{
    LONG_INT2_INC_STAT(m_Cmp);
    const int Size1 = GetRealSize();
    const int Size2 = That.GetRealSize();
    if  (Size1 != Size2)
    {
        return false;
    }
    return !memcmp(m_Number, That.m_Number, Size1); // ConstMemcmp
}
//---------------------------------------------------------------------------
bool LongInt2::operator!=(const LongInt2 &That) const noexcept
{
    return !(*this == That);
}
//---------------------------------------------------------------------------
LongInt2::LongInt2(const void *Ptr, int Size)
{
    Init(Size);
    LoadFromMem(Ptr, Size);
}
//---------------------------------------------------------------------------
// Загрузка числа из памяти
void LongInt2::LoadFromMem(const void * Source, int Bytes) noexcept
{
#if 0
    if  (/*(_dword)Source >= 0x3a0000 - 256 && (_dword)Source < 0x3a0000 + 256 ||*/ Bytes == 0)
    {
        printf("LoadFromMem(%p, %d)\n", Source, Bytes);
        FILE * f = fopen("logs\\LongInt2.txt", "a+b");
        if  (f)
        {
            fprintf(f, "LoadFromMem(%p, %d)\n", Source, Bytes);
            fclose(f);
        }
    }
#endif
    const int Size = GetSize();

    if  (Bytes == -0x10000)
    {
        Bytes = Size;
    }
    if  (!Source)  // nullptr
    {
        Bytes = 0;
    }
    if  (Bytes > Size)
    {
        Bytes = Size; // or throw
    }
    memmove(m_Number, Source, Bytes);
    memset(m_Number + Bytes, 0, Size - Bytes + 2);
}
//---------------------------------------------------------------------------
void LongInt2::Copy(const LongInt2 & Source) noexcept
{
    LONG_INT2_INC_STAT(m_Copy);
    LoadFromMem(Source.m_Number, Source.GetSize());
}
//---------------------------------------------------------------------------
void LongInt2::Init(int Size)
{
    LONG_INT2_INC_STAT(m_Init);
    m_Number = nullptr;
    m_Size = Size;
    //if  (sizeof(_word) != 2) // check is in gCMaaToolLib_crt_Initializer()
    //{
    //    Throw("sizeof(_word) != 2");
    //}
#ifdef CRYPTLIB_USE_ASM64
    m_Size8 = (m_Size + sizeof(_qword) - 1) / sizeof(_qword);
    m_Size2 = m_Size8 * 4;
    m_TotalSize = (m_Size8 + 2 + 2) * sizeof(_qword);
    m_Number = TL_NEW unsigned char[2 * sizeof(_qword) + m_TotalSize];
    if  (m_Number)
    {
        memset(m_Number, 0, 2 * sizeof(_qword) + m_TotalSize);
        m_Number += 2 * sizeof(_qword);
    }
    else
    {
        Throw("new[] returns nullptr in void LongInt2::Init(int Size)");
    }
#else
    m_Size2 = (m_Size + sizeof(_word) - 1) / sizeof(_word);
    m_TotalSize = (m_Size2 + 2 + 2) * sizeof(_word);
    m_Number = TL_NEW unsigned char[2 * sizeof(_word) + m_TotalSize];
    if  (m_Number)
    {
        memset(m_Number, 0, 2 * sizeof(_word) + m_TotalSize);
        m_Number += 2 * sizeof(_word);
    }
    else
    {
        Throw("new[] returns nullptr in void LongInt2::Init(int Size)");
    }
#endif
}
//---------------------------------------------------------------------------
LongInt2 & LongInt2::operator += (const LongInt2 &Second)
{
    LONG_INT2_INC_STAT(m_Add);
#ifdef CRYPTLIB_USE_ASM64
    const int Size1 = m_Size8;
    int Size2 = Second.m_Size8;

    if  (Size2 > Size1)
    {
        Size2 = (Second.GetRealSize2() + 3) / 4;
    }
    if  (Size2 > Size1)
    {
        Throw("Size2 > Size1 in LongInt2 & LongInt2::operator += (const LongInt2 &Second)");
    }
    const _dword v = LongInt2_add(Size2, Size1 - Size2, m_Number, Second.m_Number);
#else
    int Size1 = sizeof(_word) * m_Size2;
    int Size2 = sizeof(_word) * Second.m_Size2;

    if  (Size2 > Size1)
    {
        Size2 = sizeof(_word) * Second.GetRealSize2(); // 26.02.2008: __ Second. __
    }
    if  (Size2 > Size1)
    {
        Throw("Size2 > Size1 in LongInt2 & LongInt2::operator += (const LongInt2 &Second)");
    }
    _dword v = 0;

#ifdef USE_ASM
    if  (Size2 > 0)
    {
        unsigned char * src = Second.m_Number;
        unsigned char * dst = m_Number;
        int SizeDw = (Size2 + 3) / 4;
        int SizeUpDw = (Size1 + 3) / 4 - SizeDw;
        __asm
        {
            mov esi, src
            mov edi, dst
            mov ecx, SizeDw
            or  ecx, ecx
            jz  AddExit1
            AddLoop1:
            mov eax, [esi]
            adc [edi], eax
            lea esi, [esi + 4]
            lea edi, [edi + 4]
            loop AddLoop1
            AddExit1:
            mov eax, ecx
            jnc AddExit3
            rcl al, 1
            mov ecx, SizeUpDw
            or  ecx, ecx
            jz  AddExit3
            rcr al, 1
            mov eax, 0
            AddLoop2:
            adc [edi], eax
            lea edi, [edi + 4]
            loop AddLoop2
            rcl al, 1
            AddExit3:
            mov v, eax
        }
    }
#else // USE_ASM
    int i;
    for (i = 0; i < Size2; i += sizeof(_word))
    {
        v += lGet(i) + rGet(Second,i);
        lSet(i, v);
        v >>= 16;
    }
    for (; i < Size1 && v; i += sizeof(_word))
    {
        v += lGet(i);
        lSet(i, v);
        v >>= 16;
    }
#endif // USE_ASM

#endif
    if  (v || lGet(m_Size) /*!= 0*/)
    {
        memset(m_Number + m_Size, 0, m_TotalSize - m_Size); // restoring
        Throw("Overflow in LongInt2 & LongInt2::operator += (const LongInt2 &Second)"); // overflow
    }

    return *this;
}
//---------------------------------------------------------------------------
LongInt2 & LongInt2::operator -= (const LongInt2 &Second)
{
    LONG_INT2_INC_STAT(m_Del);
#ifdef CRYPTLIB_USE_ASM64
    const int Size1 = m_Size8;
    int Size2 = Second.m_Size8;

    if  (Size2 > Size1)
    {
        Size2 = (Second.GetRealSize2() + 3) / 4;
    }
    if  (Size2 > Size1)
    {
        Throw("(Size2 > Size1) in LongInt2 & LongInt2::operator -= (const LongInt2 &Second)");
    }
    const _dword v = LongInt2_sub(Size2, Size1 - Size2, m_Number, Second.m_Number);
#else
    int Size1 = sizeof(_word) * m_Size2;
    int Size2 = sizeof(_word) * Second.m_Size2;

    if  (Size2 > Size1)
    {
        Size2 = sizeof(_word) * Second.GetRealSize2();
    }
    if  (Size2 > Size1)
    {
        Throw("(Size2 > Size1) in LongInt2 & LongInt2::operator -= (const LongInt2 &Second)");
    }
    int i;
    _sdword v = 0;
    for (i = 0; i < Size2; i += sizeof(_word))
    {
        v = (_sdword)lGet(i) - (_sdword)rGet(Second, i) + v;
        lSet(i, (_dword)v);
        v >>= 16;
    }
    for (; i < Size1 && v; i += sizeof(_word))
    {
        v = (_sdword)lGet(i) + v;
        lSet(i, v);
        v >>= 16;
    }
#endif
    if  (v)
    {
        Throw("Underflow in LongInt2 & LongInt2::operator -= (const LongInt2 &Second)"); // underflow
    }

    return *this;
}
//---------------------------------------------------------------------------
int LongInt2::Compare(const LongInt2 &That) const noexcept
{
    LONG_INT2_INC_STAT(m_Cmp);
    const int Size1 = sizeof(_word) * GetRealSize2();
    const int Size2 = sizeof(_word) * That.GetRealSize2();
    if  (Size1 != Size2)
    {
        return Size1 - Size2;
    }
    for (int i = Size1 - 2; i >= -1; i -= 2)
    {
        const _sdword x = (_sdword)lGet(i) - (_sdword)rGet(That,i);
        if  (x != 0)
        {
            /*
               if   (i == -1)
               {
                    static int aa = 0;
                    aa++;
               }
            */
            return x;
        }
    }
    return 0;
}
//---------------------------------------------------------------------------
LongInt2::~LongInt2()
{
#ifdef CRYPTLIB_USE_ASM64
    if  (m_Number)
    {
#if 0
        bool b[2] = { false, false };
        int i;
        for (i = m_Size; i < m_TotalSize; i++)
        {
            if  (m_Number[i] != 0)
            {
                b[1] = true;
            }
        }
        for (i = 1; i <= 4*2 * (int)sizeof(_word); i++)
        {
            if  (m_Number[-i] != 0)
            {
                b[0] = true;
            }
        }
        if  (b[0] || b[1])
        {
            printf("LongInt2::~LongInt2():%s%s\n", b[1] ? " overflow detected" : "", b[0] ? " underflow detected" : "");
            FILE* f = fopen("logs\\LongInt2.txt", "a+b");
            if  (f)
            {
                fprintf(f, "LongInt2::~LongInt2():%s%s\n", b[1] ? " overflow detected" : "", b[0] ? " underflow detected" : "");
                fclose(f);
            }
        }
#endif
        m_Number -= 2 * sizeof(_qword);
        memset(m_Number, 0, 2 * sizeof(_qword) + m_TotalSize);
    }
#else
    if  (m_Number)
    {
#if 0
        bool b[2] = {false, false};
        int i;
        for (i = m_Size; i < m_TotalSize; i++)
        {
            if  (m_Number[i] != 0)
            {
                b[1] = true;
            }
        }
        for (i = 1; i <= 2 * (int)sizeof(_word); i++)
        {
            if  (m_Number[-i] != 0)
            {
                b[0] = true;
            }
        }
        if  (b[0] || b[1])
        {
            printf("LongInt2::~LongInt2():%s%s\n", b[1] ? " overflow detected" : "", b[0] ? " underflow detected" : "");
            FILE * f = fopen("logs\\LongInt2.txt", "a+b");
            if  (f)
            {
                fprintf(f, "LongInt2::~LongInt2():%s%s\n", b[1] ? " overflow detected" : "", b[0] ? " underflow detected" : "");
                fclose(f);
            }
        }
#endif
        m_Number -= 2 * sizeof(_word);
        memset(m_Number, 0, 2 * sizeof(_word) + m_TotalSize);
    }
#endif
    delete [] m_Number;
}
//---------------------------------------------------------------------------
// Определение реальной длины числа (без учета старших нулей)
int LongInt2::GetRealSize() const noexcept
{
    unsigned char * p;

    for (p = m_Number + GetSize() - 1; p >= m_Number && !(*p); p--) ;

    return (int)(p - m_Number + 1);
}
//---------------------------------------------------------------------------
// Определение реальной длины числа (без учета старших нулей) в словах
int LongInt2::GetRealSize2() const noexcept
{
    return (GetRealSize() + sizeof(_word) - 1) / sizeof(_word);
}
//---------------------------------------------------------------------------
// Определение реальной длины числа (без учета старших нулей) в битах
int LongInt2::GetRealSizeBits() const noexcept
{
    const int i = GetRealSize();
    int r = 8 * i;
    if  (i > 0)
    {
        for (int j = 0x80; j >= 0; j >>= 1)
        {
            if  ((m_Number[i - 1] & j))
            {
                break;
            }
            r--;
        }
    }
    return r;
}
//---------------------------------------------------------------------------
LongInt2 & LongInt2::CalcRest(const LongInt2 & Dividend, const LongInt2 & Divider)
{
    LONG_INT2_INC_STAT(m_Rest);
    const int  DividendSize = Dividend.GetSize();
    const int DividerSize =  Divider.GetSize();

    //   определение реальной длины делителя (без учета старших нулей)
    const int  RealDividerSize = Divider.GetRealSize();

    if  (!RealDividerSize)
    {
        DebugPrintf("LongInt2::CalcRest() - Divider==0");
        Throw("LongInt2::CalcRest() - Divider==0");
    }
    if  (GetSize() < RealDividerSize)
    {
        DebugPrintf("LongInt2::CalcRest() - ThisSize < RealDividerSize");
        Throw("LongInt2::CalcRest() - ThisSize < RealDividerSize");
    }

    // создание рабочего буфера
    LongInt2 Rest(Dividend);

    if  (DividendSize >= RealDividerSize)
    {
        for (int i = Rest.GetRealSize(); i >= RealDividerSize; i--)
        {
            const _dword x = rGet(Rest,i - 2) + (Rest.m_Number[i] << 16);
            const _dword y = rGet(Divider, RealDividerSize - 2);
            const _dword z = x / y;
            _sdword v = 0;
            for (int j = 0; j < RealDividerSize + 1; j += 2)
            {
                const _dword m = rGet(Divider, j) * z;
                v = (_sdword)rGet(Rest, i - RealDividerSize + j) - (_sdword)m + v;
                rSet(Rest, i - RealDividerSize + j, (_dword)v);
                v >>= 16;
            }
            if  (v < 0)
            {
                v = 0;
                for (int j = 0; j < RealDividerSize + 1; j += 2)
                {
                    const _dword m = rGet(Divider, j)/* * z*/;
                    v = (_sdword)rGet(Rest, i - RealDividerSize + j) + (_sdword)m + v;
                    rSet(Rest, i - RealDividerSize + j, (_dword)v);
                    v >>= 16;
                }
            }
        }
    }
    LoadFromMem(Rest.m_Number, RealDividerSize);
    return *this;
}
//---------------------------------------------------------------------------
LongInt2 & LongInt2::CalcRestEx(const LongInt2 & Dividend, const LongInt2 & Divider, LongInt2 * const* pMulTable)
{
    LONG_INT2_INC_STAT(m_RestEx);
    const int  DividendSize = Dividend.GetSize();
    const int DividerSize =  Divider.GetSize();

    //   определение реальной длины делителя (без учета старших нулей)
    int  RealDividerSize = Divider.GetRealSize();

    if  (!RealDividerSize)
    {
        DebugPrintf("LongInt2::CalcRestEx() - Divider==0");
        Throw("LongInt2::CalcRestEx() - Divider==0");
    }
    if  (GetSize() < RealDividerSize)
    {
        DebugPrintf("LongInt2::CalcRestEx() - ThisSize < RealDividerSize");
        Throw("LongInt2::CalcRestEx() - ThisSize < RealDividerSize");
    }

    // создание рабочего буфера
    LongInt2 Rest(Dividend);

    if  (DividendSize >= RealDividerSize)
    {
        for (int i = Rest.GetRealSize(); i >= RealDividerSize; i--)
        {
            _dword x = rGet(Rest, i - 2) + (Rest.m_Number[i] << 16);
            _dword y = rGet(Divider, RealDividerSize - 2);
            _dword z = x / y;
            const _dword z0 = z;
            _sdword v = 0;
            if  (z > 0)
            {
                if  (z > 255)
                {
                    z = 255;
                }
                const LongInt2 * zz = pMulTable[z - 1];
                for (int j = 0; j < RealDividerSize + 2; j += 2)
                {
                    _dword m = rGet((*zz), j);
                    v = (_sdword)rGet(Rest, i - RealDividerSize + j) - (_sdword)m + v;
                    rSet(Rest, i - RealDividerSize + j, (_dword)v);
                    v >>= 16;
                }
                if  (v < 0)
                {
                    v = 0;
                    for (int j = 0; j < RealDividerSize + 2; j += 2)
                    {
                        const _dword m = rGet(Divider, j);
                        v = (_sdword)rGet(Rest, i - RealDividerSize + j) + (_sdword)m + v;
                        rSet(Rest, i - RealDividerSize + j, (_dword)v);
                        v >>= 16;
                    }
                }
                if  (z0 > 255)
                {
                    i++;
                }
            }
        }
    }
    LoadFromMem(Rest.m_Number, RealDividerSize);
    return *this;
}
//---------------------------------------------------------------------------
#if 1
LongInt2 & LongInt2::Mul(const LongInt2 & Mul1, const LongInt2 & Mul2)
{
    LONG_INT2_INC_STAT(m_Mul);
    const int Mul1Size = Mul1.GetRealSize();
    const int Mul2Size = Mul2.GetRealSize();

    if  ( Mul1Size == 0 || Mul2Size == 0 )
    {
        Zero();
        return *this;
    }
#ifdef CRYPTLIB_USE_ASM64

    const _sdword Mul1SizeQw = (Mul1Size + 7) / 8;
    const _sdword Mul2SizeQw = (Mul2Size + 7) / 8; // modified in asm
    if  (m_TotalSize < 8 * (Mul1SizeQw + Mul2SizeQw + 1) || this == &Mul1 || this == &Mul2)
    {
        // создание рабочего буфера
        LongInt2 Product(8 * (Mul1SizeQw + Mul2SizeQw + 1));
        Product.Mul(Mul1, Mul2);
        const int r = Product.GetRealSize();
        if  (GetSize() < r)
        {
            Throw("Not enough size for multiplication result size");
        }
        LoadFromMem(Product.m_Number, r);
    }
    else
    {
        Zero();

        LongInt2_mul(Mul1SizeQw, Mul2SizeQw, m_Number, Mul1.m_Number, Mul2.m_Number);

        if  (lGet(m_Size) != 0)
        {
            memset(m_Number + m_Size, 0, m_TotalSize - m_Size); // restoring
            Throw("Multiplication overflow of result size");
        }
    }


#else
#ifdef USE_ASM

    //#pragma warning(disable:4731)

    _sdword Mul1SizeDw = (Mul1Size + 3) / 4;
    _sdword Mul2SizeDw = (Mul2Size + 3) / 4; // modified in asm
    if  (m_TotalSize < 4 * (Mul1SizeDw + Mul2SizeDw + 1) || this == &Mul1 || this == &Mul2)
    {
        // создание рабочего буфера
        LongInt2 Product(4 * (Mul1SizeDw + Mul2SizeDw + 1));
        Product.Mul(Mul1, Mul2);
        int r = Product.GetRealSize();
        if  (GetSize() < r)
        {
            Throw("Not enough size for multiplication result size");
        }
        LoadFromMem(Product.m_Number, r);
    }
    else
    {
        Zero();

        if  (&Mul1 != &Mul2)
        {
            unsigned char * m1 = Mul1.m_Number;
            unsigned char * m2 = Mul2.m_Number;
            unsigned char * dst = m_Number;


            // v.2.
            __asm
            {
                mov edi, dst
                mov esi, m2
                mov eax, Mul1SizeDw
                push eax
                mov ebx, m1
                push ebx
                mov ecx, Mul2SizeDw
                MulLoop0:
                pop eax
                pop edx
                push edx
                push eax
                push ecx
                push edi
                mov ebx, [esi]
                add esi, 4
                push esi
                mov esi, eax
                mov ecx, edx
                xor edx, edx
                MulLoop1:
                push ecx
                mov ecx, edx
                mov eax, ebx
                mul dword ptr [esi]
                add eax, ecx
                adc edx, 0
                add [edi], eax
                adc edx, 0
                add esi, 4
                add edi, 4
                pop ecx
                loop MulLoop1

                mov [edi], edx
                pop esi
                pop edi
                lea edi, [edi + 4]
                pop ecx
                loop MulLoop0
                //dec Mul2SizeDw
                //jnz MulLoop0
                pop ebx
                pop eax
            }

            /*
               // v.1.
               __asm
               {
                    mov edi, dst
                    mov esi, m2
MulLoop0:
                    push edi
                    //mov ecx, Mul2SizeDw
                    mov ebx, [esi]
                    lea esi, [esi + 4]
                    push esi
                    mov esi, m1
                    mov ecx, Mul1SizeDw
                    push ebp
                    mov ebp, 0
MulLoop1:
                    mov eax, [esi]
                    //lea esi, [esi + 4]
                    add esi, 4
                    mul ebx
                    add eax, ebp
                    adc edx, 0
                    add [edi], eax
                    adc edx, 0
                    //lea edi, [edi + 4]
                    add edi, 4
                    mov ebp, edx
                    loop MulLoop1

                    mov [edi], edx
                    pop ebp
                    pop esi
                    pop edi
                    //lea edi, [edi + 4]
                    add edi, 4
                    dec Mul2SizeDw
                    jnz MulLoop0
               }
*/
        }
        else
        {
            //LongInt2 Product2(4 + (Mul1Size + Mul2Size)), A2(Mul1);
            //Product2.Mul(Mul1, A2);

            // Sqr

            unsigned char * src = Mul1.m_Number;
            unsigned char * dst = m_Number;

            __asm
            {
                mov edi, dst
                mov esi, src
                mov ecx, Mul1SizeDw
                dec ecx
                jnz SqrLoop0
                mov eax, [esi]
                mul eax
                mov [edi], eax
                mov [edi + 4], edx
                jmp SqrExit
                SqrLoop0:
                push ecx
                mov ebx, [esi]
                lea esi, [esi + 4]
                lea edi, [edi + 4]
                push edi
                push esi
                push ebp
                mov ebp, 0

                SqrLoop1:
                mov eax, [esi]
                lea esi, [esi + 4]
                mul ebx
                add eax, ebp
                adc edx, 0
                add [edi], eax
                adc edx, 0
                lea edi, [edi + 4]
                mov ebp, edx
                loop SqrLoop1

                mov [edi], edx
                pop ebp
                pop esi
                pop edi
                pop ecx
                lea edi, [edi + 4]
                loop SqrLoop0

                mov edi, dst
                mov ecx, Mul1SizeDw
                clc
                SqrLoop2:
                rcl dword ptr [edi],1
                rcl dword ptr [edi + 4],1
                lea edi, [edi + 8]
                loop SqrLoop2

                mov esi, src
                mov edi, dst
                mov ecx, Mul1SizeDw
                xor ebx, ebx
                SqrLoop3:
                mov eax, [esi]
                mul eax
                lea esi, [esi + 4]
                add eax, ebx
                adc edx, 0
                add [edi], eax
                adc [edi + 4], edx
                lea edi, [edi + 8]
                mov ebx, 0
                rcl ebx, 1
                loop SqrLoop3
                //cmp ebx, 0
                //jz SqrExit
                //add [edi], ebx
                SqrExit:
            }
            //if   (*this != Product2)
            //{
            //     MessageBox(nullptr, "Product != Product2", "", MB_OK);
            //}
        }
        if  (lGet(m_Size) != 0)
        {
            memset(m_Number + m_Size, 0, m_TotalSize - m_Size); // restoring
            Throw("Multiplication overflow of result size");
        }
    }
#else // USE_ASM

    _sdword Mul1SizeDw = (Mul1Size + 3) / 4;
    _sdword Mul2SizeDw = (Mul2Size + 3) / 4;
    if  (m_TotalSize < 4 * (Mul1SizeDw + Mul2SizeDw + 1) || this == &Mul1 || this == &Mul2)
    {
        // создание рабочего буфера
        LongInt2 Product(4 * (Mul1SizeDw + Mul2SizeDw + 1));
        Product.Mul(Mul1, Mul2);
        int r = Product.GetRealSize();
        if  (GetSize() < r)
        {
            Throw("Not enough size for multiplication result size");
        }
        LoadFromMem(Product.m_Number, r);
    }
    else
    {
        Zero();

        LongInt2& Product = *this;// (4 + (Mul1Size + Mul2Size));

        if  (&Mul1 != &Mul2)
        {
            for (int i = 0; i < Mul2Size + 1; i += 2)
            {
                _dword m = rGet(Mul2, i);
                _dword v = 0;
                int j;
                for (j = 0; j < Mul1Size; j += 2)
                {
                    v += rGet(Mul1, j) * m + rGet(Product, i + j);
                    rSet(Product, i + j, v);
                    v >>= 16;
                }
                if  (rGet(Product, i + j) != 0)
                {
                    DebugPrintf("Product.Get(i + j) != 0");
                }
                //v += Product.Get(i + j);
                rSet(Product, i + j, v);
            }
        }
        else
        {
            // Sqr
            int i, j;
            _dword v;
            for (i = 0; i < Mul1Size - 2; i += 2)
            {
                v = 0;
                _dword mi = rGet(Mul1, i);
                for (j = i + 2; j < Mul1Size; j += 2)
                {
                    v += mi * rGet(Mul1, j) + rGet(Product, i + j);
                    rSet(Product, i + j, v);
                    v >>= 16;
                }
                rSet(Product, i + j, v);
            }
            Product <<= 1;

            v = 0;
            for (i = 0; i < Mul1Size; i += 2)
            {
                v += rGet(Mul1, i) * rGet(Mul1, i) + rGet(Product, 2 * i);
                rSet(Product, 2 * i, v);
                v = (v >> 16) + rGet(Product, 2 * i + 2);
                rSet(Product, 2 * i + 2, v);
                v >>= 16;
            }
            /*
            if   (v)
            {
                 rSet(Product, 2 * i, v + rGet(Product, 2 * i));
            }
            */
        }
    }
    /*
     int r = Product.GetRealSize();
     if   (GetSize() < r)
     {
          Throw("Not enough size for multiplication result size");
     }
     LoadFromMem(Product.m_Number, r);
     */
#endif
#endif
    return *this;
}
#endif // 1
//---------------------------------------------------------------------------
LongInt2 & LongInt2::Divide(const LongInt2 &Dividend, const LongInt2 &Divider, LongInt2 *OutRest)
{
    LONG_INT2_INC_STAT(m_Div);
    const int DividendSize = Dividend.GetSize();
    const int DividerSize =  Divider.GetSize();

    //   определение реальной длины делителя (без учета старших нулей)
    const int  RealDividerSize = Divider.GetRealSize();

    if  (!RealDividerSize)
    {
        DebugPrintf("LongInt2::Divide() - Divider==0");
        Throw("LongInt2::Divide() - Divider==0");
    }
    if  (GetSize() < RealDividerSize)
    {
        DebugPrintf("LongInt2::Divide() - ThisSize < RealDividerSize");
        Throw("LongInt2::Divide() - ThisSize < RealDividerSize");
    }

    // создание рабочего буфера
    LongInt2 Rest(Dividend);
    LongInt2 Result(Dividend.GetSize());

    if  (DividendSize >= RealDividerSize)
    {
        for (int i = Rest.GetRealSize(); i >= RealDividerSize; i--)
        {
            const _dword x = rGet(Rest, i - 2) + (Rest.m_Number[i] << 16);
            const _dword y = rGet(Divider, RealDividerSize - 2);
            _dword z = x / y;
            _sdword v = 0;
            int j;
            for (j = 0; j < RealDividerSize + 1; j += 2)
            {
                const _dword m = rGet(Divider, j) * z;
                v = (_sdword)rGet(Rest, i - RealDividerSize + j) - (_sdword)m + v;
                rSet(Rest, i - RealDividerSize + j, (_dword)v);
                v >>= 16;
            }
            if  (v < 0)
            {
                z--;
                v = 0;
                for (int j = 0; j < RealDividerSize + 1; j += 2)
                {
                    const _dword m = rGet(Divider, j)/* * z*/;
                    v = (_sdword)rGet(Rest, i - RealDividerSize + j) + (_sdword)m + v;
                    rSet(Rest, i - RealDividerSize + j, (_dword)v);
                    v >>= 16;
                }
            }
            for (j = i - RealDividerSize; z > 0; j += 2)
            {
                z += rGet(Result, j);
                rSet(Result, j, z);
                z >>= 16;
            }
        }
    }
    if  (OutRest)
    {
        OutRest->Copy(Rest);
    }
    LoadFromMem(Result(), Result.GetRealSize());
    return *this;
}
//---------------------------------------------------------------------------
int LongInt2::CalcBack(const LongInt2 &Number, const LongInt2 &Module)
{
    LONG_INT2_INC_STAT(m_Back);
    //try
    //{
    int  VarSize = Module.GetSize();
    LongInt2  s0(Module),
    s1(VarSize),
    s2(VarSize),
    a0(VarSize),
    a1(VarSize),
    a2(VarSize),
    r1(VarSize);

    if  (Module.GetRealSize() < Number.GetRealSize())
    {
        DebugPrintf( "LongInt2::CalcBack() Invalid input data" );
        return 1;
    }

    //  s0=q; s1=n;
    s1.Copy(Number);

    // a0=0; a1=1;
    a1[ 0 ] = 1;
    int i = 0, flag = 0;

    while(VarSize)
    {
        i++;
        flag ^= 1; // flag=1 ==> 'a2<0'  flag=0 ==> 'a2>0'
        //  r1=s0/s1; s2=s0%s1;
        r1.Divide(s0, s1, &s2);

#if 0
        {
            // Test for function Divide()
            LongInt2 x(2 * VarSize);
            x.Mul(s1, r1);
            x += s2;
            if  (x == s0)
            {
                printf("Ok\n");
            }
            else
            {
                printf("Fail 1\n");
            }
            x %= s1;
            if  (x == s2)
            {
                printf("Ok\n");
            }
            else
            {
                printf("Fail 2\n");
            }
        }
#endif
        // a2=a0+r1*a1; // for signed values: a2=(a0-r1*a1);
        a2.Mul(a1, r1);
        a2 += a0;

        VarSize = s2.GetRealSize();
        if  (VarSize == 1 && s2[0] == 1)
        {
            if  (flag)
            {
                // a2 = q-a2;
                Copy(Module);
                *this -= a2;
            }
            else
            {
                Copy(a2);
            }
            // Normal exit from while
            break;
        }
        else if (!VarSize)
        {
            DebugPrintf("LongInt2::CalcBack() - Error: Числа N и Q не взаимно простые");
            return 2;
        }
        // s0=s1; s1=s2; a0=a1; a1=a2;
        s0.Copy(s1); s1.Copy(s2); a0.Copy(a1); a1.Copy(a2);
    }
    //}
    //catch(const char * msg)
    //{
    //     MessageBox(nullptr, msg, "cb", MB_OK);
    //}
    return 0;
}
//---------------------------------------------------------------------------
LongInt2 & LongInt2::operator >>= (int x)
{
    if  (x < 0)
    {
        return (*this <<= -x);
    }
    if (x >= 8)
    {
        if (x >= GetSize() * 8)
        {
            Zero();
            x = 0;
        }
        else
        {
            LoadFromMem(m_Number + x / 8, GetSize() - x / 8);
            x &= 7;
        }
    }
    if (x > 0)
    {
        _dword a1 = 0;
        for (int i = (GetSize() - 1) & ~1; i >= 0; i -= 2)
        {
            _dword a2 = a1;
            a1 = lGet(i);
            lSet(i, (a1 >> x) | (a2 << (16 - x)));
        }
    }
    return *this;
}
LongInt2 & LongInt2::operator <<= (int x)
{
    if  (x < 0)
    {
        return (*this >>= -x);
    }
    const int Size = GetSize();
    if (x >= 8)
    {
        for (int i = Size - x / 8 >= 0 ? Size - x / 8 : 0; i < Size; i += 2)
        {
            if (lGet(i) != 0)
            {
                Throw("Overflow (1) in LongInt2::operator <<= (int x)");
            }
        }
        if (x >= GetSize() * 8)
        {
            Zero();
            x = 0;
        }
        else
        {
            memmove(m_Number + x / 8, m_Number, GetSize() - x / 8);
            memset(m_Number, 0, x / 8);
            //x &= 7;
        }
    }
    const int y = x & 7;
    if (y > 0)
    {
        _dword a1 = 0;
        for (int i = x / 8; i < Size; i += 2)
        {
            _dword a2 = a1;
            a1 = lGet(i);
            lSet(i, (a1 << y) | (a2 >> (16 - y)));
        }
    }
    return *this;
}
//---------------------------------------------------------------------------

int Import(LongInt2 &p, const char * ptr) noexcept
{
    const int len = (int)strlen(ptr);
    if  (len > p.GetSize() * 2 || (len & 1))
    {
        return -1;
    }
    int i;
    for (i = 0; i < len; i++)
    {
        if  (CharToHex(ptr[i]) < 0)
        {
            return -1;
        }
    }
    p.Zero();
    unsigned char * p2 = p();
    for (i = 0; i < len; i += 2)
    {
        p2[i / 2] = (CharToHex(ptr[len - i - 2]) << 4) | CharToHex(ptr[len - i - 1]);
    }
    return len / 2;
}
//---------------------------------------------------------------------------
CMaaString Import(CMaaString Text)
{
    CMaaString Ret;
    LongInt2 p((int)strlen(Text) / 2);
    const int x = Import(p, Text);
    if  (x >= 0)
    {
        Ret = CMaaString(p(), x);
    }
    return Ret;
}
//---------------------------------------------------------------------------

DEF_ALLOCATOR(LongInt2)

#if 0
// test
//#include "keys.h"

extern int N;
extern char n[128];
extern char d[128];
extern char e[128];

int test_exp()
{
    CMaaTime tx = GetHRTime();
    tx.StartWatch();
    while(tx.GetTime(1000000) < 4000000);
    try
    {
        //CMaaFile f("c:\\rusroute\\reg.bin", CMaaFile::eR);
        CMaaFile f("reg.bin", CMaaFile::eR);
        CMaaString BinFileData = f.Read(64 * 1024);
        f.Close();

        int N = ::N;
        int R = N & ~1;
        LongInt2 n(N);
        LongInt2 e(N);//, d(N);

        n.LoadFromMem(::n, ::N);
        //d.LoadFromMem(::d, ::N);
        e.LoadFromMem(::e, ::N);


        CMaaTime tx = GetHRTime();
        tx.StartWatch();
        const int C = 100;
        for (int iii = 0; iii < C; iii++)
        {
            LongInt2 Dec;
            time_t t;
            int y = RSADecrypt(n, e, BinFileData, BinFileData.Length(), Dec, &t);
            if  (y < 0)
            {
                printf("RSADecrypt() returns error %d\n", y);
                throw y;
            }
        }
        _qword t = tx.GetTime(1000000);
        __utf8_printf("N=%d, C=%d, t=%,D\n", N, C, t);
        //CMaaString s1 = LongInt2::sStatCount.Sprintf(), s2 = LongInt2::sStatTime.Sprintf();
        //__utf8_printf("%S\n%S\n", &s1, &s2);
        /*
N=128, C=100, t=9,581,253
m_Exp=0, m_Mul=831600, m_Div=0, m_Add=106114600, m_Del=189700, m_Init=53002, m_Rest=100, m_RestEx=0, m_Copy=859400, m_Cmp=832300, m_Back=0
m_Exp=0, m_Mul=16,046,204, m_Div=0, m_Add=60,327,084, m_Del=105,946, m_Init=41,525, m_Rest=7,229, m_RestEx=0, m_Copy=587,102, m_Cmp=725,898, m_Back=0

N=128, C=100, t=6,184,186
m_Exp=0, m_Mul=831600, m_Div=0, m_Add=106114600, m_Del=189700, m_Init=53002, m_Rest=100, m_RestEx=0, m_Copy=859400, m_Cmp=832300, m_Back=0
m_Exp=0, m_Mul=4,081,754, m_Div=0, m_Add=38,574,942, m_Del=75,252, m_Init=54,631, m_Rest=6,919, m_RestEx=0, m_Copy=590,218, m_Cmp=664,006, m_Back=0
*/
    }
    catch(...)
    {
        printf("catch(...)\n");
    }
    return 0;
}

#endif
