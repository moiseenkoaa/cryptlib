
// CryptLib Project

/* CryptLib library for RusRoute firewall and other projects of
 * Andrey A. Moiseenko / IE Moiseenko A.A. (Russia)
 * e-mail: support@maasoftware.ru, maa2002@mail.ru
 * web: http://maasoftware.ru, http://maasoftware.com, http://maasoft.ru, http://maasoft.org
 * Author's full name: Andrey Alekseevitch Moiseenko
 * (russian name: Моисеенко Андрей Алексеевич)
 */

// CryptLib/longint2.h

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

#ifndef __MAA_LongInt2_H
#define __MAA_LongInt2_H

#include <stdio.h>
#include <string.h>
#ifdef _DEBUG
     #include <conio.h>
#endif

#ifdef _WIN64
#define CRYPTLIB_USE_ASM64 // 26.11.2021: 128 bytes RSADecrypt: 7046316/3822831=1.843 times faster
extern "C"
{
    _dword LongInt2_add_win(_qword sz8, _qword up8, void* dst, const void* src) noexcept;
    _dword LongInt2_sub_win(_qword sz8, _qword up8, void* dst, const void* src) noexcept;
    void LongInt2_mul_win(_qword Mul1SizeQw, _qword Mul2SizeQw, void* Product, const void* Mul1, const void* Mul2) noexcept;
    _dword ConstMemcmp_win(const void* p1, const void* p2, _uqword len) noexcept;
#define LongInt2_add LongInt2_add_win
#define LongInt2_sub LongInt2_sub_win
#define LongInt2_mul LongInt2_mul_win
#define ConstMemcmp ConstMemcmp_win
}
#endif
#ifdef __linux__
#ifdef __x86_64__
#define CRYPTLIB_USE_ASM64 // 27.11.2021: 128 bytes RSADecrypt: 23943097/5898764=4.059 times faster
extern "C"
{
    _dword LongInt2_add_unix(_qword sz8, _qword up8, void* dst, const void* src) noexcept;
    _dword LongInt2_sub_unix(_qword sz8, _qword up8, void* dst, const void* src) noexcept;
    void LongInt2_mul_unix(_qword Mul1SizeQw, _qword Mul2SizeQw, void* Product, const void* Mul1, const void* Mul2) noexcept;
    _dword ConstMemcmp_unix(const void* p1, const void* p2, _uqword len) noexcept;
#define LongInt2_add LongInt2_add_unix
#define LongInt2_sub LongInt2_sub_unix
#define LongInt2_mul LongInt2_mul_unix
#define ConstMemcmp ConstMemcmp_unix
}
#endif
#endif

#ifdef CRYPTLIB_USE_ASM64
#define LONGINT_MUL_SPACE 8
#else
#define LONGINT_MUL_SPACE 4
#endif

// Арифметика длинных целых беззнаковых чисел
// Автор: Моисеенко А.А.
// Version 1.5 // 28.05.2007
// Version 1.6 // Move constructor, operator =, fix operator <<= -x; // 20.05.2026
// Для всех платформ

//---------------------------------------------------------------------------
//#define MemZero( BuffPtr, Bytes ) memset( BuffPtr, 0, Bytes )
//#define MemCopy( Destination, Source, Bytes ) memcpy( Destination, Source, Bytes )
//---------------------------------------------------------------------------
class CMyProf
{
    _qword &m_x;
#ifdef _WIN32
    LARGE_INTEGER m_t0;
#endif
#ifdef __unix__
    timeval m_t0;
#endif
public:
    CMyProf(_qword &x) noexcept
    :   m_x(x)
    {
#ifdef _WIN32
        QueryPerformanceCounter(&m_t0);
#endif
#ifdef __unix__
        gettimeofday(&m_t0, nullptr);
#endif
    }
    ~CMyProf()
    {
#ifdef _WIN32
        LARGE_INTEGER m_t1;
        QueryPerformanceCounter(&m_t1);
        m_x += (__int64)(m_t1.QuadPart - m_t0.QuadPart);
#endif
#ifdef __unix__
        timeval m_t1;
        gettimeofday(&m_t1, nullptr);
        m_x += (_qword)((m_t1.tv_sec - m_t0.tv_sec) * 1000000 + (m_t1.tv_usec - m_t0.tv_usec));
#endif
    }

};
class CMyExponent3;
class CMyExponent4;
class CMyExponent5;
class LongInt2
{
    friend class CMyExponent3;
    friend class CMyExponent4;
    friend class CMyExponent5;

    unsigned char *m_Number; // Число

    int m_Size;
    int m_Size2;  // Размер в 2-х байтовых словах
    int m_TotalSize;
#ifdef CRYPTLIB_USE_ASM64
    int m_Size8;  // Размер в 8-х байтовых словах
#endif

public:

    struct StatCount
    {
        int m_Exp, m_Mul, m_Div, m_Add, m_Del, m_Init, m_Rest, m_RestEx, m_Copy, m_Cmp, m_Back, m_Move;

        StatCount() noexcept
        {
            Reset();
        }

        void Reset() noexcept
        {
            memset(this, 0, sizeof(*this));
        }

        CMaaString Sprintf() noexcept
        {
            return CMaaString::sFormat("m_Exp=%d, m_Mul=%d, m_Div=%d, m_Add=%d, m_Del=%d, m_Init=%d, m_Rest=%d, m_RestEx=%d, m_Copy=%d, m_Cmp=%d, m_Back=%d, m_Move=%d",
                m_Exp, m_Mul, m_Div, m_Add, m_Del, m_Init, m_Rest, m_RestEx, m_Copy, m_Cmp, m_Back, m_Move);
        }
    };
    struct StatTime
    {
        _qword m_Exp, m_Mul, m_Div, m_Add, m_Del, m_Init, m_Rest, m_RestEx, m_Copy, m_Cmp, m_Back, m_Move;

        StatTime() noexcept
        {
            Reset();
        }

        void Reset() noexcept
        {
            memset(this, 0, sizeof(*this));
        }

        CMaaString Sprintf() noexcept
        {
            return CMaaString::sFormat("m_Exp=%,D, m_Mul=%,D, m_Div=%,D, m_Add=%,D, m_Del=%,D, m_Init=%,D, m_Rest=%,D, m_RestEx=%,D, m_Copy=%,D, m_Cmp=%,D, m_Back=%,D, m_Move=%,D",
                m_Exp, m_Mul, m_Div, m_Add, m_Del, m_Init, m_Rest, m_RestEx, m_Copy, m_Cmp, m_Back, m_Move);
        }
    };

    static StatCount sStatCount;
    static StatTime sStatTime;

//#define LONG_INT2_INC_STAT(x) ++LongInt2::sStatCount.x; CMyProf ______MyProf(LongInt2::sStatTime.x)
#define LONG_INT2_INC_STAT(x)

    void Swap(LongInt2 &That) noexcept
    {
        CMaaSwap(m_Number, That.m_Number);
        CMaaSwap(m_Size, That.m_Size);
        CMaaSwap(m_Size2, That.m_Size2);
        CMaaSwap(m_TotalSize, That.m_TotalSize);
#ifdef CRYPTLIB_USE_ASM64
        CMaaSwap(m_Size8, That.m_Size8);
#endif
    }

    // Во всех конструкторах размеры в байтах
    // Нехватка памяти приводит к throw

    // Инициализация нулями
    explicit LongInt2(int Size = 32);

    // Инициализация из указателя памяти
    LongInt2(const void *Ptr, int Size);

    // Инициализация другим длинным числом
    LongInt2(const LongInt2& Copy);
    LongInt2(LongInt2&& Copy) noexcept;

    ~LongInt2();

    bool operator==(const LongInt2 &That) const noexcept;
    bool operator!=(const LongInt2 &That) const noexcept;
    bool operator==(_dword x) const
    {
        LongInt2 tmp(sizeof(_dword));
        tmp = x;
        return *this == tmp;
    }
    bool operator!=(_dword x) const
    {
        LongInt2 tmp(sizeof(_dword));
        tmp = x;
        return *this != tmp;
    }


    LongInt2 & operator = (const LongInt2& That);
    LongInt2 & operator = (LongInt2&& That) noexcept;
    LongInt2 & operator = (_dword x)
    {
        const unsigned char xx[4] = {(unsigned char)x, (unsigned char)(x >> 8), (unsigned char)(x >> 16), (unsigned char)(x >> 24)};
        LongInt2 X(xx, 4);
        return (*this = X);
    }

    _dword Get(int i) const noexcept
    {
#ifdef _DEBUG111
        if  (i >= m_TotalSize - 1 || i < -1)
        {
            printf("Error in LongInt2::Get(%d)\n", i);
            static int aa = 0;
            aa++;
            return 0;
        }
#endif
#ifdef _WIN32
        return (_dword)*(_word *)&m_Number[i];
#else
        return (_dword)m_Number[i] + (((_dword)m_Number[i + 1]) << 8);
#endif
    }

    void Set(int i, _dword x) noexcept
    {
#ifdef _DEBUG111
        if  (i >= m_TotalSize - 1 || i < -1)
        {
            printf("Error in LongInt2::Set(%d, %u)\n", i, x);
            static int aa = 0;
            aa++;
            return;
        }
#endif
#ifdef _WIN32
        *(_word *)&m_Number[i] = (_word)x;
#else
        m_Number[i] = (unsigned char)x;
        m_Number[i + 1] = (unsigned char)((x) >> 8);
#endif
    }

    LongInt2 & operator += (const LongInt2 &Second);
    LongInt2 & operator -= (const LongInt2 &Second);
    LongInt2 & operator %= (const LongInt2 &Second)
    {
        CalcRest(*this, Second);
        return *this;
    }
    LongInt2 & operator >>= (int x);
    LongInt2 & operator <<= (int x);

    unsigned char * operator () () noexcept
    {
        return m_Number;
    }

    int Compare(const LongInt2 &That) const noexcept;

    bool operator < (const LongInt2 &That) const noexcept
    {
        return Compare(That) < 0;
    }
    bool operator > (const LongInt2 &That) const noexcept
    {
        return Compare(That) > 0;
    }
    bool operator <= (const LongInt2 &That) const noexcept
    {
        return Compare(That) <= 0;
    }
    bool operator >= (const LongInt2 &That) const noexcept
    {
        return Compare(That) >= 0;
    }

    // Умножение. Возможен (корректен) вызов: xxx.Mul( xxx, yyy );
    LongInt2 & Mul(const LongInt2 & Mul1, const LongInt2 & Mul2);

    // Вычисление остатка от деления: return ( Dividend % Divider );
    // Возможен (корректен) вызов: xxx.CalcRest( xxx, yyy );
    LongInt2 & CalcRest(const LongInt2 &Dividend, const LongInt2 &Divider);

    LongInt2 & CalcRestEx(const LongInt2 & Dividend, const LongInt2 & Divider, const LongInt2 * const* pMulTable);

    // Определение реальной длины числа (без учета старших нулей)
    int GetRealSize() const noexcept;

    // Определение реальной длины числа (без учета старших нулей) в словах
    int GetRealSize2() const noexcept;

    // Определение реальной длины числа (без учета старших нулей) в битах
    int GetRealSizeBits() const noexcept;

    // Вычисление частного от деления (this) и остатка в OutRest
    LongInt2 & Divide(const LongInt2 &Dividend, const LongInt2 &Divider, LongInt2 *OutRest = nullptr);

    // Вычисление обратного элемента:  (This * Number) % Module == 1
    // Возвращаемые значения:
    //      0 - OK
    //      2 - Нет обратного элемента
    //      1 - Ошибка во входных данных (Number > Module)
    int CalcBack(const LongInt2 &Number, const LongInt2 &Module);

    // Загрузка числа из памяти
    void LoadFromMem(const void * Source, int Bytes = -0x10000) noexcept;

    void Copy(const LongInt2 & Source) noexcept;

    void Zero() noexcept
    {
        memset(m_Number, 0, GetSize());
    }

    unsigned char & operator [] (int Index) const
    {
        if  ((unsigned)Index >= (unsigned)m_Size)
        {
            throw;
        }
        return m_Number[Index];
    }

    int GetSize () const noexcept
    {
        return m_Size;  // Размер в байтах
    }

    void print(const char * message = nullptr)
    {
        if  (message)
        {
            printf("%s", message);
        }
        for (int i = m_Size; i; )
        {
            printf("%02x", (int) m_Number[--i]);
        }
        printf("(hex)\n");
    }
    CMaaString sprintf(const char * message = nullptr)
    {
        CMaaString ret;
        if  (message)
        {
            ret = message;
        }
        for (int i = m_Size; i; )
        {
            ret.Format("%S%02x", &ret, (int) m_Number[--i]);
        }
        ret += "(hex)\n";
        return ret;
    }
    ADD_ALLOCATOR(LongInt2)
private:
    void Init(int Size);
};
//---------------------------------------------------------------------------
//int CharToHex(char c) noexcept;
inline int constexpr CharToHex(char c) noexcept
{
    return (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
}

int Import(LongInt2 &p, const char * ptr) noexcept; // returns size of number in bytes or -1
CMaaString Import(CMaaString Text);
//---------------------------------------------------------------------------
#endif // __MAA_LongInt2_H
