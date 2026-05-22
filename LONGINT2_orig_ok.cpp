
// Арифметика длинных целых беззнаковых чисел
// Автор: Моисеенко А.А.
// Version 1.5 // 28.05.2007
// Для всех платформ


#include "stdafx.h"
#include "temp.h"

#ifdef  _DEBUG
     #define DebugPrintf( string ) printf( "\n%s\n", string )
//; getch()
#else
     #define DebugPrintf( string ) // Nothing to do
#endif

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
LongInt2 & LongInt2::operator = (const LongInt2 &Second)
{
    int Size = Second.GetRealSize();
    if  (Size > m_Size)
    {
        throw "LongInt2 & LongInt2::operator = (const LongInt2 &Second)";
    }
    LoadFromMem(Second.m_Number, Size);
    return *this;
}
//---------------------------------------------------------------------------
bool LongInt2::operator==(const LongInt2 &That) const
{
    int Size1 = GetRealSize();
    int Size2 = That.GetRealSize();
    if  (Size1 != Size2)
    {
        return false;
    }
    return !memcmp(m_Number, That.m_Number, Size1);
}
//---------------------------------------------------------------------------
bool LongInt2::operator!=(const LongInt2 &That) const
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
void LongInt2::LoadFromMem(const void * Source, int Bytes)
{
    int  Size = GetSize();

    if  (!Bytes)
    {
        Bytes = Size;
    }
    if  (!Source)  // NULL
    {
        Bytes = 0;
    }
    if  (Bytes > Size)
    {
        Bytes = Size; // or throw
    }
    memcpy(m_Number, Source, Bytes);
    memset(m_Number + Bytes, 0, Size - Bytes + 2);
}
//---------------------------------------------------------------------------
void LongInt2::Copy(const LongInt2 & Source)
{
    LoadFromMem(Source.m_Number, Source.GetSize());
}
//---------------------------------------------------------------------------
void LongInt2::Init(int Size)
{
    m_Number = NULL;
    m_Size = Size;
    m_Size2 = (m_Size + sizeof(short) - 1) / sizeof(short);
    m_TotalSize = (m_Size2 + 1) * sizeof(short);
    if  (sizeof(short) != 2)
    {
        throw "sizeof(short) != 2";
    }
    m_Number = new unsigned char [sizeof(short) + m_TotalSize];
    if  (m_Number)
    {
        memset(m_Number, 0, (m_Size2 + 2) * sizeof(short));
        m_Number += sizeof(short);
    }
    else
    {
        throw "new[] returns NULL in void LongInt2::Init(int Size)";
    }
}
//---------------------------------------------------------------------------
LongInt2 & LongInt2::operator += (const LongInt2 &Second)
{
    int Size1 = sizeof(short) * m_Size2;
    int Size2 = sizeof(short) * Second.m_Size2;

    if  (Size2 > Size1)
    {
        Size2 = sizeof(short) * Second.GetRealSize2(); // 26.02.2008: __ Second. __
    }
    if  (Size2 > Size1)
    {
        throw "Size2 > Size1 in LongInt2 & LongInt2::operator += (const LongInt2 &Second)";
    }
    int i;
    unsigned long v = 0;
    for (i = 0; i < Size2; i += sizeof(short))
    {
        v += Get(i) + Second.Get(i);
        Set(i, v);
        v >>= 16;
    }
    for (; i < Size1 && v; i += sizeof(short))
    {
        v += Get(i);
        Set(i, v);
        v >>= 16;
    }
    if  (v)
    {
        throw "Overflow in LongInt2 & LongInt2::operator += (const LongInt2 &Second)"; // overflow
    }

    return *this;
}
//---------------------------------------------------------------------------
LongInt2 & LongInt2::operator -= (const LongInt2 &Second)
{
    int Size1 = sizeof(short) * m_Size2;
    int Size2 = sizeof(short) * Second.m_Size2;

    if  (Size2 > Size1)
    {
        Size2 = sizeof(short) * Second.GetRealSize2();
    }
    if  (Size2 > Size1)
    {
        throw "(Size2 > Size1) in LongInt2 & LongInt2::operator -= (const LongInt2 &Second)";
    }
    int i;
    long v = 0;
    for (i = 0; i < Size2; i += sizeof(short))
    {
        v = (long)Get(i) - (long)Second.Get(i) + v;
        Set(i, (unsigned long)v);
        v >>= 16;
    }
    for (; i < Size1 && v; i += sizeof(short))
    {
        v = (long)Get(i) + v;
        Set(i, v);
        v >>= 16;
    }
    if  (v)
    {
        throw "Underflow in LongInt2 & LongInt2::operator -= (const LongInt2 &Second)"; // underflow
    }

    return *this;
}
//---------------------------------------------------------------------------
int LongInt2::Compare(const LongInt2 &That) const
{
    int Size1 = sizeof(short) * GetRealSize2();
    int Size2 = sizeof(short) * That.GetRealSize2();
    if  (Size1 != Size2)
    {
        return Size1 - Size2;
    }
    for (int i = Size1 - 2; i >= 0; i -= 2)
    {
        long x = (long)Get(i) - (long)That.Get(i);
        if  (x != 0)
        {
            return x;
        }
    }
    return 0;
}
//---------------------------------------------------------------------------
LongInt2::~LongInt2()
{
    m_Number -= sizeof(short);
    if  (m_Number)
    {
        memset(m_Number, 0, (m_Size2 + 2) * sizeof(short));
    }
    delete [] m_Number;
}
//---------------------------------------------------------------------------
// Определение реальной длины числа (без учета старших нулей)
int LongInt2::GetRealSize() const
{
    unsigned char * p;

    for (p = m_Number + GetSize() - 1; p >= m_Number && !(*p); p--);

    return (int)(p - m_Number + 1);
}
//---------------------------------------------------------------------------
// Определение реальной длины числа (без учета старших нулей) в словах
int LongInt2::GetRealSize2() const
{
    return (GetRealSize() + sizeof(short) - 1) / sizeof(short);
}
//---------------------------------------------------------------------------
LongInt2 & LongInt2::CalcRest(const LongInt2 & Dividend, const LongInt2 & Divider)
{
    int  DividendSize = Dividend.GetSize(),
    DividerSize =  Divider.GetSize();

    //   определение реальной длины делителя (без учета старших нулей)
    int  RealDividerSize = Divider.GetRealSize();

    if  (!RealDividerSize)
    {
        DebugPrintf("LongInt2::CalcRest() - Divider==0");
        throw "LongInt2::CalcRest() - Divider==0";
    }
    if  (GetSize() < RealDividerSize)
    {
        DebugPrintf("LongInt2::CalcRest() - ThisSize < RealDividerSize");
        throw "LongInt2::CalcRest() - ThisSize < RealDividerSize";
    }

    // создание рабочего буфера
    LongInt2 Rest(Dividend);

    if  (DividendSize >= RealDividerSize)
    {
        for (int i = Rest.GetRealSize(); i >= RealDividerSize; i--)
        {
            unsigned long x = Rest.Get(i - 2) + (Rest.m_Number[i] << 16);
            unsigned long y = Divider.Get(RealDividerSize - 2);
            unsigned long z = x / y;
            long v = 0;
            for (int j = 0; j < RealDividerSize + 1; j += 2)
            {
                unsigned long m = Divider.Get(j) * z;
                v = (long)Rest.Get(i - RealDividerSize + j) - (long)m + v;
                Rest.Set(i - RealDividerSize + j, (unsigned long)v);
                v >>= 16;
            }
            if  (v < 0)
            {
                v = 0;
                for (int j = 0; j < RealDividerSize + 1; j += 2)
                {
                    unsigned long m = Divider.Get(j)/* * z*/;
                    v = (long)Rest.Get(i - RealDividerSize + j) + (long)m + v;
                    Rest.Set(i - RealDividerSize + j, (unsigned long)v);
                    v >>= 16;
                }
            }
        }
    }
    LoadFromMem(Rest.m_Number, RealDividerSize);
    return *this;
}
//---------------------------------------------------------------------------
LongInt2 & LongInt2::CalcRestEx(const LongInt2 & Dividend, const LongInt2 & Divider, LongInt2 ** pMulTable)
{
    int  DividendSize = Dividend.GetSize(),
    DividerSize =  Divider.GetSize();

    //   определение реальной длины делителя (без учета старших нулей)
    int  RealDividerSize = Divider.GetRealSize();

    if  (!RealDividerSize)
    {
        DebugPrintf("LongInt2::CalcRestEx() - Divider==0");
        throw "LongInt2::CalcRestEx() - Divider==0";
    }
    if  (GetSize() < RealDividerSize)
    {
        DebugPrintf("LongInt2::CalcRestEx() - ThisSize < RealDividerSize");
        throw "LongInt2::CalcRestEx() - ThisSize < RealDividerSize";
    }

    // создание рабочего буфера
    LongInt2 Rest(Dividend);

    if  (DividendSize >= RealDividerSize)
    {
        for (int i = Rest.GetRealSize(); i >= RealDividerSize; i--)
        {
            unsigned long x = Rest.Get(i - 2) + (Rest.m_Number[i] << 16);
            unsigned long y = Divider.Get(RealDividerSize - 2);
            unsigned long z = x / y;
            unsigned long z0 = z;
            long v = 0;
            if  (z > 0)
            {
                if  (z > 255)
                {
                    z = 255;
                }
                const LongInt2 * zz = pMulTable[z - 1];
                for (int j = 0; j < RealDividerSize + 2; j += 2)
                {
                    unsigned long m = zz->Get(j);
                    v = (long)Rest.Get(i - RealDividerSize + j) - (long)m + v;
                    Rest.Set(i - RealDividerSize + j, (unsigned long)v);
                    v >>= 16;
                }
                if  (v < 0)
                {
                    v = 0;
                    for (int j = 0; j < RealDividerSize + 2; j += 2)
                    {
                        unsigned long m = Divider.Get(j);
                        v = (long)Rest.Get(i - RealDividerSize + j) + (long)m + v;
                        Rest.Set(i - RealDividerSize + j, (unsigned long)v);
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
LongInt2 & LongInt2::Mul(const LongInt2 & Mul1, const LongInt2 & Mul2)
{
    int Mul1Size = Mul1.GetRealSize();
    int Mul2Size = Mul2.GetRealSize();

    if  ( Mul1Size == 0 || Mul2Size == 0 )
    {
        Zero();
        return *this;
    }

    // создание рабочего буфера
    LongInt2 Product(4 + (Mul1Size + Mul2Size));

    for (int i = 0; i < Mul2Size + 1; i += 2)
    {
        unsigned long m = Mul2.Get(i);
        unsigned long v = 0;
        int j;
        for (j = 0; j < Mul1Size; j += 2)
        {
            v += Mul1.Get(j) * m + Product.Get(i + j);
            Product.Set(i + j, v);
            v >>= 16;
        }
        if  (Product.Get(i + j) != 0)
        {
            DebugPrintf("Product.Get(i + j) != 0");
        }
        //v += Product.Get(i + j);
        Product.Set(i + j, v);
    }
    LoadFromMem(Product.m_Number, Product.GetRealSize());
    return *this;
}
//---------------------------------------------------------------------------
LongInt2 & LongInt2::Divide(const LongInt2 &Dividend, const LongInt2 &Divider, LongInt2 *OutRest)
{
    int  DividendSize = Dividend.GetSize(),
    DividerSize =  Divider.GetSize();

    //   определение реальной длины делителя (без учета старших нулей)
    int  RealDividerSize = Divider.GetRealSize();

    if  (!RealDividerSize)
    {
        DebugPrintf("LongInt2::Divide() - Divider==0");
        throw "LongInt2::Divide() - Divider==0";
    }
    if  (GetSize() < RealDividerSize)
    {
        DebugPrintf("LongInt2::Divide() - ThisSize < RealDividerSize");
        throw "LongInt2::Divide() - ThisSize < RealDividerSize";
    }

    // создание рабочего буфера
    LongInt2 Rest(Dividend);
    LongInt2 Result(Dividend.GetSize());

    if  (DividendSize >= RealDividerSize)
    {
        for (int i = Rest.GetRealSize(); i >= RealDividerSize; i--)
        {
            unsigned long x = Rest.Get(i - 2) + (Rest.m_Number[i] << 16);
            unsigned long y = Divider.Get(RealDividerSize - 2);
            unsigned long z = x / y;
            long v = 0;
            int j;
            for (j = 0; j < RealDividerSize + 1; j += 2)
            {
                unsigned long m = Divider.Get(j) * z;
                v = (long)Rest.Get(i - RealDividerSize + j) - (long)m + v;
                Rest.Set(i - RealDividerSize + j, (unsigned long)v);
                v >>= 16;
            }
            if  (v < 0)
            {
                z--;
                v = 0;
                for (int j = 0; j < RealDividerSize + 1; j += 2)
                {
                    unsigned long m = Divider.Get(j)/* * z*/;
                    v = (long)Rest.Get(i - RealDividerSize + j) + (long)m + v;
                    Rest.Set(i - RealDividerSize + j, (unsigned long)v);
                    v >>= 16;
                }
            }
            for (j = i - RealDividerSize; z > 0; j += 2)
            {
                z += Result.Get(j);
                Result.Set(j, z);
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
    return 0;
}
//---------------------------------------------------------------------------

int CharToHex(char c)
{
    if  (c >= '0' && c <= '9')
    {
        return c - '0';
    }
    if  (c >= 'a' && c <= 'f')
    {
        return c - 'a' + 10;
    }
    if  (c >= 'A' && c <= 'F')
    {
        return c - 'A' + 10;
    }
    return -1;
}

int Import(LongInt2 &p, const char * ptr)
{
    int len = (int)strlen(ptr);
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
