#include "stdafx.h"
#include "temp.h"

extern int gReduceCount;
extern int gMyRestCount;

extern int gAddDivider;
extern int gAddDivider2;
extern int gAddDividerFlag;
extern int gSub;

static int gExpCount = 0;

int gMyRestCount=0;
int gReduceCount=0;

CCryptRandom::CCryptRandom(int Mode, bool bThrow)
:   m_Mode(Mode)
#ifdef __unix__
    ,
    m_file("/dev/urandom", CMaaFile::eR_SrSw, bThrow),
    //     m_file(nullptr, nullptr, false),
    m_nRequestsProcessed(0)
#endif
{
    FILE * f = nullptr;//fopen("logs\\_ccr_1.txt", "a+b");
    if  (f)
    {
        fprintf(f, "CCryptRandom::CCryptRandom()\r\n");
    }
#ifdef _WIN32
    m_hProv = 0;
    const BOOL bres = CryptAcquireContext(&m_hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT|CRYPT_SILENT);
    const DWORD dw = GetLastError();
    if  (f)
    {
        fprintf(f, "CryptAcquireContext() return %s, m_hProv = %p\r\n", bres ? "true" : "false", (void *)m_hProv);
        if  (!bres)
        {
            XTOOLastError err("error: ", dw);
            fprintf(f, "%s\r\n", err.GetMsg());
        }
    }
    if  (!m_hProv && bThrow && !(Mode & eAllowRunTimeRandForStartingKey))
    {
        if  (f)
        {
            fclose(f);
        }
        throw 1;
    }
#endif
    memset(m_gost_key_and_salt, 0, sizeof(m_gost_key_and_salt));
    if  (f)
    {
        fclose(f);
    }
}

CCryptRandom::~CCryptRandom()
{
#ifdef _WIN32
    if  (m_hProv)
    {
        CryptReleaseContext(m_hProv, 0);
    }
#else
    //if  ('u'<'r')
    if  (m_nRequestsProcessed)
    {
        char ptr[64];
        memset(ptr, 0, (int)sizeof(ptr));
        if  (Get(ptr, 64))
        {
            FlushSeed(ptr, 64);
        }
    }
#endif
    memset(m_gost_key_and_salt, 0, sizeof(m_gost_key_and_salt));
    FILE * f = nullptr;//fopen("logs\\_ccr_1.txt", "a+b");
    if  (f)
    {
        fprintf(f, "CCryptRandom::~CCryptRandom()\r\n");
        fclose(f);
    }
}

bool CCryptRandom::Get(void * ptr, int len) // noexcept
{
#ifdef _WIN32
    if  (!m_hProv && !(m_Mode & eAllowRunTimeRandForStartingKey))
    {
        return false;
    }
    //     return CryptGenRandom(m_hProv, len, (LPBYTE) ptr) != FALSE;
#endif
    if  (m_b1st)
    {
        //printf("point 1\n");
        int nn = 0;
#ifdef _WIN32
        if  (m_hProv && CryptGenRandom(m_hProv, sizeof(m_gost_key_and_salt), (LPBYTE)m_gost_key_and_salt))
        {
            //m_b1st =
            nn = (int)sizeof(m_gost_key_and_salt);
        }
#else
        //printf("point 2\n");
        char * ptr2 = (char *)m_gost_key_and_salt;
        int req = (int)sizeof(m_gost_key_and_salt);
        //if  ('u'<'r')
        {
            //int x = 
                GetSeed(ptr2, req);
            //ptr2 += x;
            //req -= x;
            //nn += x;
        }
        //else
        {
            timeval tv;
            memset(&tv, 0, sizeof(tv));
            gettimeofday(&tv, nullptr);
            int iField = 0;
            while(req > 0)
            {
                int ___rnd = 0;
                int x = m_file.Read(&___rnd, sizeof(___rnd));
                if  (x <= 0)
                {
                    break;
                }
                //memcpy(ptr2, &___rnd, req >= (int)sizeof(___rnd) ? sizeof(___rnd) : req);
                if (req >= (int)sizeof(int))
                {
                    *(int *)ptr2 ^= ___rnd ^ (!iField ? (int)tv.tv_sec : (int)tv.tv_usec);
                    iField = 1 - iField;
                }
                ___rnd = 0;
                ptr2 += x;
                req -= x;
                nn += x;
            }
        }
#endif
        static char zero[32];
        if  (nn == (int)sizeof(m_gost_key_and_salt))
        {
            if  (ConstMemcmp(m_gost_key_and_salt, zero, 32) && ConstMemcmp(m_gost_key_and_salt + 32, zero, 32))
            {
                //printf("point 3\n");
                m_b1st = false;
            }
        }
        if  (m_b1st && (m_Mode & eAllowRunTimeRandForStartingKey))
        {
            // regenerate or if runtime srand/rand allowed for initial key generation
#ifdef _WIN32
            const _dword dw1 = GetTickCount();
            const _dword dw2 = (_dword)time(nullptr);
            LARGE_INTEGER tmp;
            QueryPerformanceFrequency(&tmp);
            const _qword q1 = (_qword)tmp.QuadPart;
            const _qword q2 = (_qword)__rdtsc();
            const _dword dw3 = (_dword)q1;
            const _dword dw4 = (_dword)(q1 >> 32);
            const _dword dw5 = (_dword)q1;
            const _dword dw6 = (_dword)(q1 >> 32);
            srand( (dw1 << 16) ^ (dw1 >> 16)
                 ^ (dw2 << 16) ^ (dw2 >> 16)
                 ^ (dw3 << 16) ^ (dw3 >> 16)
                 ^ (dw4 << 16) ^ (dw4 >> 16)
                 ^ (dw5 << 16) ^ (dw5 >> 16)
                 ^ (dw6 << 16) ^ (dw6 >> 16)
                 ^ 1234567890);
#else
            timeval tv;
            gettimeofday(&tv, nullptr);
            srand((tv.tv_sec << 16) ^ (tv.tv_sec >> 16) ^ (tv.tv_usec << 16) ^ (tv.tv_usec >> 16) ^ 1234567890);
#endif
            for (int j = 0; j < 10 && m_b1st; j++)
            {
                for (int i = 0; i < (int)sizeof(m_gost_key_and_salt); i++)
                {
                    m_gost_key_and_salt[i] = (char)rand();
                }
                if  (ConstMemcmp(m_gost_key_and_salt, zero, 32) && ConstMemcmp(m_gost_key_and_salt + 32, zero, 32))
                {
                    m_b1st = false;
                }
            }
        }
    }
    //printf("point 4, 0x%4x\n", m_Mode);
    if  (m_b1st)
    {
        return false;
    }
    //printf("point 5\n");
    if  (
#ifdef _WIN32
         m_hProv &&
#endif
         (m_Mode & (
#ifdef _WIN32
         0
#else
         eOSCryptFunctionsForStartingKey
#endif
         | eForcedOSCryptFunctionsForStartingKeyOnly)) == 0)
    {
#ifdef _WIN32
        return CryptGenRandom(m_hProv, len, (LPBYTE) ptr) != FALSE;
#else
        //printf("point 6\n");
        int nn = 0;
        char * ptr2 = (char *)ptr;
        int req = (int)len;
        while(req > 0)
        {
            int ___rnd = 0;
            int x = m_file.Read(&___rnd, sizeof(___rnd));
            if  (x <= 0)
            {
                break;
            }
            memcpy(ptr2, &___rnd, req >= (int)sizeof(___rnd) ? sizeof(___rnd) : req);
            ___rnd = 0;
            ptr2 += x;
            req -= x;
            nn += x;
        }
        return nn == len;
#endif
    }

    //printf("test\n");
    _qword Salt;
    const int Mode = m_Mode;
    if  (Mode & eSyncronizeThreads)
    {
        m_Mutex.LockM();
    }
    Salt = ++(*(_qword *)(m_gost_key_and_salt + 64));
    if  (!Salt)
    {
        Salt = ++(*(_qword *)(m_gost_key_and_salt + 64));
    }
    if  (Mode & eSyncronizeThreads)
    {
        m_Mutex.UnLockM();
    }
    memset(ptr, 0, len);
    m_gost.Encrypt(m_gost_key_and_salt, ptr, len, &Salt);
    if  (Mode & eSyncronizeThreads)
    {
        m_Mutex.LockM();
    }
    m_gost.Encrypt(m_gost_key_and_salt + 32, m_gost_key_and_salt + 64, 8, &Salt);
    if  (Mode & eSyncronizeThreads)
    {
        m_Mutex.UnLockM();
    }
    Salt = 0;
#ifdef __unix__
    ++m_nRequestsProcessed;
#endif
    return true;
}

#ifdef __unix__

#define TMP_SEED_FILE1_FMT "/var/www/temp/randseed%1"
#define TMP_SEED_FILE2_FMT "/tmp/randseed%1"

int CCryptRandom::GetSeed(void * ptr, int size)
{
    _qword uid = getuid();
    m_SeedFn.Format2("%D", TMP_SEED_FILE1_FMT, uid);
    CMaaFile f(m_SeedFn, CMaaFile::eR_SrSw, eNoExcept);
    if (!f.IsOpen())
    {
        m_SeedFn.Format2("%D", TMP_SEED_FILE2_FMT, uid);
        f = CMaaFile(m_SeedFn, CMaaFile::eR_SrSw, eNoExcept);
    }
    char buffer[64];
    memset(buffer, 0, 64);
    if  (f.IsOpen())
    {
        f.Read(buffer, 64);
    }
    timeval tv;
    gettimeofday(&tv, nullptr);
    srand((tv.tv_sec << 16) ^ (tv.tv_sec >> 16) ^ (tv.tv_usec << 16) ^ (tv.tv_usec >> 16) ^ 1234567890);
    char * p = (char *)&tv;
    int i;
    for (i = 0; i < (int)sizeof(tv); i++)
    {
        buffer[i + 8] ^= p[i];
    }
    _qword qw[2] = {getpid(), 0};
    for (i = 0; i < (int)sizeof(qw[0]); i++)
    {
        buffer[i] ^= *(i + (char*)qw);
    }
    int retsize = 0;
    for (; size > 0; size -= 64)
    {
        memcpy(ptr, buffer, size >= 64 ? 64 : size);
        retsize += (size >= 64 ? 64 : size);
        ptr = (char *)ptr + 64;
    }
    return retsize;
}
int CCryptRandom::FlushSeed(const void * ptr, int size)
{
    if  (size >= 64)
    {
        /*
        _qword uid = getuid();
        CMaaFile f(CMaaString::sFormat2("%D", TMP_SEED_FILE1_FMT, uid), CMaaFile::eRWC_SrSw, "mode=640", eNoExcept);
        if (!f.IsOpen())
        {
            f = CMaaFile(CMaaString::sFormat2("%D", TMP_SEED_FILE2_FMT, uid), CMaaFile::eRWC_SrSw, "mode=640", eNoExcept);
        }
        */
        CMaaFile f(m_SeedFn, CMaaFile::eRWC_SrSw, "mode=640", eNoExcept);
        if  (f.IsOpen())
        {
            return (int)f.Write(ptr, 64);
        }
    }
    return 0;
}
#endif

static CCryptRandom* gpCCryptRandom = nullptr;
static CGostBsMaa * gpGostBsMaa = nullptr;

CCryptRandom & GetGlobal___CCryptRnd() noexcept
{
    if  (!gpCCryptRandom)
    {
        __GLock__lib(true);
        __GLock__usr(true);
        CMaaWin32Locker<CMaa_gLock_usr_Mutex> gLocker(gLock);
        gLocker.LockM();
        if  (!gpCCryptRandom)
        {
            gpCCryptRandom = new CCryptRandom; //(CCryptRandom::eForcedOSCryptFunctionsForStartingKeyOnly);
        }
        gLocker.UnLockM();
    }
    return *gpCCryptRandom;
}

CGostBsMaa & GetGlobal___gGostBsMaa() noexcept
{
    if  (!gpGostBsMaa)
    {
        __GLock__lib(true);
        __GLock__usr(true);
        CMaaWin32Locker<CMaa_gLock_usr_Mutex> gLocker(gLock);
        gLocker.LockM();
        if  (!gpGostBsMaa)
        {
            gpGostBsMaa = new CGostBsMaa;
        }
        gLocker.UnLockM();
    }
    return *gpGostBsMaa;
}

#define global___Rnd GetGlobal___CCryptRnd()

class CMaaCLGlobDel
{
public:
    CMaaCLGlobDel() noexcept
    {
        __GLock__lib(true);
        __GLock__usr(true);
    }
    ~CMaaCLGlobDel()
    {
        CMaaWin32Locker<CMaa_gLock_usr_Mutex> gLocker(gLock);
        gLocker.LockM();
        if  (gpGostBsMaa)
        {
            delete gpGostBsMaa;
            gpGostBsMaa = nullptr;
        }
        if  (gpCCryptRandom)
        {
            delete gpCCryptRandom;
            gpCCryptRandom = nullptr;
        }
        gLocker.UnLockM();
    }
};

#ifndef CRYPTLIB_USE_ASM64
#if 0
// 0 - p1[] == p2[],  != 0 - p1[] != p2[]
_dword ConstMemcmp(const void* p1, const void* p2, size_t len) noexcept
{
    const _uqword* ptr1 = (const _uqword*)p1;
    const _uqword* ptr2 = (const _uqword*)p2;
    _uqword a64 = 0;
    size_t i;
    for (i = len >> 4; i; i--)
    {
        a64 |= ptr1[0] ^ ptr2[0];
        a64 |= ptr1[1] ^ ptr2[1];
        ptr1 += 2;
        ptr2 += 2;
    }
    _dword a32 = (_dword)((a64 >> 32) | a64);
    const unsigned char* ptr1_ = (const unsigned char*)ptr1;
    const unsigned char* ptr2_ = (const unsigned char*)ptr2;
    for (i = len & 0xf; i; i--)
    {
        a32 |= *ptr1_++ ^ *ptr2_++;
    }
    //_dword a16 = (_word)((a32 >> 16) | a32);
    //unsigned char a8 = (unsigned char)((a16 >> 8) | a16);
    //return a8;
    return a32;
}
#else
// 0 - p1[] == p2[],  != 0 - p1[] != p2[]
_dword ConstMemcmp(const void* p1, const void* p2, size_t len) noexcept
{
    const unsigned char* ptr1 = (const unsigned char*)p1;
    const unsigned char* ptr2 = (const unsigned char*)p2;
    unsigned char a = 0;
    for (size_t i = len; i; i--)
    {
        a |= *ptr1++ ^ *ptr2++;
    }
    return a;
}
#endif
#endif

CMaaCLGlobDel gCMaaCLGlobDel;

void GetRnd(void *ptr, int size)
{
    global___Rnd.Get(ptr, size);
}

void GenRnd(LongInt2 &p, int R /* = 0*/)
{
    if  (R == 0)
    {
        R = p.GetSize();
    }
    if  (R > p.GetSize())
    {
        throw "GenRnd(): R > p.GetSize()";
    }
    p.Zero();
    /*
        for     (int i = 0; i < R; i++)
        {
                p[i] = rand();
        }
    */
    global___Rnd.Get(p(), R);
}

int IsPrime(LongInt2 &p, int pass, bool (* ProgressProc)(int pass, int n, int m, void * Param), void * Param)
{
    const int N = p.GetSize();
    const int R = N;

    LongInt2 a(N), p_1(N), p_1_2(N), n0(N), n1(N), n2(N);

    n1[0] = 1;
    n2[0] = 2;

    if  (p == n1 || p == n0)
    {
        return false;
    }

    //printf("[1]\n");fflush(stdout);
    p_1.LoadFromMem(p());
    //printf("[2]\n");fflush(stdout);
    p_1 -= n1;
    //printf("[3]\n");fflush(stdout);
    p_1_2.Divide(p_1, n2);

    int cnt1 = 0, cnt_1 = 0;

    //printf("[4]\n");fflush(stdout);
    CMyExponent MyExp(p(), N);
    //printf("[5]\n");fflush(stdout);

    for (int i = 0; i < R * 8 + 5; i++)
    {
        //printf("i = %d of %d\n", i, R * 8 + 5);fflush(stdout);
        //int iii = 0;
        do
        {
            //printf("\n(1) %d,%d...\n", i, ++iii); fflush(stdout);
            global___Rnd.Get(a(), R);
            //printf("[6]\n");fflush(stdout);
            //printf("\n(2) %d,%d...\n", i, iii); fflush(stdout);
            a %= p;

        } while(a == n0);

        //printf("[7]\n");fflush(stdout);
        //printf("\n(3)...\n"); fflush(stdout);
        MyExp.Exponent(a(), p_1_2(), a());
        //printf("[8]\n");fflush(stdout);

        if  (ProgressProc)
        {
            //printf("\n(4) %d...\n"); fflush(stdout);
            if  (!ProgressProc(pass, i, R * 8 + 5 - 1, Param))
            {
                return -1;
            }
        }

        if  (a == n1)
        {
            //printf("\n(5) ...\n"); fflush(stdout);
            cnt1++;
            continue;
        }
        else if (a == p_1)
        {
            //printf("\n(6) ...\n"); fflush(stdout);
            cnt_1++;
            continue;
        }
        //printf("not prime number.\n");
        return 0;
    }
    //printf("possible, prime number.\n");
    //DWORD Time1 = GetTickCount();
    //printf("%d sec %d %d ", (Time1 - Time0 + 500) / 1000, cnt1, cnt_1);
    //p.print("p = ");
    if  (cnt_1 == 0)
    {
        //printf("\n(7) ...\n"); fflush(stdout);
        //printf("posible not prime number with ver=1/2^%d\n", cnt1);
        return 0;
    }
    return 1;
}

int GenPrime(LongInt2 &p, int R /* = 0*/, bool (* ProgressProc)(int pass, int n, int m, void * Param), void * Param)
{
    int pass = 0;
    if  (R == 0)
    {
        R = p.GetSize();
    }
    if  (R > p.GetSize())
    {
        //printf("\n(__1) error \n");
        throw "GenPrime(): R > p.GetSize()";
    }
    int x;
    do
    {
        //printf("...\n");fflush(stdout);
        GenRnd(p, R);
        //p.print("p = ");fflush(stdout);
        p[0] |= 1;
        p[R - 1] |= 0x80;

        //printf("gExpCount = %d\n", gExpCount);

        x = IsPrime(p, ++pass, ProgressProc, Param);
        if  (x < 0)
        {
            break;
        }

    }    while(!x);

    return x;
}

void ___mainCrypt ()
{
    //GostTest();
    return;

    int fcnt = 0;
    /*
        try
        {
                for     (int i = 0; i < 1000; i++)
                {
               if       (i == 998)
                        {
                                static int aa = 0;
                                aa++;
                        }
                        printf("%4d. ", i);
                        LongInt2 a1(64), a2(32), a3(64);
                        GenRnd(a1, 64);
                        GenRnd(a2, 32);
                        LongInt22 b1(a1(), a1.GetSize()), b2(a2(), a2.GetSize());
                        LongInt22 b3(a3.GetSize());
                        a1 %= a2;
                        //a3.Mul(a1, a2);
                        //b1.print("b1 = ");
                        //b2.print("b2 = ");
                        //b3.Mul(b1, b2);
               b1 %= b2;
                        if      (!ConstMemcmp(a1(), b1(), 64))
                        {
                                printf("OK\n");
                        }
                        else
                        {
                                fcnt++;
                                printf("Fail\n");
                        }
                }
        }
        catch(const char * message)
        {
                printf("catch(message): %s\n", message);
        }
        catch(...)
        {
                printf("catch(...)\n");
        }
        printf("Failures count: %d\n", fcnt);
        return;
     */
    try
    {
        if  (0)
        {
            LongInt2 a(2), b(2), c(2), d(4);
            a[0]=0xfe; a[1]=0xff;
            b[0]=0xfe; b[1]=0xff;
            c[0]=0xff; c[1]=0xff;
            a.print("a = ");
            b.print("b = ");
            c.print("c = ");
            CMyExponent MyExp(c(), 2);
            MyExp.Exponent(a(), b(), d());
            d.print("d = ");
        }

        int N = 1024/8;
        //N = 32;
        const int R = N & ~1;

        LongInt2 p(N / 2), q(N / 2);

        GenPrime(p, R / 2);
        p.print("p = ");

        GenPrime(q, R / 2);
        q.print("q = ");

        LongInt2 n(N);

        n.Mul(p, q);
        n.print("n = p * q = ");

        LongInt2 _1(N);
        _1[0] = 1;

        LongInt2 tmp1(N / 2), tmp2(N / 2);
        tmp1.LoadFromMem(p());
        tmp1 -= _1;
        tmp2.LoadFromMem(q());
        tmp2 -= _1;

        LongInt2 p_1_q_1(N);
        p_1_q_1.Mul(tmp1, tmp2);

        LongInt2 e(N), d(N);

        int i;

        for (int j = 0; j < 20; j++)
        {
            i = 0;
            printf("Generating e...\n");
            do
            {
                /*
                    if   (i)
                    {
                         printf("The next does not have Back element:\n");
                         e.print("e = ");
                    }
                */
                GenRnd(e, p_1_q_1.GetRealSize() - 1); // CalcBack works with e < p_1_q_1

            } while(d.CalcBack(e, p_1_q_1) != 0 && ++i < 100);

            if  (i >= 100)
            {
                printf("Generation of e failed %d times.\n", i);
                p.print("p = ");
                q.print("q = ");
                n.print("n = p * q = ");
                return;
            }

            //printf("i =%2d ", i);
            //e.print("e = ");
            //d.print("      d = ");
            //}

            e.print("e = ");
            d.print("d = ");

            LongInt2 PlainText(N);
            char * Text = TL_NEW char[N + 1000];
            Text[0] = 0;
            i = 0;
            while((int)strlen(Text) < N)
            {
                sprintf(Text + strlen(Text), "This is a plain text %d...", ++i);
            }
            PlainText.LoadFromMem(Text, p_1_q_1.GetRealSize() - 1);
            PlainText[p_1_q_1.GetRealSize() - 1] = 0;
            memset(Text, 'X', N + 1000);

            printf("PlainText: %s\n", PlainText());
            //PlainText.print("hex = ");

            LongInt2 ChipherText(N);

            CMyExponent MyExp(n(), N);
            MyExp.Exponent(PlainText(), e(), ChipherText());

            //ChipherText.print("ChipherText hex = ");

            LongInt2 xPlainText(N);

            MyExp.Exponent(ChipherText(), d(), xPlainText());

            memcpy(Text, xPlainText(), N);
            strcpy(&Text[N + 5], "5");
            printf("xPlainText: %s\n", Text);
            //xPlainText.print("hex = ");

            if  (PlainText == xPlainText)
            {
                printf("OK\n");
            }
            else
            {
                fcnt++;
                printf("FAIL\n");
            }

        }

        printf("RSA:\nPublic key is the pair (n, e)\nPrivate key is d\np and q are the top secret\n");

        printf("Failures: %d\n", fcnt);

        //printf("gExpCount = %d\n", gExpCount);

        return;

    }
    catch(const char * message)
    {
        printf("catch(message): %s\n", message);
    }
    catch(...)
    {
        printf("catch(...)\n");
    }
    printf("Failures count: %d\n", fcnt);
    return;

    /*
     N = 512/8;

     int R = N;

     printf("Finding %d bits (%d bytes) prime numbers.\n", R * 8, R);

     LongInt2 p(N);

     int Errors = 0;
     for  (int nn = 0; nn < 1000; nn++)
     {
          DWORD Time0 = GetTickCount();
          printf("%4d ", nn + 1);

          GenPrime(p, R);

          p.print("p = ");

          if   (R <= 4)
          {
               unsigned int x = p[0] + 256 * (p[1] + 256 * (p[2] + 256 * p[3]));
               printf("x = %u\n", x);
               double xx = (double)x;
               xx = sqrt(xx);
               unsigned int sqrtx = 1 + (unsigned int)xx;
               for  (unsigned int ii = 2; ii < sqrtx; ii++)
               {
                    if   ((x % ii) == 0)
                    {
                         printf("Error: %u = %u * %u\n", x, ii, x / ii);
                         Errors++;
                    }
               }
          }
     }

     printf("Done. Errors = %d\n", Errors);

     */

    return;
    /*
     Sleep ( 1000 );
     LongInt2 q ( Number_P, 64 );
     LongInt2 A ( Number_A1, 64 );
     LongInt2 X ( 64 ), X1 ( 64 ), X2 ( 64 ), Y ( 64 ), Y2 ( 64 ), MyY ( 64 ), MyY_ ( 2 * 64 ), MyY1 ( 64 ), MyY2 ( 64 );
     //srand( (unsigned)time( nullptr ) );
     int i;
     for  ( i = 0; i < X.GetSize ()-1; i++ )
     {
          X1 [ i ] = rand ();
          X2 [ i ] = rand ();
     }
     X.Copy ( X1 );
     X += X2;

     LONG64 tmp, my_t, t, my_t2;
     //
     QueryPerformanceCounter ( (LARGE_INTEGER*)&tmp );
     CMyExponent MyExp ( Number_P, 64 );
     MyExp.Exponent ( A(), X(), MyY() );
     QueryPerformanceCounter ( (LARGE_INTEGER*)&my_t );
     my_t -= tmp;
     MyY.print ( "MyY = " );
     QueryPerformanceFrequency ( (LARGE_INTEGER*)&tmp );
     printf ( "%d ticks (%lg ms)\n", ( DWORD ) my_t, ( double ) my_t * 1000.0 / ( double ) tmp );

     printf ( "Time Mul(*) = %d, time Rest(%%) = %d\n", (DWORD)t_mul, (DWORD)t_rest );
     printf ( "Count of Rest = %d\n", gMyRestCount );
     printf ( "gSub = %d, gAddDivider = %d, gAddDivider2 = %d\n", gSub, gAddDivider, gAddDivider2 );

#if 0
     QueryPerformanceCounter ( (LARGE_INTEGER*)&tmp );
     MyExp.Exponent ( A(), X1(), MyY1() );
     MyExp.Exponent ( A(), X2(), MyY2() );
     MyY_.Mul ( MyY1, MyY2 );
     MyY_ %= q;
     MyY.Copy ( MyY_ );
     QueryPerformanceCounter ( (LARGE_INTEGER*)&my_t2 );
     my_t2 -= tmp;
     MyY.print ( "MyY = " );
     QueryPerformanceFrequency ( (LARGE_INTEGER*)&tmp );
     printf ( "%d ticks (%lg ms)\n", ( DWORD ) my_t2, ( double ) my_t2 * 1000.0 / ( double ) tmp );
#endif

     QueryPerformanceCounter ( (LARGE_INTEGER*)&tmp );
     CExponent Exp ( Number_P, 64 );
     Exp.Exponent ( A(), X(), Y() );
     QueryPerformanceCounter ( (LARGE_INTEGER*)&t );
     t -= tmp;
     Y.print ( "  Y = " );
     QueryPerformanceFrequency ( (LARGE_INTEGER*)&tmp );
     printf ( "%d ticks (%lg ms)\n", ( DWORD ) t, ( double ) t * 1000.0 / ( double ) tmp );
     printf ( "Count of Rest = %d\n", gReduceCount );
     */

    /*CExponent Exp2;
     Exp2.Exponent ( A(), X(), Y2() );
     Y2.print ( "  Y2= " );
     */
}

#ifdef CMyExponent2
#undef CMyExponent2
#endif

CMyExponent2::CMyExponent2 ( void * P, _dword Size )
{
    int i;
    m_P = nullptr;
    for ( i = 0; i < MUL_TABLE_SIZE; i++ )
    {
        m_MulTable [ i ] = nullptr;
    }
    if  ( !P )
    {
        throw "P = nullptr";
    }
    try
    {
        m_P = TL_NEW char [ m_Size = Size ];
        int err = MUL_TABLE_SIZE;
        for ( i = 0; i < MUL_TABLE_SIZE; i++ )
        {
            m_MulTable [ i ] = TL_NEW LongInt2 ( Size + 4);//, &err );
        }
        err = 0;
        if  ( m_P && !err )
        {
            memcpy ( m_P, P, Size );
            m_MulTable [ 0 ] -> LoadFromMem ( m_P, Size );
            for ( i = 1; i < MUL_TABLE_SIZE; i++ )
            {
                m_MulTable [ i ] -> Copy ( * m_MulTable [ i - 1 ] );
                (* m_MulTable [ i ]) += * m_MulTable [ 0 ];
            }
            /*
                        for  ( i = 0; i < 5; i++ )
                        {
                                printf ( "%2d = ", i );
                                m_MulTable [ i ] -> print ();
                        }*/
        }
    }
    catch(...)
    {
        for ( int i = MUL_TABLE_SIZE; i; )
        {
            delete m_MulTable [ --i ];
        }
        delete [] m_P;
        throw;
    }
}
CMyExponent2::~CMyExponent2 ()
{
    for ( int i = MUL_TABLE_SIZE; i; )
    {
        delete m_MulTable [ --i ];
    }
    delete [] m_P;
}

_qword t_mul = 0, t_rest = 0;

void CMyExponent2::Exponent ( void * A, void * X, void * Y )
{
    LongInt2 q ( m_P, m_Size );
    LongInt2 Ai ( 2 * m_Size );
    Ai.LoadFromMem ( A, m_Size );
    Ai %= q;
    const int N = m_Size * 8;
    LongInt2 Ax ( 2 * m_Size );
    Ax [ 0 ] = 1;

    //_qword t1, t2;

    static int pass = 0;
    pass++;
    gExpCount++;
    //printf("pass = %d\n", pass);

    const unsigned char * b = ( unsigned char * ) X;
    for ( int bit = 0;; )
    {
        //printf("\n\nBit = %d\n", bit);
        if  (bit == 125)
        {
            static int aa = 0;
            aa++;
        }
        if  ( ( b [ bit / 8 ] & ( 1 << ( bit % 8 ) ) ) )
        {
            {
                CMyProf prof (t_mul);
                //printf("Ax.Mul ( Ax, Ai );\n");
                Ax.Mul ( Ax, Ai );
            }
            {
                CMyProf prof (t_rest);
                //LongInt2 li ( m_Size );
                //li.CalcRestEx ( Ax, q, m_MulTable );
                gMyRestCount++;
                //printf("Ax.CalcRestEx ( Ax, q, m_MulTable );\n");
                Ax.CalcRestEx ( Ax, q, m_MulTable );
                //Ax %= q;
                /*if   ( ConstMemcmp ( li (), Ax (), m_Size ) )
               {
                    printf ( "Mismatch\n" );
               }*/
            }
        }
        if  ( ++bit == N )
        {
            break;
        }
        {
            CMyProf prof (t_mul);
            //printf("Ai.Mul ( Ai, Ai );\n");
            Ai.Mul ( Ai, Ai );
        }

        {
            CMyProf prof (t_rest);
            //LongInt2 li ( m_Size );
            //li.CalcRestEx ( Ai, q, m_MulTable );
            gMyRestCount++;
            //printf("Ai.CalcRestEx ( Ai, q, m_MulTable );\n");
            Ai.CalcRestEx ( Ai, q, m_MulTable );
            //Ai %= q;
            /*if   ( ConstMemcmp ( li (), Ai (), m_Size ) )
          {
               printf ( "Mismatch\n" );
          }*/
        }
    }

    //printf("memcpy ( Y, Ax(), m_Size );\n");
    memcpy ( Y, Ax(), m_Size );
}
