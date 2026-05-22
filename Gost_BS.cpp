#include "stdafx.h"
//#include <conio.h>
#include "temp.h"

void GostMain();

// GOST
// Брюс Шнайдер
// /*unsigned*/ char  k87[256],k65[256],k43[256],k21[256];

typedef  unsigned   long   u4;
typedef  unsigned  char  byte;
struct gost_ctx
{
    //u4   k[8];
    /*   Constant   s-boxes   --  set   up   in   gost_init().   */
    unsigned char  k87[256],k65[256],k43[256],k21[256];
};
/*   Note:     encrypt  and  decrypt   expect   full   blocks�padding  blocks   is
                        caller's   responsibility.      All  bulk  encryption   is  done   in
                        ECB  node by   these  calls.      Other  modes  may  be  added  easily
                        enough.
*/
void  gost_enc(gost_ctx *, u4 * key, u4 *, int);
void  gost_dec(gost_ctx *, u4 * key, u4 *, int);
//void  gost_key(gost_ctx *, u4 *);
void  gost_init(gost_ctx *);
void  gost_destroy(gost_ctx *);

#ifdef        alpha      /*  Any  other   64-bit  machines?   */
typedef  unsigned  int  word32;
#else
typedef unsigned long word32;
#endif
void kboxinit(gost_ctx  *c)
{
    int   i;
    byte k8[16] = {14,    4,   13,    1,    2,   15, 11,  8,  3, 10,  6,
        12,    5,    9,    0,    7 };
    byte k7[16] = {15,    1,    8,   14,    6,   11,  3,  4,  9,  7,  2,
        13,   12,    0,    5,   10 };
    byte k6[16] = {10,    0,    9,   14,    6,    3, 15,  5,  1, 13, 12,
        7,   11,    4,    2,    8 };
    byte k5[16] = { 7,   13,   14,    3,    0,    6,  9, 10,  1,  2,  8,
        5,   11,   12,    4,   15 };
    byte k4[16] = { 2,   12,    4,    1,    7,   10, 11,  6,  8,  5,  3,
        15,   13,    0,   14,    9 };
    byte k3[16] = {12,    1,   10,   15,    9,    2,  6,  8,  0, 13,  3,
        4,   14,    7,    5,   11 };

    byte k2[16] = { 4,   11,    2,   14,   15,    0,  8, 13,  3, 12,  9,
        7,    5,   10,          6,    1};
    byte kl[16] = {13,    2,    8,    4,    6,   15, 11,  1,  10, 9,  3,
        14,    5,    0,   12,    7};

    for (i = 0;   i   <   256;   i++)
    {
        c->k87[i]       =  k8[i >> 4] << 4 | k7[i & 15];
        c->k65[i]       =  k6[i >> 4] << 4 | k5[i & 15];
        c->k43[i]       =  k4[i >> 4] << 4 | k3[i & 15];
        c->k21[i] =  k2[i >> 4] << 4 | kl[i & 15];
    }
}

static word32
f(gost_ctx *c,word32 x)
{
    x = c->k87[x>>24 & 255] << 24 | c->k65[x>>16 & 255] << 16 |
    c->k43[x>> 8 & 255] << 8  | c->k21[x     & 255];
    /*   Rotate   left   11  bits   */
    return  x<<11 | x>>(32-11);
}

void  gostcrypt(gost_ctx *c, u4 * key, word32 *d)
{
    register  word32  n1,   n2;   /*   As   naned  in  the   GOST   */
    n1  = d[0];
    n2  = d[1];
    /* Instead of swapping halves, swap names each round */
    n2 ^= f(c,n1+key[0]);   n1   ^= f(c,n2+key[1]);
    n2 ^= f(c,n1+key[2]);   n1   ^= f(c,n2+key[3]);
    n2 ^= f(c,n1+key[4]);   n1   ^= f(c,n2+key[5]);
    n2 ^= f(c,n1+key[6]);   n1   ^= f(c,n2+key[7]);
    n2 ^= f(c,n1+key[0]);   n1   ^= f(c,n2+key[1]);
    n2 ^= f(c,n1+key[2]);   n1   ^= f(c,n2+key[3]);
    n2 ^= f(c,n1+key[4]);   n1   ^= f(c,n2+key[5]);
    n2 ^= f(c,n1+key[6]);   n1   ^= f(c,n2+key[7]);
    n2 ^= f(c,n1+key[0]);   n1   ^= f(c,n2+key[1]);
    n2 ^= f(c,n1+key[2]);   n1   ^= f(c,n2+key[3]);
    n2 ^= f(c,n1+key[4]);   n1   ^= f(c,n2+key[5]);
    n2 ^= f(c,n1+key[6]);   n1   ^= f(c,n2+key[7]);
    n2 ^= f(c,n1+key[7]);   n1   ^= f(c,n2+key[6]);
    n2 ^= f(c,n1+key[5]);   n1   ^= f(c,n2+key[4]);
    n2 ^= f(c,n1+key[3]);   n1   ^= f(c,n2+key[2]);
    n2 ^= f(c,n1+key[1]);   n1   ^= f(c,n2+key[0]);
    d[0] = n2; d[1] = n1;
}

void
gostdecrypt(gost_ctx *c, u4 * key, u4 *d)
{
    register word32   n1,   n2;   /*   As   naned in the  GOST   */
    n1   =  d[0];   n2   =  d[1];
    n2   ^=  f(c,n1+key[0]);   n1  ^=  f(c,n2+key[1]);
    n2   ^=  f(c,n1+key[2]);   n1  ^=  f(c,n2+key[3]);
    n2   ^=  f(c,n1+key[4]);   n1  ^=  f(c,n2+key[5]);
    n2   ^=  f(c,n1+key[6]);   n1  ^=  f(c,n2+key[7]);
    n2   ^=  f(c,n1+key[7]);   n1  ^=  f(c,n2+key[6]);
    n2   ^=  f(c,n1+key[5]);   n1  ^=  f(c,n2+key[4]);
    n2   ^=  f(c,n1+key[3]);   n1  ^=  f(c,n2+key[2]);
    n2   ^=  f(c,n1+key[1]);   n1  ^=  f(c,n2+key[0]);
    n2   ^=  f(c,n1+key[7]);   n1  ^=  f(c,n2+key[6]);
    n2   ^=  f(c,n1+key[5]);   n1  ^=  f(c,n2+key[4]);
    n2   ^=  f(c,n1+key[3]);   n1  ^=  f(c,n2+key[2]);
    n2   ^=  f(c,n1+key[1]);   n1  ^=  f(c,n2+key[0]);
    n2   ^=  f(c,n1+key[7]);   n1  ^=  f(c,n2+key[6]);
    n2   ^=  f(c,n1+key[5]);   n1  ^=  f(c,n2+key[4]);
    n2   ^=  f(c,n1+key[3]);   n1  ^=  f(c,n2+key[2]);
    n2   ^=  f(c,n1+key[1]);   n1  ^=  f(c,n2+key[0]);
    d[0]  =  n2;   d[1]   =   n1;
}

void gost_enc(gost_ctx *c, u4 * key, u4 *d, int blocks)
{
    int i;
    for (i=0; i < blocks; i++)
    {
        gostcrypt(c, key, d);
        d+=2;
    }
}

void gost_dec(gost_ctx  *c, u4 * key, u4 *d, int blocks)
{
    int i;
    for (i=0; i < blocks; i++)
    {
        gostdecrypt(c, key, d);
        d+=2;
    }
}

/*
void  gost_key(gost_ctx   *c,   u4   *k)
{
        int  i;
        for(i=0;i<8;i++)  c->k[i]=k[i];
}
*/

void  gost_init(gost_ctx *c)
{
    kboxinit(c);
}

void gost_destroy(gost_ctx *c)
{
    //      int i;
    //      for(i=0;i<8;i++) c->k[i]=0;
}


CGostBS::CGostBS()
{
    m_gc = new gost_ctx;
    if  (!m_gc)
    {
        throw 1;
    }
    gost_init(m_gc);
}

CGostBS::~CGostBS()
{
    gost_destroy(m_gc);
    delete m_gc;
}

// Key - 32 bytes, Salt - 8 bytes, OutSalt - 8 bytes
void CGostBS::Encrypt(const void * Key, const void * InData, size_t Size, const void * Salt, void * OutData, void *OutSalt)
{
    unsigned long n12[2] = { *(const unsigned long *)Salt, *((const unsigned long *)Salt + 1) };

    size_t i;
    for (i = 0; i < (Size >> 3); i++)
    {
        gostcrypt(m_gc, (u4 *)Key, (word32 *)n12);
        n12[0] ^= ((const unsigned long *) InData)[i * 2];
        n12[1] ^= ((const unsigned long *) InData)[i * 2 + 1];
        ((unsigned long *) OutData)[i * 2] = n12[0];
        ((unsigned long *) OutData)[i * 2 + 1] = n12[1];
    }
    if  (Size & 7)
    {
        unsigned long t[2] = {0,0};
        memcpy(t, ((const unsigned long * )InData) + i * 2, Size & 7);
        gostcrypt(m_gc, (u4 *)Key, (word32 *)n12);
        t[0] ^= n12[0];
        t[1] ^= n12[1];
        memcpy(((unsigned long *) OutData) + i * 2, &t, Size & 7);
    }
    if  (OutSalt)
    {
        *(unsigned long *)OutSalt = n12[0];
        *((unsigned long *)OutSalt + 1) = n12[1];
    }
}
// Key - 32 bytes, Salt - 8 bytes, OutSalt - 8 bytes
void CGostBS::Decrypt(const void * Key, const void * InData, size_t Size, const void * Salt, void * OutData, void *OutSalt)
{
    unsigned long n12[2] = { *(const unsigned long *)Salt, *((const unsigned long *)Salt + 1) };
    unsigned long N12[2];

    size_t i;
    for (i = 0; i < (Size >> 3); i++)
    {
        gostcrypt(m_gc, (u4 *)Key, (word32 *)n12);
        N12[0] = ((const unsigned long *)InData)[i * 2];
        N12[1] = ((const unsigned long *)InData)[i * 2 + 1];

        ((unsigned long *) OutData)[i * 2] = n12[0] ^ N12[0];
        ((unsigned long *) OutData)[i * 2 + 1] = n12[1] ^ N12[1];

        n12[0] = N12[0];
        n12[1] = N12[1];
    }
    if  (Size & 7)
    {
        unsigned long t[2] = {0,0};
        memcpy(t, ((const unsigned long * )InData) + i * 2, Size & 7);
        gostcrypt(m_gc, (u4 *)Key, (word32 *)n12);
        t[0] ^= n12[0];
        t[1] ^= n12[1];
        memcpy(((unsigned long *) OutData) + i * 2, &t, Size & 7);
    }
    if  (OutSalt)
    {
        *(unsigned long *)OutSalt = n12[0];
        *((unsigned long *)OutSalt + 1) = n12[1];
    }
}

extern "C" int CryptSection1(int x);

extern "C" int gExtData;

int gExtData = 11;

int CryptSection1(int x)
{
    return x + gExtData;
}


void GostTest()
{
    {
        HANDLE hp = GetCurrentProcess();
        //DWORD Id = GetCurrentProcessId();
        //GetCurrentProcessHandle(&hp);
        unsigned char Buffer[128];
        SIZE_T s = 0;
        unsigned char * p = (unsigned char *)&CryptSection1;
        if  (*p == 0xe9)
        {
            printf("jump\n");
            p += 5 + *(long *)(p + 1);
        }
        ReadProcessMemory(hp, p, Buffer, 128, &s);
        printf("s = %d\n", s);
        int i;
        for (i = 0; i < s; i++)
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
        printf("%d bytes written.\n", s);
        printf("CryptSection1(11) = %d\n", CryptSection1(11));
        static int aa = 0;
        aa++;
    }

    //GostMain();   return;

    return;

    CGostBS g;

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

            if  (!memcmp(data, data2, sizeof(data)))
            {
                printf("\r%d --> OK", i);
            }
            else
            {
                printf("\r%d - FAIL enc->dec\n", i);
            }

            g.Decrypt(k, data, sizeof(data), Salt, data2);
            g.Encrypt(k, data2, sizeof(data2), Salt, data2);

            if  (!memcmp(data, data2, sizeof(data)))
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


#if 0
void GostMain()
{
    gost_ctx   gc;
    u4   k[8], k2[8], data[10], data2[10];
    int   i ;
    /* Initialize GOST context. */
    gost_init (&gc);
    /* Prepare key�a simple key should be 0K, with this many rounds! */
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

void GostMain()
{
    CGostBS g;
    long k[8];
    int i;
    for (i = 0; i < 8; i++) k[i] = i;
    long Data[21], Data2[21], Data3[21];
    for (i = 0; i < 21; i++) Data[i] = i;
    long Salt[2] = {1, 2};
    long Salt2[2];
    size_t NN = 20 * sizeof(_dword);

    g.Encrypt(k, Data, NN / 2, Salt, Data2, Salt2);
    g.Encrypt(k, Data + 10, NN / 2 + 4, Salt2, Data2 + 10, NULL);
    g.Decrypt(k, Data2, NN + 4, Salt, Data3, NULL);

    for (i = 0; i < 21; i++)
    {
        printf("%02d. %08lx %08lx %08lx\n", i, Data[i], Data2[i], Data3[i]);
    }
}
