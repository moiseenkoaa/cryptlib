
// CryptLib Project

/* CryptLib library for RusRoute firewall and other projects of
 * Andrey A. Moiseenko / IE Moiseenko A.A. (Russia)
 * e-mail: support@maasoftware.ru, maa2002@mail.ru
 * web: http://maasoftware.ru, http://maasoftware.com, http://maasoft.ru, http://maasoft.org
 * Author's full name: Andrey Alekseevitch Moiseenko
 * (russian name: Моисеенко Андрей Алексеевич)
 */

// CryptLib/Gost_BS_MAA.h

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


//struct gost_ctx;
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

    _dword
#ifdef _WIN32
    //_fastcall
#endif
    //f(_dword x) const noexcept { return k87[x >> 24 & 255] | k65[x >> 16 & 255] | k43[x >> 8 & 255] | k21[x & 255]; }
    f(_dword x) const noexcept { return k21[x & 255] | k43[x >> 8 & 255] | k65[x >> 16 & 255] | k87[x >> 24 & 255]; }

    void gostcrypt(const _dword* key, _dword* d) const noexcept;
    void gostcrypt16(const _dword* key, _dword* d) const noexcept;
    void gostdecrypt(const _dword* key, _dword* d) const noexcept;
    void gost_enc(const _dword* key, _dword*, int) const noexcept;
    void gost_dec(const _dword* key, _dword*, int) const noexcept;
    //void  gost_key(gost_ctx *, u4 *);

    // High level functions
    void Encrypt(const _dword* Key, const _dword* pIn, size_t Size, const _dword* Salt, _dword* pOut, _dword* OutSalt) const noexcept;
    void Decrypt(const _dword* Key, const _dword* pIn, size_t Size, const _dword* Salt, _dword* pOut, _dword* OutSalt) const noexcept;
    void Imito(const _dword* Key, const _dword* pIn, size_t Size, _dword* ImitoValue, const _dword* Salt, const _dword* End) const noexcept;
    // 1.12x faster
    void EncryptImito(const _dword* Key, const _dword* pIn, size_t Size, const _dword* Salt, _dword* pOut, _dword* OutSalt, _dword* ImitoValue, const _dword* End) const noexcept;
    void DecryptImito(const _dword* Key, const _dword* pIn, size_t Size, const _dword* Salt, _dword* pOut, _dword* OutSalt, _dword* ImitoValue, const _dword* End) const noexcept;
};

class CGostBsMaa
{
    gost_ctx m_gc;
public:
    CGostBsMaa() noexcept;
    ~CGostBsMaa();

    // Key - 32 bytes, Salt - 8 bytes, OutSalt - 8 bytes
    void Encrypt(const void * Key, const void * InData, size_t Size, const void * Salt, void * OutData = nullptr, void *OutSalt = nullptr) const noexcept;
    void Decrypt(const void * Key, const void * InData, size_t Size, const void * Salt, void * OutData = nullptr, void *OutSalt = nullptr) const noexcept;
    void Imito(const void * Key, const void * InData, size_t Size, void * ImitoValue, const void * Salt = nullptr, const void * End = nullptr) const noexcept;
    // 1.12x faster
    void EncryptImito(const void* Key, const void* InData, size_t Size, void* ImitoValue, const void* Salt, void* OutData = nullptr, void* OutSalt = nullptr, const void* End = nullptr) const noexcept;
    void DecryptImito(const void* Key, const void* InData, size_t Size, void* ImitoValue, const void* Salt, void* OutData = nullptr, void* OutSalt = nullptr, const void* End = nullptr) const noexcept;
    void Hash(const void * Key, const void * InData, size_t Size, const void * Salt, void * Hash, int HashSize = 32) const noexcept;
    void JoinHash(const void * Key, const void * Hash1, const void * Hash2, int HashSize, const void * Salt, void * OutHash, void * OutSalt = nullptr/*not recommended for >= 2 calls*/) const noexcept;
    void GenSalt(void *OutSalt) const;
    void GenKey(void *OutKey) const;
    void GenKeyByPassword(CMaaString strPassword, void *OutKey, void * Salt = nullptr, int VariableSalt = 1) const; // -1 for using existed Salt (passed as a argument)
    CMaaString GeneratePassword(int len = 16) const;
    CMaaString EncryptByPassword(CMaaString strPassword, CMaaString Data) const;
    CMaaString DecryptByPassword(CMaaString strPassword, CMaaString Data, bool &bResult) const;
};

//extern CGostBsMaa gGostBsMaa;
extern CGostBsMaa & GetGlobal___gGostBsMaa() noexcept;
#define gGostBsMaa GetGlobal___gGostBsMaa()

/*
CGostBsMaa::Encrypt():      x1 = 91746719 B/s = 89596.40 KB/s = 87.496 MB/s = 733.974 mbits/s
CGostBsMaa_tst::Encrypt():  x2 = 71841679 B/s = 70157.89 KB/s = 68.514 MB/s = 574.733 mbits/s
x2/x1 = 0.783044, x1/x2 = 1.277068
*/
struct gost_ctx_tst;
class CGostBsMaa_tst
{
    gost_ctx_tst* m_gc;
public:
    CGostBsMaa_tst();
    ~CGostBsMaa_tst();

    // Key - 32 bytes, Salt - 8 bytes, OutSalt - 8 bytes
    void Encrypt(const void* Key, const void* InData, size_t Size, const void* Salt, void* OutData = nullptr, void* OutSalt = nullptr);
    void Decrypt(const void* Key, const void* InData, size_t Size, const void* Salt, void* OutData = nullptr, void* OutSalt = nullptr);
    void Imito(const void* Key, const void* InData, size_t Size, void* ImitoValue, const void* Salt = nullptr, const void* End = nullptr);
    /*
    void Hash(const void* Key, const void* InData, size_t Size, const void* Salt, void* Hash, int HashSize = 32);
    void JoinHash(const void* Key, const void* Hash1, const void* Hash2, int HashSize, const void* Salt, void* OutHash, void* OutSalt = nullptr);
    void GenSalt(void* OutSalt);
    void GenKey(void* OutKey);
    void GenKeyByPassword(CMaaString strPassword, void* OutKey, void* Salt = nullptr, int VariableSalt = 1); // -1 for using existed Salt (passed as a argument)
    CMaaString GeneratePassword(int len = 16);
    CMaaString EncryptByPassword(CMaaString strPassword, CMaaString Data);
    CMaaString DecryptByPassword(CMaaString strPassword, CMaaString Data, bool& bResult);
    */
};
