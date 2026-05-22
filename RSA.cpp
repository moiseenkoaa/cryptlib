
// CryptLib Project

/* CryptLib library for RusRoute firewall and other projects of
 * Andrey A. Moiseenko / IE Moiseenko A.A. (Russia)
 * e-mail: support@maasoftware.ru, maa2002@mail.ru
 * web: http://maasoftware.ru, http://maasoftware.com, http://maasoft.ru, http://maasoft.org
 * Author's full name: Andrey Alekseevitch Moiseenko
 * (russian name: Моисеенко Андрей Алексеевич)
 */

// CryptLib/RSA.cpp

/* Copyright (C) 2002-2024 Andrey A. Moiseenko (support@maasoftware.ru)
 * All rights reserved.
 *
 * This library contains the basic cryptography function,
 * prime numbers checks and generator, random number generator,
 * Mantgomery exponent, symmetric GOST and asymmetric RSA-like.
 * This file is RSA-like encryption/decryption implementation written
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

#include "stdafx.h"
#include "temp.h"

int RSAEncrypt(LongInt2 &n, LongInt2 &x, const void *ptr, int len, LongInt2 &Out, time_t Time)
{
    //*Out = nullptr;
    int R = n.GetRealSize();
    if  (R < 16)
    {
        return -1;
    }
    try
    {
        const int Blocks = (len + 4 + R - 9) / (R - 8);
        const int OutSize = Blocks * R;
        LongInt2 o(OutSize);

        LongInt2 PlainText(R);
        LongInt2 ChipherText(R);
        CMyExponent MyExp(n(), R);
        int BlkNum = 0;
        while(len > 0 || !BlkNum)
        {
            int b;
            if  (!BlkNum)
            {
                b = len < R - 12 ? len : R - 12;
                PlainText.LoadFromMem(ptr, b);
                memcpy(PlainText() + R - 12, &len, 4);
            }
            else
            {
                b = len < R - 8 ? len : R - 8;
                PlainText.LoadFromMem(ptr, b);
            }
            memcpy(PlainText() + R - 8, &Time, 4);
            ptr = (char *)ptr + b;
            len -= b;
            PlainText[R - 4] = (unsigned char)BlkNum;
            GetRnd(PlainText() + R - 3, 2);

            ChipherText.Zero();
            MyExp.Exponent(PlainText(), x(), ChipherText());

            if  (BlkNum * R > OutSize)
            {
                return -2;
            }
            memcpy(o() + BlkNum * R, ChipherText(), R);
            BlkNum++;
        }

        Out.Swap(o);
        return OutSize;
    }
    catch(...)
    {
    }
    return -10;
}

int RSADecrypt(LongInt2 &n, LongInt2 &x, const void *ptr, int len, LongInt2 &Out, time_t *Time)
{
    time_t tt;
    if  (!Time)
    {
        Time = &tt;
    }
    *Time = 0;
    //*Out = nullptr;
    int R = n.GetRealSize();
    if  (R < 16)
    {
        return -1;
    }
    if  ((len % R) || !len)
    {
        return -1;
    }
    try
    {
        const int Blocks = len / R;
        const int MaxOutSize = Blocks == 1 ? R - 12 : R - 12 + (Blocks - 1) * (R - 8);
        const int MinOutSize = Blocks == 1 ? 0 : R - 12 + (Blocks - 2) * (R - 8) + 1;
        int OutSize = 0;
        LongInt2 o(MaxOutSize);

        LongInt2 ChipherText(R);
        LongInt2 PlainText(R);
        CMyExponent MyExp(n(), R);
        for (int i = 0; i < Blocks; i++)
        {
            memcpy(ChipherText(), (char *)ptr + R * i, R);
            PlainText.Zero();
            MyExp.Exponent(ChipherText(), x(), PlainText());

            if  (PlainText[R - 4] != (unsigned char)i)
            {
                OutSize = -2;
                break;
            }
            if  (!i)
            {
                memcpy(&OutSize, PlainText() + R - 12, 4);
                memcpy(Time, PlainText() + R - 8, 4);
                if  (OutSize < MinOutSize || OutSize > MaxOutSize)
                {
                    OutSize = -3;
                    break;
                }
                int b = OutSize < R - 12 ? OutSize : R - 12;
                memcpy(o(), PlainText(), b);
            }
            else
            {
                int b = OutSize - (R - 12) - (R - 8) * (i - 1) < R - 8 ? OutSize - (R - 12) - (R - 8) * (i - 1) : R - 8;
                memcpy(o() + (R - 12) + (R - 8) * (i - 1), PlainText(), b);
            }
            time_t t = 0;
            memcpy(&t, PlainText() + R - 8, 4);
            if  (t != *Time)
            {
                OutSize = -4;
                break;
            }
        }

        if  (OutSize >= 0)
        {
            Out.Swap(o);
        }

        return OutSize;
    }
    catch(...)
    {
    }
    return -10;
}

/*CMaaString*/ CMaaString GetFingerprint(LongInt2 &n, LongInt2 &x)
{
    unsigned char f[16];
    memset(f, 0, sizeof(f));
    const _dword Salt[2] = {0x01234567, 0x89abcdef};
    LongInt2 nx(n.GetSize() + x.GetSize());
    memcpy(nx(), n(), n.GetSize());
    memcpy(nx() + n.GetSize(), x(), x.GetSize());
    gGostBsMaa.Hash(nullptr, nx(), nx.GetSize(), Salt, f, sizeof(f));
    nx.Zero();
    CMaaString a = Export(f, (int)sizeof(f));
    CMaaString r = a.Left(4);
    for (int i = 4; i < a.Length(); i += 4)
    {
        r += CMaaString(":") + a.Mid(i, 4);
    }
    return r;
}
