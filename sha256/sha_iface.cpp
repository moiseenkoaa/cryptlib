#include "stdafx.h"
#ifdef _WIN32
#include "..\temp.h"
#else
#include "temp.h"
#endif
//#include "sha.h"
//#include "sha-private.h"

CSHACacl::CSHACacl(SHAversion HashNo)
{
    memset(&m_ctx, '\343', sizeof(m_ctx)); // force bad data into struct
    if (HashNo != SHA1 && HashNo != SHA224 && HashNo != SHA256 && HashNo != SHA384 && HashNo != SHA512)
    {
        HashNo = SHA256;
    }
    //m_ctx.whichSha = HashNo; // SHA1, SHA224, SHA256, SHA384, SHA512
    m_err = USHAReset(&m_ctx, HashNo);
    if (m_err != shaSuccess)
    {
        CMaaString err;
        err.Format("CSHACacl::CSHACacl(): Reset Error %d", m_err);
        throw err;
    }
}
CSHACacl::~CSHACacl()
{
    memset(&m_ctx, '\343', sizeof(m_ctx)); // force bad data into struct
    m_Hash.Fill('\0');
    m_err = 0;
}
void CSHACacl::Update(const void * ptr, unsigned int Len)
{
    m_err = USHAInput(&m_ctx, (const uint8_t*)ptr, Len);
    if (m_err != shaSuccess)
    {
        CMaaString err;
        err.Format("CSHACacl::Update(): shaInput Error %d", m_err);
        throw err;
    }
}
int CSHACacl::HashSize() noexcept
{
    switch(m_ctx.whichSha)
    {
    case SHA1:
        return SHA1HashSize;   // = 20
    case SHA224:
        return SHA224HashSize; // = 28
    case SHA256:
        return SHA256HashSize; // = 32
    case SHA384:
        return SHA384HashSize; // = 48
    case SHA512:
        return SHA512HashSize; // = 64
    }
    return 0; // err
}
void CSHACacl::GetHash(void * ptr, int bits, int bitcount) // HashSize() bytes;
{
    if (bitcount > 0)
    {
        m_err = USHAFinalBits(&m_ctx, bits, bitcount);
        if (m_err != shaSuccess)
        {
            CMaaString err;
            err.Format("CSHACacl::GetHash(): USHAFinalBits Error %d", m_err);
            throw err;
        }
    }
    m_err = USHAResult(&m_ctx, (uint8_t*)ptr);
    if (m_err != shaSuccess)
    {
        CMaaString err;
        err.Format("CSHACacl::GetHash(): shaResult Error %d", m_err);
        throw err;
    }
}
CMaaString CSHACacl::GetHash(int bits, int bitcount) // HashSize() bytes string
{
    if (m_Hash.IsEmpty())
    {
        CMaaString digest(nullptr, HashSize());
        if  (digest.Length() == HashSize())
        {
            GetHash((char *)(const char *)digest, bits, bitcount);
        }
        m_Hash = digest;
    }
    return m_Hash;
}
CMaaString CSHACacl::GetTextHash(int bits, int bitcount) // 16 bytes string
{
    return GetHash(bits, bitcount).DisplayHex();
}
bool CSHACacl::ChkPassword(CMaaString password, CMaaString Hash)
{
    SHAversion HashNo;
    if (Hash.IsLeft("sha1(", 5))
    {
        HashNo = SHA1;
        Hash = Hash.RefMid(5);
    }
    else if (Hash.IsLeft("sha224(", 7))
    {
        HashNo = SHA224;
        Hash = Hash.RefMid(7);
    }
    else if (Hash.IsLeft("sha256(", 7))
    {
        HashNo = SHA256;
        Hash = Hash.RefMid(7);
    }
    else if (Hash.IsLeft("sha384(", 7))
    {
        HashNo = SHA384;
        Hash = Hash.RefMid(7);
    }
    else if (Hash.IsLeft("sha512(", 7))
    {
        HashNo = SHA512;
        Hash = Hash.RefMid(7);
    }
    else
    {
        if (Hash.Length() == 1 && Hash[0] == '\0')
        {
            return false;
        }
        return password == Hash;
    }
    int p = (warning_int)Hash.Find(',');
    if (p < 0)
    {
        return false;
    }
    bool bErr;
    CMaaString Salt = Hash.RefLeft(p).FromDisplayedHex(&bErr);
    if (bErr)
    {
        return false;
    }
    Hash = Hash.RefMid(p + 1);
    if (Hash.LastChar() != ')')
    {
        return false;
    }
    Hash = Hash.RefLeft(Hash.Length() - 1);
    Hash = Hash.FromDisplayedHex(&bErr);
    if (bErr)
    {
        return false;
    }
    CSHACacl c(HashNo);
    c.Update(Salt, (warning_int)Salt.Length());
    c.Update(password, (warning_int)password.Length());
    return Hash == c.GetHash();
}
CMaaString CSHACacl::HashPassword(CMaaString password, SHAversion HashNo)
{
    CMaaString Hash("", 1);
    const char * name = nullptr;
    switch(HashNo)
    {
    case SHA1:
        name = "sha1";
        break;
    case SHA224:
        name = "sha224";
        break;
    case SHA256:
        name = "sha256";
        break;
    case SHA384:
        name = "sha384";
        break;
    case SHA512:
        name = "sha512";
        break;
    default:
        return Hash; // err
    }
    CSHACacl c(HashNo);
    CMaaString Salt(nullptr, c.HashSize());
    if (Salt.Length() == c.HashSize())
    {
        GetRnd((void *)(const char *)Salt, (warning_int)Salt.Length());
        c.Update(Salt, (warning_int)Salt.Length());
        c.Update(password, (warning_int)password.Length());
        Salt = Salt.DisplayHex();
        CMaaString h = c.GetTextHash();
        if (Salt.Length() + h.Length() == 4 * c.HashSize())
        {
            h.Format("%s(%S,%S)", name, &Salt, &h);
            if (h.IsNotEmpty())
            {
                Hash = h;
            }
        }
    }
    return Hash;
}

#if 0
/*
 * Exercise a hash series of functions. The input is a filename.
 * If the result is known, it is in resultarray in uppercase hex.
 */
int hashfile(int hashno, const char *hashfilename, int bits,
  int bitcount, int skipSpaces, const unsigned char *keyarray,
  int keylen, const char *resultarray, int hashsize,
  int printResults, int printPassFail)
{
  USHAContext sha;
  HMACContext hmac;
  int err, nread, c;
  unsigned char buf[4096];
  uint8_t Message_Digest[USHAMaxHashSize];
  unsigned char cc;
  FILE *hashfp = (strcmp(hashfilename, "-") == 0) ? stdin :
    fopen(hashfilename, "r");

  if (!hashfp) {
    fprintf(stderr, "cannot open file '%s'\n", hashfilename);
    return shaStateError;
  }

  memset(&sha, '\343', sizeof(sha)); /* force bad data into struct */
  memset(&hmac, '\343', sizeof(hmac));
  err = keyarray ? hmacReset(&hmac, hashes[hashno].whichSha,
                             keyarray, keylen) :
                   USHAReset(&sha, hashes[hashno].whichSha);

  if (err != shaSuccess) {
    fprintf(stderr, "hashfile(): %sReset Error %d.\n",
            keyarray ? "hmac" : "sha", err);
    return err;
  }

  if (skipSpaces)
    while ((c = getc(hashfp)) != EOF) {
      if (!isspace(c)) {
        cc = (unsigned char)c;
        err = keyarray ? hmacInput(&hmac, &cc, 1) :
                         USHAInput(&sha, &cc, 1);
        if (err != shaSuccess) {
          fprintf(stderr, "hashfile(): %sInput Error %d.\n",
                  keyarray ? "hmac" : "sha", err);
          if (hashfp != stdin) fclose(hashfp);
          return err;
        }
      }
    }
  else
    while ((nread = fread(buf, 1, sizeof(buf), hashfp)) > 0) {
      err = keyarray ? hmacInput(&hmac, buf, nread) :
                       USHAInput(&sha, buf, nread);
      if (err != shaSuccess) {
        fprintf(stderr, "hashfile(): %s Error %d.\n",
                keyarray ? "hmacInput" : "shaInput", err);
        if (hashfp != stdin) fclose(hashfp);
        return err;
      }
    }

  if (bitcount > 0)
    err = keyarray ? hmacFinalBits(&hmac, bits, bitcount) :
                   USHAFinalBits(&sha, bits, bitcount);
  if (err != shaSuccess) {
    fprintf(stderr, "hashfile(): %s Error %d.\n",
            keyarray ? "hmacResult" : "shaResult", err);
    if (hashfp != stdin) fclose(hashfp);
    return err;
  }

  err = keyarray ? hmacResult(&hmac, Message_Digest) :
                   USHAResult(&sha, Message_Digest);
  if (err != shaSuccess) {
    fprintf(stderr, "hashfile(): %s Error %d.\n",
            keyarray ? "hmacResult" : "shaResult", err);
    if (hashfp != stdin) fclose(hashfp);
    return err;
  }

  printResult(Message_Digest, hashsize, hashes[hashno].name, "file",
    hashfilename, resultarray, printResults, printPassFail);

  if (hashfp != stdin) fclose(hashfp);
  return err;
}
#endif
