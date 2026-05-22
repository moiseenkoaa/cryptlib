#include "stdafx.h"
#include "Temp.h"

//#define CNtlmProxyAuth_TEST

/*
class CNtlmProxyAuth
{
protected:
     struct Type1Hdr
     {
        _byte   protocol[8];     // 'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'
        _byte   type;            // 0x01
        _byte   zero1[3];
        short   flags;           // 0xb203
        _byte   zero2[2];

        short   dom_len1;         // domain string length
        short   dom_len2;         // domain string length
        short   dom_off;         // domain string offset
        _byte   zero3[2];

        short   host_len1;        // host string length
        short   host_len2;        // host string length
        short   host_off;        // host string offset (always 0x20)
        _byte   zero4[2];

        //byte    host[*];         // host string (ASCII)
        //byte    dom[*];          // domain string (ASCII)
     };

     struct Type2Msg
     {
        _byte   protocol[8];     // 'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'
        _byte   type;            // 0x02
        _byte   zero1[7];
        short   msg_len;         // 0x28
        _byte   zero2[2];
        short   flags;           // 0x8201
        _byte   zero3[2];

        _byte   nonce[8];        // nonce
        _byte   zero4[8];
    };

    struct Type3Hdr
    {
        _byte   protocol[8];     // 'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'
        _byte   type;            // 0x03
        _byte   zero1[3];

        short   lm_resp_len1;     // LanManager response length (always 0x18)
        short   lm_resp_len2;     // LanManager response length (always 0x18)
        short   lm_resp_off;     // LanManager response offset
        _byte   zero2[2];

        short   nt_resp_len1;     // NT response length (always 0x18)
        short   nt_resp_len2;     // NT response length (always 0x18)
        short   nt_resp_off;     // NT response offset
        _byte   zero3[2];

        short   dom_len1;         // domain string length
        short   dom_len2;         // domain string length
        short   dom_off;         // domain string offset (always 0x40)
        _byte   zero4[2];

        short   user_len1;        // username string length
        short   user_len2;        // username string length
        short   user_off;        // username string offset
        _byte   zero5[2];

        short   host_len1;        // host string length
        short   host_len2;        // host string length
        short   host_off;        // host string offset
        _byte   zero6[6];

        short   msg_len;         // message length
        _byte   zero7[2];

        short   flags;           // 0x8201
        _byte   zero8[2];

        //byte    dom[*];          // domain string (unicode UTF-16LE)   // off:64
        //byte    user[*];         // username string (unicode UTF-16LE)
        //byte    host[*];         // host string (unicode UTF-16LE)
        //byte    lm_resp[*];      // LanManager response
        //byte    nt_resp[*];      // NT response
    };

     _uword htons_le(_uword x) // storing LittleEndianWord
     {
          return x;
     }

     _uword ntohs_le(_uword x) // reading LittleEndianWord
     {
          return x;
     }

     CMaaString m_HostName, m_DomainNameUp, m_DomainName, m_UserName, m_Password;
     _byte   m_Nonce[8];

public:
*/

CNtlmProxyAuth::CNtlmProxyAuth(const CMaaString &HostName, const CMaaString &DomainName, const CMaaString &UserName, const CMaaString &Password, int Type)
{
#ifndef CNtlmProxyAuth_NEW
    memset(m_Nonce, 0, sizeof(m_Nonce));
    const int n = (warning_int)HostName.Find('.');
    if  (n >= 0)
    {
        HostName = HostName.Left(n);
    }
    m_HostName = HostName.ToUpper();
    m_DomainNameUp = DomainName.ToUpper();
    m_DomainName = m_DomainNameUp;
    m_UserName = UserName;
    m_Password = Password;
#else
    m_HostName = HostName.ToUpper(e_utf8);
    m_DomainName = DomainName.ToUpper(e_utf8);
    m_UserName = UserName;
    m_Password = Password;
    m_Type = Type;
#endif
}

CNtlmProxyAuth::~CNtlmProxyAuth()
{
#ifndef CNtlmProxyAuth_NEW
    memset(m_Nonce, 0, sizeof(m_Nonce));
    m_UserName.ClearPassword();
    m_Password.ClearPassword();
#endif
}

CMaaString CNtlmProxyAuth::GetType1Message(
#ifdef CNtlmProxyAuth_TEST
     CMaaString * mm,
#endif
     bool bFullLine)
{
#ifndef CNtlmProxyAuth_NEW
    Type1Hdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    memcpy(hdr.protocol, "NTLMSSP\0", 8);
    hdr.type = 0x01;
    hdr.flags = htons_le(0xb203);
    const int x = 0x20;
    hdr.host_off = htons_le(x);
    hdr.host_len1 = hdr.host_len2 = htons_le(m_HostName.Length());
    hdr.dom_off = htons_le(x + m_HostName.Length());
    hdr.dom_len1 = hdr.dom_len2 = htons_le(m_DomainNameUp.Length());
    CMaaString Msg1 = CMaaString(&hdr, x) + m_HostName + m_DomainNameUp;
#ifdef CNtlmProxyAuth_TEST
    if  (mm)
    {
        *mm = Msg1;
    }
#endif
    Msg1 = Msg1.Base64Encode();
#else
    CMaaString Msg1 = make_type1_msg(m_DomainName, m_HostName, m_Type);
#endif
    if  (bFullLine)
    {
        Msg1 = CMaaString("Proxy-Authorization: NTLM ") + Msg1;
    }
    return Msg1;
}

bool CNtlmProxyAuth::SetType2Message(
#ifdef CNtlmProxyAuth_TEST
     CMaaString * mm,
#endif
     CMaaString Msg2, bool bFullLine, bool bStrict)
{
#ifdef CNtlmProxyAuth_TEST
    if  (mm)
    {
        mm->Empty();
    }
#endif
    if  (bFullLine)
    {
        if  (Msg2.IsLeftCi("Proxy-Authenticate: NTLM ", (int)strlen("Proxy-Authenticate: NTLM "), 0))
        {
            Msg2 = Msg2.Mid((int)strlen("Proxy-Authenticate: NTLM "));
        }
        else if (Msg2.IsLeftCi("WWW-Authenticate: NTLM ", (int)strlen("WWW-Authenticate: NTLM "), 0))
        {
            Msg2 = Msg2.Mid((int)strlen("WWW-Authenticate: NTLM "));
        }
        else
        {
            return false;
        }
    }
#ifndef CNtlmProxyAuth_NEW
    Msg2 = Msg2.RemoveSpaces();
    bool bOk = false;
    CMaaString msg = Msg2.Base64Decode(&bOk);
    if  (!bOk)
    {
        return false;
    }
#ifdef CNtlmProxyAuth_TEST
    if  (mm)
    {
        *mm = msg;
    }
#endif
    if  (msg.Length() < 0x28)// && msg.Length() != 0x38)
    {
        return false;
    }
    Type2Msg * p = (Type2Msg *)(const char *)msg;
    if (memcmp(p->protocol, "NTLMSSP\0", 8) || (ntohs_le(p->msg_len) != msg.Length()))
    //if (memcmp(p->protocol, "NTLMSSP\0", 8) || (ntohs_le(p->msg_len) > msg.Length()))
    {
        return false;
    }
    if  (bStrict)
    {
        if  (p->type != 0x02 ||
             //memcmp(p->zero1, "\0\0\0\0\0\0\0", 7) ||
             //memcmp(p->zero2, "\0\0", 2) ||
             ntohs_le(p->flags) != 0x8201 ||
             //memcmp(p->zero3, "\0\0", 2) ||
             //memcmp(p->zero4, "\0\0\0\0\0\0\0\0", 8 ||
             false
             )
        {
            return false;
        }
    }
    memcpy(m_Nonce, p->nonce, sizeof(m_Nonce));
    m_msg2 = msg;
#else
    m_Msg2 = Msg2.RemoveSpaces();
#endif
    return true;
}

CMaaString CNtlmProxyAuth::GetType3Message(
#ifdef CNtlmProxyAuth_TEST
     CMaaString * mm,
#endif
     bool bFullLine)
{
#ifndef CNtlmProxyAuth_NEW
    Type3Hdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    memcpy(hdr.protocol, "NTLMSSP\0", 8);
    hdr.type = 0x03;
    hdr.flags = htons_le(0x8201);


    /* setup LanManager password */

    const char * passw = m_Password;

    char  lm_pw[14];
    int   len = (int)strlen(passw);
    if  (len > 14)  len = 14;

    int idx;
    for (idx=0; idx<len; idx++)
    {
        lm_pw[idx] = toupper(passw[idx]);
    }
    for (; idx<14; idx++)
    {
        lm_pw[idx] = 0;
    }


    /* create LanManager hashed password */

    unsigned char magic[] = {0x4B, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25};
    unsigned char lm_hpw[21];
    des_key_schedule ks;

    setup_des_key(lm_pw, ks);
    //des_ecb_encrypt(reinterpret_cast<des_cblock>(magic), lm_hpw, ks, DES_ENCRYPT);
    des_ecb_encrypt(&magic, (des_cblock *)lm_hpw, ks, DES_ENCRYPT);

    setup_des_key(lm_pw+7, ks);
    //des_ecb_encrypt(reinterpret_cast<des_cblock>(magic), lm_hpw+8, ks, DES_ENCRYPT);
    //unsigned char * lm_hpw___ = lm_hpw+8;
    des_ecb_encrypt(&magic, (des_cblock *)(lm_hpw+8), ks, DES_ENCRYPT);

    memset(lm_hpw+16, 0, 5);


    /* create NT hashed password */

    len = (int)strlen(passw);
    //char nt_pw[2*len];
    CMaaString _nt_pw(nullptr, 2 * len);
    char * nt_pw = (char *)(const char *)_nt_pw;
    for (idx=0; idx<len; idx++)
    {
        nt_pw[2*idx] = passw[idx];
        nt_pw[2*idx+1] = 0;
    }

    unsigned char nt_hpw[21];

    /*
     MD4_CTX context;
     MD4Init(&context);
     MD4Update(&context, nt_pw, 2*len);
     MD4Final(nt_hpw, &context);
     */
    CMD4Cacl md4;
    md4.Update(nt_pw, 2*len);
    md4.GetHash(nt_hpw);

    memset(nt_hpw+16, 0, 5);


    /* create responses */

    unsigned char lm_resp[24], nt_resp[24];
    calc_resp(lm_hpw, m_Nonce, lm_resp);
    calc_resp(nt_hpw, m_Nonce, nt_resp);

    CMaaString Domain;
    {
        CMaaPtr<WCHAR> Buffer(100 + 4 * m_DomainName.Length());
        int n = MultiByteToWideChar(CP_ACP, 0, (LPCSTR)(const char *)m_DomainName, (warning_int)m_DomainName.Length(), Buffer, (warning_int)Buffer.MaxIndex());
        Domain = CMaaString(Buffer, (n >= 0 ? n : 0) * sizeof(WCHAR));
    }
    CMaaString User;
    {
        CMaaPtr<WCHAR> Buffer(100 + 4 * m_UserName.Length());
        int n = MultiByteToWideChar(CP_ACP, 0, (LPCSTR)(const char *)m_UserName, (warning_int)m_UserName.Length(), Buffer, (warning_int)Buffer.MaxIndex());
        User = CMaaString(Buffer, (n >= 0 ? n : 0) * sizeof(WCHAR));
    }
    CMaaString Host;
    {
        CMaaPtr<WCHAR> Buffer(100 + 4 * m_HostName.Length());
        int n = MultiByteToWideChar(CP_ACP, 0, (LPCSTR)(const char *)m_HostName, (warning_int)m_HostName.Length(), Buffer, (warning_int)Buffer.MaxIndex());
        Host = CMaaString(Buffer, (n >= 0 ? n : 0) * sizeof(WCHAR));
    }
    int hdrlen;
    int x;
    x = hdrlen = 64;
    hdr.dom_off = htons_le(x);
    hdr.dom_len1 = hdr.dom_len2 = htons_le((warning_int)Domain.Length());
    x += (warning_int)Domain.Length();

    hdr.user_off = htons_le(x);
    hdr.user_len1 = hdr.user_len2 = htons_le((warning_int)User.Length());
    x += (warning_int)User.Length();

    hdr.host_off = htons_le(x);
    hdr.host_len1 = hdr.host_len2 = htons_le((warning_int)Host.Length());
    x += (warning_int)Host.Length();

    hdr.lm_resp_off = htons_le(x);
    hdr.lm_resp_len1 = hdr.lm_resp_len2 = htons_le(24);
    x += 24;

    hdr.nt_resp_off = htons_le(x);
    hdr.nt_resp_len1 = hdr.nt_resp_len2 = htons_le(24);
    x += 24;

    hdr.msg_len = htons_le(x);

    CMaaString Msg3 = CMaaString(&hdr, hdrlen) + Domain + User + Host + CMaaString(lm_resp, 24) + CMaaString(nt_resp, 24);

#ifdef CNtlmProxyAuth_TEST
    if  (mm)
    {
        *mm = Msg3;
    }
#endif

    Msg3 = Msg3.Base64Encode();
#else
    CMaaString Msg3 = make_type3_msg(m_UserName, m_Password, m_DomainName, m_HostName, m_Msg2, m_Type);
#endif
    if  (bFullLine)
    {
        //Msg1 = CMaaString("Authorization: NTLM ") + Msg3;
        Msg3 = CMaaString("Proxy-Authorization: NTLM ") + Msg3;
    }
    return Msg3;
}

#ifndef CNtlmProxyAuth_NEW
void CNtlmProxyAuth::calc_resp(unsigned char *keys, unsigned char *plaintext, unsigned char *results)
{
    /*
     * takes a 21 byte array and treats it as 3 56-bit DES keys. The
     * 8 byte plaintext is encrypted with each key and the resulting 24
     * bytes are stored in the results array.
     */
    des_key_schedule ks;

    setup_des_key(keys, ks);
    des_ecb_encrypt((des_cblock*) plaintext, (des_cblock*) results, ks, DES_ENCRYPT);

    setup_des_key(keys+7, ks);
    des_ecb_encrypt((des_cblock*) plaintext, (des_cblock*) (results+8), ks, DES_ENCRYPT);

    setup_des_key(keys+14, ks);
    des_ecb_encrypt((des_cblock*) plaintext, (des_cblock*) (results+16), ks, DES_ENCRYPT);
}

void CNtlmProxyAuth::setup_des_key(void * key_56_, des_key_schedule ks) noexcept
{
    unsigned char * key_56 = (unsigned char *)key_56_;
    /*
     * turns a 56 bit key into the 64 bit, odd parity key and sets the key.
     * The key schedule ks is also set.
     */
    des_cblock key;

    key[0] = key_56[0];
    key[1] = ((key_56[0] << 7) & 0xFF) | (key_56[1] >> 1);
    key[2] = ((key_56[1] << 6) & 0xFF) | (key_56[2] >> 2);
    key[3] = ((key_56[2] << 5) & 0xFF) | (key_56[3] >> 3);
    key[4] = ((key_56[3] << 4) & 0xFF) | (key_56[4] >> 4);
    key[5] = ((key_56[4] << 3) & 0xFF) | (key_56[5] >> 5);
    key[6] = ((key_56[5] << 2) & 0xFF) | (key_56[6] >> 6);
    key[7] =  (key_56[6] << 1) & 0xFF;

    des_set_odd_parity(&key);
    des_set_key(&key, ks);
}
#endif

#ifndef CNtlmProxyAuth_NEW
CNtlmv2ProxyAuth::CNtlmv2ProxyAuth(const CMaaString &HostName, const CMaaString &DomainName, const CMaaString &UserName, const CMaaString &Password)
:   CNtlmProxyAuth(HostName, DomainName, UserName, Password)
{
}

CNtlmv2ProxyAuth::~CNtlmv2ProxyAuth()
{
}

#ifndef CNtlmProxyAuth_NEW
/**
* Calculates the LM Response for the given challenge, using the specified
* password.
*
* @param password The user's password.
* @param challenge The Type 2 challenge from the server.
*
* @return The LM Response.
*/
CMaaString CNtlmv2ProxyAuth::getLMResponse(CMaaString password, CMaaString challenge)
{
    CMaaString _lmHash = lmHash(password);
    return lmResponse(_lmHash, challenge);
}

/**
* Calculates the NTLM Response for the given challenge, using the
* specified password.
*
* @param password The user's password.
* @param challenge The Type 2 challenge from the server.
*
* @return The NTLM Response.
*/
CMaaString CNtlmv2ProxyAuth::getNTLMResponse(CMaaString password, CMaaString challenge)
{
    CMaaString _ntlmHash = ntlmHash(password);
    return lmResponse(_ntlmHash, challenge);
}

/**
* Calculates the NTLMv2 Response for the given challenge, using the
* specified authentication target, username, password, target information
* block, and client nonce.
*
* @param target The authentication target (i.e., domain).
* @param user The username.
* @param password The user's password.
* @param targetInformation The target information block from the Type 2
* message.
* @param challenge The Type 2 challenge from the server.
* @param clientNonce The random 8-byte client nonce.
*
* @return The NTLMv2 Response.
*/
CMaaString CNtlmv2ProxyAuth::getNTLMv2Response(CMaaString target, CMaaString user,
     CMaaString password, CMaaString targetInformation, CMaaString challenge,
     CMaaString clientNonce)
{
    CMaaString _ntlmv2Hash = ntlmv2Hash(target, user, password);
    CMaaString blob = createBlob(targetInformation, clientNonce);
    return lmv2Response(_ntlmv2Hash, blob, challenge);
}

/**
* Calculates the LMv2 Response for the given challenge, using the
* specified authentication target, username, password, and client
* challenge.
*
* @param target The authentication target (i.e., domain).
* @param user The username.
* @param password The user's password.
* @param challenge The Type 2 challenge from the server.
* @param clientNonce The random 8-byte client nonce.
*
* @return The LMv2 Response.
*/
CMaaString CNtlmv2ProxyAuth::getLMv2Response(CMaaString target, CMaaString user,
     CMaaString password, CMaaString challenge, CMaaString clientNonce)
{
    CMaaString _ntlmv2Hash = ntlmv2Hash(target, user, password);
    return lmv2Response(_ntlmv2Hash, clientNonce, challenge);
}

/**
* Calculates the NTLM2 Session Response for the given challenge, using the
* specified password and client nonce.
*
* @param password The user's password.
* @param challenge The Type 2 challenge from the server.
* @param clientNonce The random 8-byte client nonce.
*
* @return The NTLM2 Session Response.  This is placed in the NTLM
* response field of the Type 3 message; the LM response field contains
* the client nonce, null-padded to 24 bytes.
*/
CMaaString CNtlmv2ProxyAuth::getNTLM2SessionResponse(CMaaString password,
     CMaaString challenge, CMaaString clientNonce)
{
    CMaaString _ntlmHash = ntlmHash(password);

    // MessageDigest md5 = MessageDigest.getInstance("MD5");
    // md5.update(challenge);
    // md5.update(clientNonce);
    CMD4Cacl md5;
    md5.Update(challenge, (warning_int)challenge.Length());
    md5.Update(clientNonce, (warning_int)clientNonce.Length());
    CMaaString digest = md5.GetHash();
    CMaaString sessionHash(nullptr, 8);
    sessionHash.Fill();
    sessionHash.Copy(0, digest, 0, 8);
    return lmResponse(_ntlmHash, sessionHash);
}

/**
* Creates the LM Hash of the user's password.
*
* @param password The password.
*
* @return The LM Hash of the given password, used in the calculation
* of the LM Response.
*/
CMaaString CNtlmv2ProxyAuth::lmHash(CMaaString password)
{
    //CMaaString oemPassword = password.toUpperCase().getBytes("US-ASCII");
    CMaaString oemPassword = password.ToUpper();//.toUpperCase().getBytes("US-ASCII");
    int length = oemPassword.Length() <= 14 ? (warning_int)oemPassword.Length() : 14;
    //byte[] keyBytes = TL_NEW byte[14];
    char keyBytes[14];
    //CMaaString keyBytes(nullptr, 14);
    //keyBytes.Fill();
    //System.arraycopy(oemPassword, 0, keyBytes, 0, length);
    //keyBytes.Copy(0, oemPassword, 0, length);
    memset(keyBytes, 0, sizeof(keyBytes));
    memcpy(keyBytes, oemPassword, length);

    /*
     Key lowKey = createDESKey(keyBytes, 0);
     Key highKey = createDESKey(keyBytes, 7);
     byte[] magicConstant = "KGS!@#$%".getBytes("US-ASCII");
     Cipher des = Cipher.getInstance("DES/ECB/NoPadding");
     des.init(Cipher.ENCRYPT_MODE, lowKey);
     byte[] lowHash = des.doFinal(magicConstant);
     des.init(Cipher.ENCRYPT_MODE, highKey);
     byte[] highHash = des.doFinal(magicConstant);
     */

    unsigned char magicConstant[] = {0x4B, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25};
    //char lm_pw[14];
    //unsigned char lm_hpw[21];

    char _lmHash[16];
    memset(_lmHash, 0, sizeof(_lmHash));

    des_key_schedule ks;

    setup_des_key(&keyBytes[0], ks);
    des_ecb_encrypt(&magicConstant, (des_cblock *)_lmHash/*lm_hpw*/, ks, DES_ENCRYPT);

    setup_des_key(&keyBytes[7], ks);
    des_ecb_encrypt(&magicConstant, (des_cblock *)(_lmHash+8/*lm_hpw+8*/), ks, DES_ENCRYPT);

    return CMaaString(_lmHash, 16);
}

/**
* Creates the NTLM Hash of the user's password.
*
* @param password The password.
*
* @return The NTLM Hash of the given password, used in the calculation
* of the NTLM Response and the NTLMv2 and LMv2 Hashes.
*/
CMaaString CNtlmv2ProxyAuth::ntlmHash(CMaaString password)
{
    CMaaString nt_pw = password.UnicodeLittleUnmarked();

    //unsigned char nt_hpw[21];

    CMD4Cacl md4;
    md4.Update(nt_pw, (warning_int)nt_pw.Length());
    //md4.GetHash(digest);//nt_hpw);

    //memset(nt_hpw+16, 0, 5);

    //byte[] unicodePassword = password.getBytes("UnicodeLittleUnmarked");
    //MessageDigest md4 = MessageDigest.getInstance("MD4");
    //return md4.digest(unicodePassword);
    //return CMaaString(digest, 16);
    return md4.GetHash(); // 16 bytes string
}
/**
* Creates the NTLMv2 Hash of the user's password.
*
* @param target The authentication target (i.e., domain).
* @param user The username.
* @param password The password.
*
* @return The NTLMv2 Hash, used in the calculation of the NTLMv2
* and LMv2 Responses.
*/
CMaaString CNtlmv2ProxyAuth::ntlmv2Hash(CMaaString target, CMaaString user, CMaaString password)
{
    CMaaString _ntlmHash = ntlmHash(password);
    CMaaString identity = user.ToUpper() + target;
    return hmacMD5(identity.UnicodeLittleUnmarked(), _ntlmHash);
}

/**
* Creates the LM Response from the given hash and Type 2 challenge.
*
* @param hash The LM or NTLM Hash.
* @param challenge The server challenge from the Type 2 message.
*
* @return The response (either LM or NTLM, depending on the provided
* hash).
*/
CMaaString CNtlmv2ProxyAuth::lmResponse(CMaaString hash, CMaaString challenge)
{
    // challenge.Length()
    if  (challenge.Length() != 8)
    {
        static int aa = 0;
        aa++;
        Error(2);
        return "";
    }

    char keyBytes[21];
    memset(keyBytes, 0, sizeof(keyBytes));
    //System.arraycopy(hash, 0, keyBytes, 0, 16);
    //keyBytes.Copy(hash, 0, 0, 16);
    memcpy(keyBytes, hash, hash.Length() >= 16 ? 16 : /*error*/hash.Length());

    /*
     Key lowKey = createDESKey(keyBytes, 0);
     Key middleKey = createDESKey(keyBytes, 7);
     Key highKey = createDESKey(keyBytes, 14);
     Cipher des = Cipher.getInstance("DES/ECB/NoPadding");
     des.init(Cipher.ENCRYPT_MODE, lowKey);
     byte[] lowResponse = des.doFinal(challenge);
     des.init(Cipher.ENCRYPT_MODE, middleKey);
     byte[] middleResponse = des.doFinal(challenge);
     des.init(Cipher.ENCRYPT_MODE, highKey);
     byte[] highResponse = des.doFinal(challenge);
     byte[] lmResponse = TL_NEW byte[24];
     System.arraycopy(lowResponse, 0, lmResponse, 0, 8);
     System.arraycopy(middleResponse, 0, lmResponse, 8, 8);
     System.arraycopy(highResponse, 0, lmResponse, 16, 8);
     */
    char _lmResponse[24];
    des_key_schedule ks;
    setup_des_key(&keyBytes[0], ks);
    des_ecb_encrypt((des_cblock *)(const char *)challenge, (des_cblock *)_lmResponse, ks, DES_ENCRYPT);
    setup_des_key(&keyBytes[7], ks);
    des_ecb_encrypt((des_cblock *)(const char *)challenge, (des_cblock *)(_lmResponse + 8), ks, DES_ENCRYPT);
    setup_des_key(&keyBytes[14], ks);
    des_ecb_encrypt((des_cblock *)(const char *)challenge, (des_cblock *)(_lmResponse + 16), ks, DES_ENCRYPT);

    return CMaaString(_lmResponse, 24);
}

/**
* Creates the LMv2 Response from the given hash, client data, and
* Type 2 challenge.
*
* @param hash The NTLMv2 Hash.
* @param clientData The client data (blob or client nonce).
* @param challenge The server challenge from the Type 2 message.
*
* @return The response (either NTLMv2 or LMv2, depending on the
* client data).
*/
CMaaString CNtlmv2ProxyAuth::lmv2Response(CMaaString hash, CMaaString clientData, CMaaString challenge)
{
    CMaaString data = challenge + clientData;
    CMaaString mac = hmacMD5(data, hash);
    CMaaString _lmv2Response = mac + clientData;
    /*
          = TL_NEW byte[mac.length + clientData.length];
     System.arraycopy(mac, 0, lmv2Response, 0, mac.length);
     System.arraycopy(clientData, 0, lmv2Response, mac.length, clientData.length);
     */
    return _lmv2Response;
}

/**
* Creates the NTLMv2 blob from the given target information block and
* client nonce.
*
* @param targetInformation The target information block from the Type 2
* message.
* @param clientNonce The random 8-byte client nonce.
*
* @return The blob, used in the calculation of the NTLMv2 Response.
*/
CMaaString CNtlmv2ProxyAuth::createBlob(CMaaString targetInformation, CMaaString clientNonce)
{
    _byte blobSignature[4] = {0x01, 0x01, 0x00, 0x00};
    _byte reserved[4] = {0x00, 0x00, 0x00, 0x00};
    _byte unknown1[4] = {0x00, 0x00, 0x00, 0x00};
    _byte unknown2[4] = {0x00, 0x00, 0x00, 0x00};
    _qword _time; // tenths of a microsecond since January 1, 1601
#ifdef _WIN32
    SYSTEMTIME _SystemTime;
    FILETIME _FileTime;
    /*void*/ GetSystemTime(&_SystemTime);
    /*BOOL*/ SystemTimeToFileTime(&_SystemTime, &_FileTime);
    _time = ((_qword)_FileTime.dwHighDateTime) << 32 | (_qword)_FileTime.dwLowDateTime;
#else
    timeval tv;
    gettimeofday(&tv, nullptr);
    _time = (_qword)tv.tv_sec * 1000000LL + (_qword)tv.tv_usec;
    _time += 11644473600000l000LL; // microseconds from January 1, 1601 -> epoch.
    _time *= 10; // tenths of a microsecond.
#endif
    // convert to little-endian byte array.
    CMaaString _timestamp(nullptr, 8);
    for (int i = 0; i < 8; i++)
    {
        _timestamp[i] = (char)(_time & 0xff);
        _time >>= 8;
    }

    CMaaString blob =
    CMaaString(blobSignature, (int)sizeof(blobSignature)) +
    CMaaString(reserved, (int)sizeof(reserved)) +
    _timestamp +
    clientNonce +
    CMaaString(unknown1, (int)sizeof(unknown1)) +
    targetInformation +
    CMaaString(unknown2, (int)sizeof(unknown2));
    return blob;
}

/**
* Calculates the HMAC-MD5 hash of the given data using the specified
* hashing key.
*
* @param data The data for which the hash will be calculated.
* @param key The hashing key.
*
* @return The HMAC-MD5 hash of the given data.
*/
CMaaString CNtlmv2ProxyAuth::hmacMD5(CMaaString data, CMaaString key)
{
    CMaaString ipad(nullptr, 64);
    CMaaString opad(nullptr, 64);
    ipad.Fill(0x36);
    opad.Fill(0x5c);
    for (int i = (warning_int)key.Length() - 1; i >= 0; i--)
    {
        ipad[i] = ipad[i] ^ key[i];
        opad[i] = opad[i] ^ key[i];
    }
    CMaaString content = ipad + data;
    CMD5Cacl md5;
    md5.Update(content, (warning_int)content.Length());
    data = md5.GetHash();

    content = opad + data;
    CMD5Cacl md5_;
    md5_.Update(content, (warning_int)content.Length());
    return md5_.GetHash();
}

void CNtlmv2ProxyAuth::Error(int n)
{
    static int aa = 0;
    aa++;
    throw n;
}
#endif

#if 0
import java.security.Key;
import java.security.MessageDigest;

import javax.crypto.Cipher;

import javax.crypto.spec.SecretKeySpec;

/**
 * Calculates the various Type 3 responses.
 */
public class Responses
{


    /**
     * Creates a DES encryption key from the given key material.
     *
     * @param bytes A byte array containing the DES key material.
     * @param offset The offset in the given byte array at which
     * the 7-byte key material starts.
     *
     * @return A DES encryption key created from the key material
     * starting at the specified offset in the given byte array.
     */
private static Key createDESKey(byte[] bytes, int offset) {
        byte[] keyBytes = TL_NEW byte[7];
        System.arraycopy(bytes, offset, keyBytes, 0, 7);
        byte[] material = TL_NEW byte[8];
        material[0] = keyBytes[0];
        material[1] = (byte) (keyBytes[0] << 7 | (keyBytes[1] & 0xff) >>> 1);
        material[2] = (byte) (keyBytes[1] << 6 | (keyBytes[2] & 0xff) >>> 2);
        material[3] = (byte) (keyBytes[2] << 5 | (keyBytes[3] & 0xff) >>> 3);
        material[4] = (byte) (keyBytes[3] << 4 | (keyBytes[4] & 0xff) >>> 4);
        material[5] = (byte) (keyBytes[4] << 3 | (keyBytes[5] & 0xff) >>> 5);
        material[6] = (byte) (keyBytes[5] << 2 | (keyBytes[6] & 0xff) >>> 6);
        material[7] = (byte) (keyBytes[6] << 1);
        oddParity(material);
        return TL_NEW SecretKeySpec(material, "DES");
    }

    /**
     * Applies odd parity to the given byte array.
     *
     * @param bytes The data whose parity bits are to be adjusted for
     * odd parity.
     */
private static void oddParity(byte[] bytes) {
        for (int i = 0; i < bytes.length; i++) {
            byte b = bytes[i];
            boolean needsParity = (((b >>> 7) ^ (b >>> 6) ^ (b >>> 5) ^
                 (b >>> 4) ^ (b >>> 3) ^ (b >>> 2) ^
                 (b >>> 1)) & 0x01) == 0;
            if  (needsParity) {
                bytes[i] |= (byte) 0x01;
            } else {
                bytes[i] &= (byte) 0xfe;
            }
        }
    }

}
#endif

bool CNtlmv2ProxyAuth::SetType2Message(
#ifdef CNtlmProxyAuth_TEST
     CMaaString * mm,
#endif
     CMaaString Msg2, bool bFullLine, bool bStrict)
{
#ifdef CNtlmProxyAuth_TEST
    if  (mm)
    {
        mm->Empty();
    }
#endif
    if  (!CNtlmProxyAuth::SetType2Message(
#ifdef CNtlmProxyAuth_TEST
         mm,
#endif
         Msg2, bFullLine, bStrict))
    {
        return false;
    }
    return true;
}

CMaaString CNtlmv2ProxyAuth::GetType3Message(
#ifdef CNtlmProxyAuth_TEST
     CMaaString * mm,
#endif
     bool bFullLine)
{
#ifndef CNtlmProxyAuth_NEW
    CMaaString _NTLMv2Response;
    CMaaString _LMv2Response;
    if  (m_msg2.Length() >= sizeof(Type2Msg))
    {
        Type2Msg * p = (Type2Msg *)(const char *)m_msg2;
        if  ((p->zero3[0] & 0x80) || 0)
        {
            CMaaString TargetInformation = m_msg2.Mid(40);
            if  (TargetInformation.Length() >= 8)
            {
                const char * ptr = TargetInformation;
                int len = htons_le(*(short *)(ptr + 2));
                int off = htons_le(*(short *)(ptr + 4));
                off -= 40;
                if  (off >= 8 && len >= 0 && off + len <= TargetInformation.Length())
                {
                    TargetInformation = TargetInformation.Mid(off, len);
                    CMaaString clientNonce(nullptr, 8);
                    GetRnd((char *)(const char *)clientNonce, 8);
                    CMaaString challenge(m_Nonce, 8);
                    try
                    {
                        _NTLMv2Response = getNTLMv2Response(m_DomainNameUp, m_UserName, m_Password, TargetInformation, challenge, clientNonce);
                        _LMv2Response = getLMv2Response(m_DomainNameUp, m_UserName, m_Password, challenge, clientNonce);
                    }
                    catch(int)
                    {
                        _NTLMv2Response.Empty();
                        _LMv2Response.Empty();
                    }
                }
            }
        }
    }

    Type3Hdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    memcpy(hdr.protocol, "NTLMSSP\0", 8);
    hdr.type = 0x03;
    hdr.flags = htons_le(0x8201);


    /* setup LanManager password */

    const char * passw = m_Password;

    char  lm_pw[14];
    int   len = (int)strlen(passw);
    if  (len > 14)  len = 14;

    int idx;
    for (idx=0; idx<len; idx++)
    {
        lm_pw[idx] = toupper(passw[idx]);
    }
    for (; idx<14; idx++)
    {
        lm_pw[idx] = 0;
    }


    /* create LanManager hashed password */

    unsigned char magic[] = {0x4B, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25};
    unsigned char lm_hpw[21];
    des_key_schedule ks;

    setup_des_key(lm_pw, ks);
    //des_ecb_encrypt(reinterpret_cast<des_cblock>(magic), lm_hpw, ks, DES_ENCRYPT);
    des_ecb_encrypt(&magic, (des_cblock *)lm_hpw, ks, DES_ENCRYPT);

    setup_des_key(lm_pw+7, ks);
    //des_ecb_encrypt(reinterpret_cast<des_cblock>(magic), lm_hpw+8, ks, DES_ENCRYPT);
    //unsigned char * lm_hpw___ = lm_hpw+8;
    des_ecb_encrypt(&magic, (des_cblock *)(lm_hpw+8), ks, DES_ENCRYPT);

    memset(lm_hpw+16, 0, 5);


    /* create NT hashed password */

    len = (int)strlen(passw);
    //char nt_pw[2*len];
    CMaaString _nt_pw(nullptr, 2 * len);
    char * nt_pw = (char *)(const char *)_nt_pw;
    for (idx=0; idx<len; idx++)
    {
        nt_pw[2*idx] = passw[idx];
        nt_pw[2*idx+1] = 0;
    }

    unsigned char nt_hpw[21];

    /*
     MD4_CTX context;
     MD4Init(&context);
     MD4Update(&context, nt_pw, 2*len);
     MD4Final(nt_hpw, &context);
     */
    CMD4Cacl md4;
    md4.Update(nt_pw, 2*len);
    md4.GetHash(nt_hpw);

    memset(nt_hpw+16, 0, 5);


    /* create responses */

    unsigned char lm_resp[24], nt_resp[24];
    calc_resp(lm_hpw, m_Nonce, lm_resp);
    calc_resp(nt_hpw, m_Nonce, nt_resp);

    CMaaString Domain;
    {
        CMaaPtr<WCHAR> Buffer(100 + 4 * m_DomainName.Length());
        int n = MultiByteToWideChar(CP_ACP, 0, (LPCSTR)(const char *)m_DomainName, (warning_int)m_DomainName.Length(), Buffer, (warning_int)Buffer.MaxIndex());
        Domain = CMaaString(Buffer, (n >= 0 ? n : 0) * sizeof(WCHAR));
    }
    CMaaString User;
    {
        CMaaPtr<WCHAR> Buffer(100 + 4 * m_UserName.Length());
        int n = MultiByteToWideChar(CP_ACP, 0, (LPCSTR)(const char *)m_UserName, (warning_int)m_UserName.Length(), Buffer, (warning_int)Buffer.MaxIndex());
        User = CMaaString(Buffer, (n >= 0 ? n : 0) * sizeof(WCHAR));
    }
    CMaaString Host;
    {
        CMaaPtr<WCHAR> Buffer(100 + 4 * m_HostName.Length());
        int n = MultiByteToWideChar(CP_ACP, 0, (LPCSTR)(const char *)m_HostName, (warning_int)m_HostName.Length(), Buffer, (warning_int)Buffer.MaxIndex());
        Host = CMaaString(Buffer, (n >= 0 ? n : 0) * sizeof(WCHAR));
    }
    int hdrlen;
    int x;
    x = hdrlen = 64;
    hdr.dom_off = htons_le(x);
    hdr.dom_len1 = hdr.dom_len2 = htons_le((warning_int)Domain.Length());
    x += (warning_int)Domain.Length();

    hdr.user_off = htons_le(x);
    hdr.user_len1 = hdr.user_len2 = htons_le((warning_int)User.Length());
    x += (warning_int)User.Length();

    hdr.host_off = htons_le(x);
    hdr.host_len1 = hdr.host_len2 = htons_le((warning_int)Host.Length());
    x += (warning_int)Host.Length();

    hdr.lm_resp_off = htons_le(x);
    if  (_NTLMv2Response.IsNotEmpty() && _LMv2Response.IsNotEmpty())
    {
        hdr.lm_resp_len1 = hdr.lm_resp_len2 = htons_le((warning_int)_LMv2Response.Length());
        x += (warning_int)_LMv2Response.Length();
    }
    else
    {
        hdr.lm_resp_len1 = hdr.lm_resp_len2 = htons_le(24);
        x += 24;
    }

    hdr.nt_resp_off = htons_le(x);
    if  (_NTLMv2Response.IsNotEmpty() && _LMv2Response.IsNotEmpty())
    {
        hdr.nt_resp_len1 = hdr.nt_resp_len2 = htons_le((warning_int)_NTLMv2Response.Length());
        x += (warning_int)_NTLMv2Response.Length();
    }
    else
    {
        hdr.nt_resp_len1 = hdr.nt_resp_len2 = htons_le(24);
        x += 24;
    }

    hdr.msg_len = htons_le(x);

    CMaaString Msg3 = CMaaString(&hdr, hdrlen) + Domain + User + Host;
    if  (_NTLMv2Response.IsNotEmpty() && _LMv2Response.IsNotEmpty())
    {
        Msg3 += _LMv2Response + _NTLMv2Response;
    }
    else
    {
        Msg3 += CMaaString(lm_resp, 24) + CMaaString(nt_resp, 24);
    }

#ifdef CNtlmProxyAuth_TEST
    if  (mm)
    {
        *mm = Msg3;
    }
#endif

    Msg3 = Msg3.Base64Encode();
#else
    CMaaString Msg3 = make_type3_msg(m_UserName, m_Password, m_DomainName, m_HostName, m_Msg2, USE_NTLM2SESSION);
#endif
    if  (bFullLine)
    {
        //Msg1 = CMaaString("Authorization: NTLM ") + Msg3;
        Msg3 = CMaaString("Proxy-Authorization: NTLM ") + Msg3;
    }
    return Msg3;
}

#ifdef CNtlmProxyAuth_NEW
CMaaString CNtlmv2ProxyAuth::GetType1Message(
#ifdef CNtlmProxyAuth_TEST
    CMaaString* mm,
#endif
    bool bFullLine)
{
    CMaaString Msg1 = make_type1_msg(m_DomainName, m_HostName, USE_NTLM2SESSION);
    if (bFullLine)
    {
        Msg1 = CMaaString("Proxy-Authorization: NTLM ") + Msg1;
    }
    return Msg1;
}
#endif
#endif

#if 0
//tests

#if 0
try
{
    const char * msgs[] =
    {
        "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",
        nullptr,
        "TlRMTVNTUAABAAAAl4II4gAAAAAAAAAAAAAAAAAAAAAGAbwbAAAADw==",
        "TlRMTVNTUAACAAAACAAIADgAAAAVgoni7QFnWx7XlLUAAAAAAAAAAI4AjgBAAAAABQLODgAAAA9TAFQAQQBSAAIACABTAFQAQQBSAAEADgBTAEEAUABQAEgASQBSAAQAHgBzAHQAYQByAC4AcwBpAHIAbwBkAGUAbAAuAHIAdQADAC4AcwBhAHAAcABoAGkAcgAuAHMAdABhAHIALgBzAGkAcgBvAGQAZQBsAC4AcgB1AAUAFABzAGkAcgBvAGQAZQBsAC4AcgB1AAAAAAA=",
        "TlRMTVNTUAADAAAAGAAYAIQAAAA4ATgBnAAAAA4ADgBYAAAAEAAQAGYAAAAOAA4AdgAAABAAEADUAQAAFYKI4gYBvBsAAAAPpCFlXkhUGY6UUpVL7dMPklMASQBSAE8ARABFAEwAYQAuAGcAYQBsAGsAaQBuAFMAQwAwADAANAAwADcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEb5w96fYgYp4BMd7gzradAEBAAAAAAAAmFhbGCwBygFREzILvDyB5AAAAAACAAgAUwBUAEEAUgABAA4AUwBBAFAAUABIAEkAUgAEAB4AcwB0AGEAcgAuAHMAaQByAG8AZABlAGwALgByAHUAAwAuAHMAYQBwAHAAaABpAHIALgBzAHQAYQByAC4AcwBpAHIAbwBkAGUAbAAuAHIAdQAFABQAcwBpAHIAbwBkAGUAbAAuAHIAdQAIADAAMAAAAAAAAAABAAAAABAAAB1mQsoFMnPJhhV27HtrhlGic1H8mqbzdaEUoJSLeostCgAQAAAAAAAAAAAAAAAAAAAAAAAJAC4ASABUAFQAUAAvAHMAYQBwAHAAaABpAHIALgBzAGkAcgBvAGQAZQBsAC4AcgB1AAAAAAAAAAAAK1yFPgtE+Hk4Hmnuoa1l1A==",
        nullptr
    };

    for (int i = 0; msgs[i]; i++)
    {
        CMaaString txt = msgs[i];//"TlRMTVNTUAABAAAAB7IIogcABwAuAAAABgAGACgAAAAFASgKAAAAD1NDMDA0MVNJUk9ERUw=";
        bool bOk = false;
        CMaaString txt2 = txt.Base64Decode(&bOk);
        char fn1[MAX_PATH], fn2[MAX_PATH];
        sprintf(fn1, "c:\\1\\xx_%d.txt", i + 1);
        sprintf(fn2, "c:\\1\\xx_%d_dump.txt", i + 1);

        CMaaFile f(fn1, CMaaFile::eWC);
        f.Write(txt2);
        f.Close();

        f = CMaaFile(fn2, CMaaFile::eWC);
        f.Write(CMaaString::sFormat("%s%m", !bOk ? "false\r\n" : "", (const char *)txt2, txt2.Length()));
        f.Close();
    }
}
catch(...)
{
}
return FALSE;
#endif

/*
     try
     {
          //CNtlmProxyAuth a("LightCity", "Ursa-Minor", "Zaphod", "Beeblebrox");
          CNtlmProxyAuth a("SC0041", "SIRODEL", "a.galkin", "");
          CMaaFile f("c:\\1\\ntlm_mytest.txt", CMaaFile::eWC);
          CMaaString m;
          f.Write(a.GetType1Message(
#ifdef CNtlmProxyAuth_TEST
               &m
#endif
               ) + "\r\n");
          f.Write(CMaaString::sFormat("%m", (const char *)m, m.Length()) + "\r\n");
          if   (a.SetType2Message(
#ifdef CNtlmProxyAuth_TEST
               &m, 
#endif
               //"WWW-Authenticate: NTLM TlRMTVNTUAACAAAAAAAAACgAAAABggAAU3J2Tm9uY2UAAAAAAAAAAA=="))
               "Proxy-Authenticate: NTLM TlRMTVNTUAACAAAACAAIADgAAAAFgomiGXyUe/lR8TQAAAAAAAAAAI4AjgBAAAAABQLODgAAAA9TAFQAQQBSAAIACABTAFQAQQBSAAEADgBTAEEAUABQAEgASQBSAAQAHgBzAHQAYQByAC4AcwBpAHIAbwBkAGUAbAAuAHIAdQADAC4AcwBhAHAAcABoAGkAcgA"))
          {
               f.fprintf("true\r\n");
          }
          else
          {
               f.fprintf("false\r\n");
          }
          f.Write(CMaaString::sFormat("%m", (const char *)m, m.Length()) + "\r\n");
          f.Write(a.GetType3Message(
#ifdef CNtlmProxyAuth_TEST
               &m
#endif
               ) + "\r\n");
          f.Write(CMaaString::sFormat("%m", (const char *)m, m.Length()) + "\r\n");
          f.Close();
     }
     catch(...)
     {
     }
     return FALSE;
     */

#endif

DEF_ALLOCATOR(CNtlmProxyAuth)
