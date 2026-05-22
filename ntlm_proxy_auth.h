//#define CNtlmProxyAuth_TEST

#define CNtlmProxyAuth_NEW

class CNtlmProxyAuth
{
protected:
#ifndef CNtlmProxyAuth_NEW
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

    static _uword htons_le(_uword x) noexcept // storing LittleEndianWord
    {
        return x;
    }

    static _uword ntohs_le(_uword x) noexcept // reading LittleEndianWord
    {
        return x;
    }

    CMaaString m_HostName, m_DomainNameUp, m_DomainName, m_UserName, m_Password;
    _byte   m_Nonce[8];
    CMaaString m_msg2;
#else
    CMaaString m_HostName, m_DomainName, m_UserName, m_Password, m_Msg2;
    int m_Type;
#endif

public:
    CNtlmProxyAuth(const CMaaString &HostName, const CMaaString &DomainName, const CMaaString &UserName, const CMaaString &Password, int Type);
    ~CNtlmProxyAuth();

    virtual CMaaString GetType1Message(
#ifdef CNtlmProxyAuth_TEST
         CMaaString * mm = nullptr,
#endif
         bool bFullLine = true);

    virtual bool SetType2Message(
#ifdef CNtlmProxyAuth_TEST
         CMaaString * mm,
#endif
         CMaaString Msg2, bool bFullLine = true, bool bStrict = false);

    virtual CMaaString GetType3Message(
#ifdef CNtlmProxyAuth_TEST
         CMaaString * mm = nullptr,
#endif
         bool bFullLine = true);

protected:

#ifndef CNtlmProxyAuth_NEW
    //Helpers

    static void calc_resp(unsigned char *keys, unsigned char *plaintext, unsigned char *results);
    static void setup_des_key(void * key_56_, des_key_schedule ks) noexcept;
#endif
public:
    ADD_ALLOCATOR(CNtlmProxyAuth)
};


#ifndef CNtlmProxyAuth_NEW
class CNtlmv2ProxyAuth : public CNtlmProxyAuth
{
public:
    CNtlmv2ProxyAuth(const CMaaString &HostName, const CMaaString &DomainName, const CMaaString &UserName, const CMaaString &Password);
    ~CNtlmv2ProxyAuth();

#ifdef CNtlmProxyAuth_NEW
    CMaaString GetType1Message(
#ifdef CNtlmProxyAuth_TEST
        CMaaString* mm = nullptr,
#endif
        bool bFullLine = true);
#endif

    bool SetType2Message(
#ifdef CNtlmProxyAuth_TEST
         CMaaString * mm,
#endif
         CMaaString Msg2, bool bFullLine = true, bool bStrict = false);

    CMaaString GetType3Message(
#ifdef CNtlmProxyAuth_TEST
         CMaaString * mm = nullptr,
#endif
         bool bFullLine = true);

#ifndef CNtlmProxyAuth_NEW
    CMaaString getLMResponse(CMaaString password, CMaaString challenge);
    CMaaString getNTLMResponse(CMaaString password, CMaaString challenge);
    CMaaString getNTLMv2Response(CMaaString target, CMaaString user, CMaaString password, CMaaString targetInformation, CMaaString challenge, CMaaString clientNonce);
    CMaaString getLMv2Response(CMaaString target, CMaaString user, CMaaString password, CMaaString challenge, CMaaString clientNonce);
    CMaaString getNTLM2SessionResponse(CMaaString password, CMaaString challenge, CMaaString clientNonce);
    CMaaString lmHash(CMaaString password);
    CMaaString ntlmHash(CMaaString password);
    CMaaString ntlmv2Hash(CMaaString target, CMaaString user, CMaaString password);
    CMaaString lmResponse(CMaaString hash, CMaaString challenge);
    CMaaString lmv2Response(CMaaString hash, CMaaString clientData, CMaaString challenge);
    CMaaString createBlob(CMaaString targetInformation, CMaaString clientNonce);
    CMaaString hmacMD5(CMaaString data, CMaaString key);
    void Error(int n);
#endif
};
#endif
