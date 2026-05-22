#include "stdafx.h"
#include "temp.h"

#include "util.h"
#include "ntlm.h"
#include "util.cpp"

//#include <openssl/rand.h>
//#include <cstring>

CMaaString make_type1_msg(const CMaaString &domain_, const CMaaString &host_, int ntlm_resp_type)
{
    CMaaString upper_domain = Utf8ToAnsi(domain_.ToUpper(e_utf8));
    CMaaString upper_host = Utf8ToAnsi(host_.ToUpper(e_utf8));
    int dom_len = (warning_int)upper_domain.Length();
    const int hst_len = (warning_int)upper_host.Length();
    
    struct Type1Message msg1;
    memset(&msg1, 0, MSG1_SIZE);
    
    strcpy(msg1.signature, ASCII_STR(NTLMSSP_SIGNATURE));
    
    msg1.type = to_little_endian((uint32_t) TYPE1_INDICATOR);
    
    if (ntlm_resp_type == USE_NTLMV1)
    {
        msg1.flag = to_little_endian((uint32_t) NTLMV1_FLAG);
    }
    else if (ntlm_resp_type == USE_NTLM2SESSION)
    {
        msg1.flag = to_little_endian((uint32_t) NTLM2SESSION_FLAG);
    }
    else if (ntlm_resp_type == USE_NTLMV2)
    {
        msg1.flag = to_little_endian((uint32_t) NTLMV2_FLAG);
    }
    else
    {
        return CMaaStringZ;
    }
        
    msg1.dom_len = msg1.dom_max_len = to_little_endian((uint16_t) dom_len);
    msg1.dom_off = to_little_endian((uint32_t) MSG1_SIZE);
    
    msg1.hst_len = msg1.hst_max_len = to_little_endian((uint16_t) hst_len);
    msg1.hst_off  = to_little_endian((uint32_t)(MSG1_SIZE + dom_len));
    
    const size_t buff_size = MSG1_SIZE + dom_len + hst_len;
    CMaaString strBuff(nullptr, buff_size, CMaaString::eCryptoKey);
    if (strBuff.Length() != (int)buff_size)
    {
        return CMaaStringZ;
    }
    char *buff = strBuff.GetBuffer();
    memcpy(buff, &msg1, MSG1_SIZE);
    if (dom_len)
    {
        memcpy(buff + MSG1_SIZE, ASCII_STR(upper_domain), dom_len);
    }
    if (hst_len)
    {
        memcpy(buff + MSG1_SIZE + dom_len, ASCII_STR(upper_host), hst_len);
    }

    return strBuff.Base64Encode();
}

CMaaString make_type3_msg(const CMaaString &username_, const CMaaString &password_, const CMaaString &domain_, const CMaaString &host_, const CMaaString &msg2_b64_buff, int ntlm_resp_type)
{
    if (msg2_b64_buff.IsEmpty())
    {
        return CMaaStringZ;
    }
    //domain = domain.ToUpper(e_utf8);

    Message2Handle msg2_handle(msg2_b64_buff);
    
    const bool support_unicode = msg2_handle.support_unicode();
    
    CMaaString s_username, s_password, s_domain, s_host_;
    if (support_unicode)
    {
        s_username = Utf8ToUnicode(username_);
        s_password = Utf8ToUnicode(password_);
        s_domain = Utf8ToUnicode(domain_);
        s_host_ = Utf8ToUnicode(host_);
        
        if (is_big_endian())
        {
            s_password.SetCryptoKeyBit();
            s_username = UnicodeBigEndianToUnicode(s_username);
            s_password = UnicodeBigEndianToUnicode(s_password);
            s_domain = UnicodeBigEndianToUnicode(s_domain);
            s_host_ = UnicodeBigEndianToUnicode(s_host_);
        }
    }
    else
    {
        s_username = Utf8ToAnsi(username_);
        s_password = Utf8ToAnsi(password_);
        s_domain = Utf8ToAnsi(domain_);
        s_host_ = Utf8ToAnsi(host_);
    }
    s_password.SetCryptoKeyBit();

    struct Type3Message msg3;
    memset(&msg3, 0, MSG3_SIZE);
    uint16_t lm_challenge_resp_len, nt_challenge_resp_len, dom_len, usr_name_len, hst_len;
    uint32_t lm_challenge_resp_off, nt_challenge_resp_off, dom_off, usr_name_off, hst_off;
        
    strcpy(msg3.signature, ASCII_STR(NTLMSSP_SIGNATURE));
    msg3.type = to_little_endian((uint32_t) TYPE3_INDICATOR);
    
    uint8_t lm_resp[24];
    uint8_t bf_ntlm_resp[24];
    memset(lm_resp, 0, sizeof(lm_resp));;
    memset(bf_ntlm_resp, 0, sizeof(bf_ntlm_resp));;
    uint8_t* ntlm_resp = bf_ntlm_resp;
    setup_security_buffer(lm_challenge_resp_len, lm_challenge_resp_off, msg3.lm_challenge_resp_len, msg3.lm_challenge_resp_max_len, msg3.lm_challenge_resp_off, 
            24, 
            MSG3_SIZE);
        
    setup_security_buffer(dom_len, dom_off, msg3.dom_len, msg3.dom_max_len, msg3.dom_off, 
        (uint16_t)s_domain.Length(),
        lm_challenge_resp_off + lm_challenge_resp_len);
    
    setup_security_buffer(usr_name_len, usr_name_off, msg3.usr_name_len, msg3.usr_name_max_len, msg3.usr_name_off, 
        (uint16_t)s_username.Length(),
        dom_off + dom_len);
    
    setup_security_buffer(hst_len, hst_off, msg3.hst_len, msg3.hst_max_len, msg3.hst_off, 
        (uint16_t)s_host_.Length(),
        usr_name_off + usr_name_len);
        
    setup_security_buffer(nt_challenge_resp_len, nt_challenge_resp_off, msg3.nt_challenge_resp_len, msg3.nt_challenge_resp_max_len, msg3.nt_challenge_resp_off, 
            24, 
            hst_off + hst_len);

    msg3.session_key_len = msg3.session_key_max_len = 0;

    CMaaString str_ntlmv2_resp;
    if (ntlm_resp_type == USE_NTLMV1)
    {
        msg3.flag = to_little_endian((uint32_t) NTLMV1_FLAG);

        //memset(lm_resp, 0, 24);
        calc_lmv1_resp(password_, msg2_handle.get_challenge(), lm_resp);
        
        uint8_t *ntlmv1_resp = ntlm_resp;
        //memset(ntlmv1_resp, 0, 24);
        calc_ntlmv1_resp(password_, msg2_handle.get_challenge(), ntlmv1_resp);
        
    }
    else if (ntlm_resp_type == USE_NTLM2SESSION)
    {
        msg3.flag = to_little_endian((uint32_t) NTLM2SESSION_FLAG);
        
        uint8_t* ntlm2session_resp = ntlm_resp;
        //memset(lm_resp, 0, 24);
        //memset(ntlm2session_resp, 0, 24);
        
        uint8_t client_nonce[8];
        memset(client_nonce, 0, 8);
        create_client_nonce(client_nonce, 8);
        calc_ntlm2session_resp(password_, msg2_handle.get_challenge(), client_nonce, lm_resp, ntlm2session_resp);
        
    }
    else if (ntlm_resp_type == USE_NTLMV2)
    {
        msg3.flag = to_little_endian((uint32_t) NTLM2SESSION_FLAG);
        uint8_t* lmv2_resp = lm_resp;
        //memset(lmv2_resp, 0, 24);
        calc_lmv2_resp(username_, password_, domain_, msg2_handle.get_challenge(), lmv2_resp);
        
        uint16_t target_info_len = 0;
        const uint8_t* target_info = msg2_handle.get_target_info(target_info_len);
        const size_t blob_len = 28 + target_info_len; //the blob fixed len + target_info_len
        const size_t ntlmv2_resp_len = 16 + blob_len;// hmac + blob
        str_ntlmv2_resp = CMaaString(nullptr, ntlmv2_resp_len /* * sizeof(uint8_t)*/, CMaaString::eCryptoKey);
        if (str_ntlmv2_resp.IsEmpty())
        {
            return CMaaStringZ;
        }
        uint8_t* ntlmv2_resp = (uint8_t*)str_ntlmv2_resp.GetBuffer();
        //uint8_t *ntlmv2_resp = new uint8_t[ntlmv2_resp_len];
        ntlm_resp = ntlmv2_resp;
        //memset(ntlmv2_resp, 0, ntlmv2_resp_len);
        
        setup_security_buffer(nt_challenge_resp_len, nt_challenge_resp_off, msg3.nt_challenge_resp_len, msg3.nt_challenge_resp_max_len, msg3.nt_challenge_resp_off, 
            (uint16_t)ntlmv2_resp_len, 
            hst_off + hst_len);
        calc_ntlmv2_resp(username_, password_, domain_, msg2_handle.get_challenge(), target_info, target_info_len, ntlmv2_resp);
    }
    else
    {
        return CMaaStringZ;
    }
    
    const size_t msg3_buff_len = MSG3_SIZE + lm_challenge_resp_len + nt_challenge_resp_len + dom_len + usr_name_len + hst_len;
    CMaaString str_msg3_buff(nullptr, msg3_buff_len, CMaaString::eCryptoKey);
    char* msg3_buff = str_msg3_buff.GetBuffer();// new char[msg3_buff_len];
    memcpy(msg3_buff, &msg3, MSG3_SIZE);
    memcpy(msg3_buff + lm_challenge_resp_off, lm_resp, lm_challenge_resp_len);
    memcpy(msg3_buff + nt_challenge_resp_off, ntlm_resp, nt_challenge_resp_len);

    /*
    char* p_domain = (char*)(const char*)domain;
    char* p_username = (char*)(const char*)username;
    char* p_host = (char*)(const char*)host;
    if(support_unicode)
    {
        p_domain = new char[dom_len];
        p_username = new char[usr_name_len];
        p_host = new char[hst_len];
        
        memset(p_domain, 0, dom_len);
        memset(p_username, 0, usr_name_len);
        memset(p_host, 0, hst_len);
        
        ascii_to_unicode(domain, p_domain);
        ascii_to_unicode(username, p_username);
        ascii_to_unicode(host, p_host);
    }
    */
    memcpy(msg3_buff + dom_off, s_domain, dom_len);
    memcpy(msg3_buff + usr_name_off, s_username, usr_name_len);
    memcpy(msg3_buff + hst_off, s_host_, hst_len);

    /*
    if (support_unicode)
    {
        delete [] p_domain;
        delete [] p_username;
        delete [] p_host;
    }
    */

    //CMaaString result = 
    return CMaaString(msg3_buff, msg3_buff_len).Base64Encode();
    
    /*
    char* msg3_buff_b64 = new char[BASE64_ENCODE_LENGTH(msg3_buff_len) + 1];
    base64_encode(msg3_buff, msg3_buff_b64, msg3_buff_len);
    msg3_buff_b64[BASE64_ENCODE_LENGTH(msg3_buff_len)] = '\0';
    std::string result(msg3_buff_b64);
    */

    //delete [] msg3_buff;
    //delete [] msg3_buff_b64;
    //delete [] ntlm_resp;
    //return result;
    
}

static void calc_lmv1_resp(const CMaaString &password_, const uint8_t* challenge, uint8_t* lm_resp)
{
    CMaaString upper_pwd = Utf8ToAnsi(password_.ToUpper(e_utf8).SetCryptoKeyBitEx());
    upper_pwd.SetCryptoKeyBit();
    const size_t upper_pwd_len = upper_pwd.Length();
    uint8_t pwd[14];
    memset(pwd, 0, 14);
    const size_t mv_len = upper_pwd_len < 14 ? upper_pwd_len : 14;
    memcpy(pwd, upper_pwd, mv_len);
    uint8_t* pwd_l = pwd;// low 7 bytes
    uint8_t* pwd_h = pwd + 7;// high 7 bytes
    
    uint8_t lm_hash_padded[21];
    memset(lm_hash_padded, 0, 21);
    
    uint8_t* lm_hash_l = lm_hash_padded;// low 8 bytes
    uint8_t* lm_hash_h = lm_hash_padded + 8; // high 8 bytes
    uint8_t* lm_hash_p = lm_hash_padded + 16; // the padded 5 bytes
    DES_cblock magic = { 0x4B, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25 }; // "KGS!@#$%"
    
    //key data result
    des_enc(pwd_l, &magic, (DES_cblock*)lm_hash_l);
    des_enc(pwd_h, &magic, (DES_cblock*)lm_hash_h);
    memset(lm_hash_p, 0, 5);
    
    memset(lm_resp, 0, 24);
    uint8_t* lm_resp1 = lm_resp;
    uint8_t* lm_resp2 = lm_resp + 8;
    uint8_t* lm_resp3 = lm_resp + 16;
    
    uint8_t* lm_hash_padded1 = lm_hash_padded;
    uint8_t* lm_hash_padded2 = lm_hash_padded + 7;
    uint8_t* lm_hash_padded3 = lm_hash_padded + 14;

    des_enc(lm_hash_padded1, (DES_cblock*) challenge, (DES_cblock*) lm_resp1);
    des_enc(lm_hash_padded2, (DES_cblock*) challenge, (DES_cblock*) lm_resp2);
    des_enc(lm_hash_padded3, (DES_cblock*) challenge, (DES_cblock*) lm_resp3);
    
    memset(pwd, 0, 14);
    memset(lm_hash_padded, 0, 21);
}

static void calc_ntlmv1_resp(const CMaaString &password_, const uint8_t* challenge, uint8_t* ntlmv1_resp)
{
    uint8_t ntlmv1_hash_padded[21];
    memset(ntlmv1_hash_padded, 0, 21);
    memset(ntlmv1_resp, 0, 24);
    
    uint8_t ntlmv1_hash[MD4_DIGEST_LENGTH]; // 16-uint8_t
    memset(ntlmv1_hash, 0, MD4_DIGEST_LENGTH);
    calc_ntlmv1_hash(password_, ntlmv1_hash);
    
    memset(ntlmv1_hash_padded, 0, 21);
    memcpy(ntlmv1_hash_padded, ntlmv1_hash, MD4_DIGEST_LENGTH);
    
    uint8_t* ntlmv1_resp1 = ntlmv1_resp;
    uint8_t* ntlmv1_resp2 = ntlmv1_resp + 8;
    uint8_t* ntlmv1_resp3 = ntlmv1_resp + 16;
    
    uint8_t* ntlmv1_hash_padded1 = ntlmv1_hash_padded;
    uint8_t* ntlmv1_hash_padded2 = ntlmv1_hash_padded  + 7;
    uint8_t* ntlmv1_hash_padded3 = ntlmv1_hash_padded  + 14;
    
    des_enc(ntlmv1_hash_padded1, (DES_cblock*) challenge, (DES_cblock*) ntlmv1_resp1);
    des_enc(ntlmv1_hash_padded2, (DES_cblock*) challenge, (DES_cblock*) ntlmv1_resp2);
    des_enc(ntlmv1_hash_padded3, (DES_cblock*) challenge, (DES_cblock*) ntlmv1_resp3);
}

static void calc_ntlm2session_resp(const CMaaString &password_, const uint8_t* challenge, uint8_t* client_nonce, uint8_t* lm_resp, uint8_t* ntlm2session_resp)
{
    memset(lm_resp, 0, 24);
    memcpy(lm_resp, client_nonce, 8);
        
    uint8_t session_nonce[16];
    memset(session_nonce, 0, 16);
    concat(challenge, 8, client_nonce, 8, session_nonce);
    
    uint8_t ntlm2session_hash[8];
    memset(ntlm2session_hash, 0, 8);
    calc_ntlm2session_hash(session_nonce, ntlm2session_hash);
    
    
    uint8_t ntlmv1_hash_padded[21];
    memset(ntlmv1_hash_padded, 0, 21);

    uint8_t ntlmv1_hash[MD4_DIGEST_LENGTH]; // 16-uint8_t
    memset(ntlmv1_hash, 0, MD4_DIGEST_LENGTH);
    calc_ntlmv1_hash(password_, ntlmv1_hash);
    
    memset(ntlmv1_hash_padded, 0, 21);
    memcpy(ntlmv1_hash_padded, ntlmv1_hash, MD4_DIGEST_LENGTH);
    
    uint8_t* ntlm2session_resp1 = ntlm2session_resp;
    uint8_t* ntlm2session_resp2 = ntlm2session_resp + 8;
    uint8_t* ntlm2session_resp3 = ntlm2session_resp + 16;
    
    uint8_t* ntlmv1_hash_padded1 = ntlmv1_hash_padded;
    uint8_t* ntlmv1_hash_padded2 = ntlmv1_hash_padded  + 7;
    uint8_t* ntlmv1_hash_padded3 = ntlmv1_hash_padded  + 14;
    
    des_enc(ntlmv1_hash_padded1, (DES_cblock*) ntlm2session_hash, (DES_cblock*) ntlm2session_resp1);
    des_enc(ntlmv1_hash_padded2, (DES_cblock*) ntlm2session_hash, (DES_cblock*) ntlm2session_resp2);
    des_enc(ntlmv1_hash_padded3, (DES_cblock*) ntlm2session_hash, (DES_cblock*) ntlm2session_resp3);
    
    memset(session_nonce, 0, 16);
    memset(ntlm2session_hash, 0, 8);
    memset(ntlmv1_hash_padded, 0, 21);
    memset(ntlmv1_hash, 0, MD4_DIGEST_LENGTH);
}

static void calc_lmv2_resp(const CMaaString &username_, const CMaaString &password_, const CMaaString &domain_, const uint8_t* challenge, uint8_t* lmv2_resp)
{
    uint8_t client_nonce[8];
    memset(client_nonce, 0, 8);
    create_client_nonce(client_nonce, 8);

    uint8_t data[16];
    memset(data, 0, 16);
    concat(client_nonce, 8, challenge, 8, data);
    
    uint8_t ntlmv2_hash[16];
    memset(ntlmv2_hash, 0, 16);
    calc_ntlmv2_hash(username_, password_, domain_, ntlmv2_hash);
    
    uint8_t hmac[16];
    memset(hmac, 0, 16);
    hmac_md5_enc((void*)ntlmv2_hash, 16, data, 16, hmac, 16);
    
    concat(hmac, 16, client_nonce, 8, lmv2_resp);
    
    memset(client_nonce, 0, 8);
    memset(data, 0, 16);
    memset(ntlmv2_hash, 0, 16);
    memset(hmac, 0, 16);
}

static void calc_ntlmv2_resp(const CMaaString &username_, const CMaaString &password_, const CMaaString &domain_, const uint8_t* challenge, const uint8_t* target_info, uint16_t target_info_len, uint8_t* ntlmv2_resp)
{
    const size_t blob_len = 28 + target_info_len; //the blob fixed len + target_info_len
    CMaaString str_blob(nullptr, blob_len, CMaaString::eCryptoKey);
    if (str_blob.IsEmpty())
    {
        return;
    }
    //uint8_t* blob = new uint8_t[blob_len];
    //memset(blob, 0, blob_len);
    uint8_t* blob = (uint8_t *)str_blob.GetBuffer();
    create_blob(target_info, target_info_len, blob, blob_len);
    
    size_t challenge_len = 8;
    size_t data_len = challenge_len + blob_len;
    CMaaString str_data(nullptr, data_len, CMaaString::eNotInitMemKey);
    if (str_data.IsEmpty())
    {
        return;
    }
    //uint8_t* data = new uint8_t[data_len];
    uint8_t* data = (uint8_t*)str_data.GetBuffer();
    concat(challenge, challenge_len, blob, blob_len, data);
    
    uint8_t ntlmv2_hash[16];
    memset(ntlmv2_hash, 0, 16);
    calc_ntlmv2_hash(username_, password_, domain_, ntlmv2_hash);
    
    uint8_t hmac[16];
    memset(hmac, 0, 16);
    hmac_md5_enc((void*)ntlmv2_hash, 16, data, (int)data_len, hmac, 16);

    concat(hmac, 16, blob, blob_len, ntlmv2_resp); 
    //delete [] blob;   
    
    memset(ntlmv2_hash, 0, 16);
    memset(hmac, 0, 16);
}

static void calc_ntlmv1_hash(const CMaaString &password_, uint8_t* ntlmv1_hash)
{
    memset(ntlmv1_hash, 0, MD4_DIGEST_LENGTH);
    //size_t unicode_pwd_len = password.Length() * 2;
    //char* unicode_pwd = new char[unicode_pwd_len];
    CMaaString unicode_pwd = Utf8ToUnicode(password_);
    unicode_pwd.SetCryptoKeyBit();
    if (is_big_endian())
    {
        unicode_pwd = UnicodeBigEndianToUnicode(unicode_pwd);
        unicode_pwd.SetCryptoKeyBit();
    }

    //ascii_to_unicode(password, unicode_pwd);
    
    md4_enc((uint8_t*)(const char *)unicode_pwd, unicode_pwd.Length() /*unicode_pwd_len*/, ntlmv1_hash);

    //delete []unicode_pwd;
}

//16-uint8_t session_nonce
//8-uint8_t session_hash
static void calc_ntlm2session_hash(uint8_t* session_nonce, uint8_t* session_hash) noexcept
{
    //session_nonce is 16-uint8_t
    //session_hash is 8 uint8_t
    memset(session_hash, 0, 8);
    uint8_t md5_nonce[16];
    md5_enc(session_nonce, 16, md5_nonce);
    memcpy(session_hash, md5_nonce, 8);

    memset(md5_nonce, 0, 16);
}

static void calc_ntlmv2_hash(const CMaaString &username_, const CMaaString &password_, const CMaaString &domain_, uint8_t* ntlmv2_hash)
{
    memset(ntlmv2_hash, 0, 16);
    
    uint8_t ntlmv1_hash[MD4_DIGEST_LENGTH]; 
    memset(ntlmv1_hash, 0, MD4_DIGEST_LENGTH);
    calc_ntlmv1_hash(password_, ntlmv1_hash);
    
    CMaaString username = Utf8ToUnicode(username_.ToUpper(e_utf8));
    CMaaString domain = Utf8ToUnicode(domain_);
    if (is_big_endian())
    {
        username = UnicodeBigEndianToUnicode(username);
        domain = UnicodeBigEndianToUnicode(domain);
    }

    CMaaString unicode_name_dom = username + domain;
    if (unicode_name_dom.Length() == username.Length() + domain.Length())
    {
        hmac_md5_enc((void*)ntlmv1_hash, MD4_DIGEST_LENGTH, (uint8_t*)unicode_name_dom.GetBuffer(), (int)unicode_name_dom.Length(), ntlmv2_hash, 16);
    }
    //size_t unicode_name_dom_len = username.Length() * 2 + domain.Length() * 2;
    //char* unicode_name_dom = new char[unicode_name_dom_len];
    
    //ascii_to_unicode(username.ToUpper(), unicode_name_dom);
    //ascii_to_unicode(domain, unicode_name_dom + username.Length() * 2);
    
    //hmac_md5_enc((void*)ntlmv1_hash, MD4_DIGEST_LENGTH, (uint8_t*)unicode_name_dom, unicode_name_dom_len, ntlmv2_hash, 16);
    
    //delete [] unicode_name_dom;
    memset(ntlmv1_hash, 0, MD4_DIGEST_LENGTH);
}

static void create_client_nonce(uint8_t* nonce, size_t len) noexcept
{
    memset(nonce, 0, len);
    if (len != 8)
    {
        return;
    }
    //int ret = RAND_bytes(nonce, 8);
    int ret = 1;
    try
    {
        GetRnd(nonce, 8);
    }
    catch (...)
    {
        ret = 0;
    }
    //if fail, set 0xffffffff0102034
	if (ret != 1)
	{
        for(int i = 0; i < 4; ++i)
        {
        	nonce[i] = 0xff;
        }
        
        for(int j = 4; j < 8; ++j)
		{
			nonce[j] = j;
		}
	}
}

static void create_blob(const uint8_t* target_info, uint16_t target_info_len, uint8_t* blob, size_t blob_len) noexcept
{
   /*
    * Description   Content
    * 0             Blob Signature      0x01010000
    * 4             Reserved            long (0x00000000)
    * 8             Timestamp           Little-endian, 64-bit signed value representing the number of tenths of a microsecond since January 1, 1601.
    * 16            Client Nonce        8 bytes
    * 24            Unknown             4 bytes
    * 28            Target Information  Target Information block (from the Type 2 message).
    * (variable)    Unknown             4 bytes
    */
    memset(blob, 0, blob_len);
    if (28 + target_info_len != (int)blob_len)
    {
        return;
    }

    uint64_t timestamp = create_timestamp();
    uint8_t client_nonce[8];
    memset(client_nonce, 0, 8);
    create_client_nonce(client_nonce, 8);
    
    //uint8_t *blob = new uint8_t[blob_len];
    memset(blob, 0, blob_len);
    blob[0] = 0x1;
    blob[1] = 0x1;
    memcpy(blob + 8, &timestamp, 8);
    memcpy(blob + 16, client_nonce, 8);
    memcpy(blob + 28, target_info, target_info_len); // or memmove
    
    memset(client_nonce, 0, 8);
}

static void setup_security_buffer(uint16_t &temp_len,uint32_t &temp_off, uint16_t &msg_len, uint16_t &msg_max_len, uint32_t &msg_off, uint16_t len_val, uint32_t off_val) noexcept
{
    temp_len = len_val;
    temp_off = off_val;
    msg_len = msg_max_len = to_little_endian(len_val);
    msg_off = to_little_endian(off_val);
}


Message2Handle::Message2Handle(const CMaaString & msg2_b64_buff)
{
    memset(&msg2, 0, MSG2_SIZE);
    //msg2_buff = NULL;
    //size_t msg2_buff_len = BASE64_DECODE_LENGTH(msg2_b64_buff.Length());
    //msg2_buff = new uint8_t[msg2_buff_len];
    m_buff = msg2_b64_buff.Base64Decode();
    m_buff.SetCryptoKeyBit();
    //base64_decode(msg2_b64_buff.c_str(), msg2_buff);
    memcpy(&msg2, m_buff, m_buff.Length() >= (int)MSG2_SIZE ? MSG2_SIZE : m_buff.Length());
    /*
    * following is a tricky part
    * the memmove directly may cause:
    * some little endian data was recognized as big endian data in big endian machine
    * so,just call toLittleEndian() in TmAuDIUtil could solve
    */
    if(is_big_endian())
    {
        msg2.type = to_little_endian(msg2.type);
        msg2.target_name_len = to_little_endian(msg2.target_name_len);
        msg2.target_name_max_len = to_little_endian(msg2.target_name_max_len);
        msg2.target_name_off = to_little_endian(msg2.target_name_off);
        msg2.flag = to_little_endian(msg2.flag);
        msg2.target_info_len = to_little_endian(msg2.target_info_len);
        msg2.target_info_max_len = to_little_endian(msg2.target_info_max_len);
        msg2.target_info_off = to_little_endian(msg2.target_info_off);
    }
}
Message2Handle::~Message2Handle()
{
    //if(NULL != msg2_buff)
    //{
    //    delete [] msg2_buff;
    //}
}

const uint8_t* Message2Handle::get_challenge() noexcept
{
    return msg2.challenge;
}

uint32_t Message2Handle::get_flag() const noexcept
{
    return msg2.flag;
}

bool Message2Handle::support_unicode() const noexcept
{
    return msg2.flag & 0x1;
}

const uint8_t* Message2Handle::get_target_info(uint16_t& target_info_len) noexcept
{
    target_info_len = msg2.target_info_len;
  
    const uint8_t* target_info = (const uint8_t*)(msg2.target_info_off + (const char *)m_buff);
    return target_info;
}
