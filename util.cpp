//#include "stdafx.h"
//#include "temp.h"

/*
std::string to_uppercase(const std::string& s)
{
    if(s.length() == 0){
		return std::string("");
	}
	char* buf = new char[s.length()];
	s.copy(buf, s.length());
	for(unsigned int i = 0; i < s.length(); i++)
		buf[i] = static_cast<char>(toupper(buf[i]));
	std::string r(buf, s.length());
	delete [] buf;
	return r;
}
*/

#if 1

/*
#ifdef TOOLSLIB_LITTLE_ENDIAN
static constexpr bool is_big_endian() noexcept
{
	return false;
}
static constexpr uint16_t to_little_endian(uint16_t i_data) noexcept
{
	return i_data;
}
static constexpr uint32_t to_little_endian(uint32_t i_data) noexcept
{
	return i_data;
}
static constexpr uint64_t to_little_endian(uint64_t i_data) noexcept
{
	return i_data;
}
#else
static constexpr bool is_big_endian() noexcept
{
	return true;
}
static constexpr uint16_t to_little_endian(uint16_t i_data) noexcept
{
	return my_htons_le(i_data);
}
static uint32_t to_little_endian(uint32_t i_data) noexcept
{
	return my_htonl_le(i_data);
}
static uint64_t to_little_endian(uint64_t i_data) noexcept
{
	return (uint64_t)my_htonq_le((_qword)i_data);
}
#endif
*/

#else

static bool is_big_endian() noexcept
{
	uint32_t data = 0x11223344;
	uint8_t* pdata = (uint8_t*)&data;
	return pdata[0] == 0x11;
}

static uint16_t to_little_endian(uint16_t i_data) noexcept
{
	if (!is_big_endian())
	{
		return i_data;
	}
	uint16_t o_data;
	uint8_t* pi = (uint8_t*)&i_data;
	uint8_t* po = (uint8_t*)&o_data;

	po[0] = pi[1];
	po[1] = pi[0];
	return o_data;
}

static uint32_t to_little_endian(uint32_t i_data) noexcept
{
	if (!is_big_endian())
	{
		return i_data;
	}
	uint32_t o_data;
	uint8_t* pi = (uint8_t*)&i_data;
	uint8_t* po = (uint8_t*)&o_data;

	po[0] = pi[3];
	po[1] = pi[2];
	po[2] = pi[1];
	po[3] = pi[0];
	return o_data;
}

static uint64_t to_little_endian(uint64_t i_data) noexcept
{
	if (!is_big_endian())
	{
		return i_data;
	}
	uint64_t o_data;
	uint8_t* pi = (uint8_t*)&i_data;
	uint8_t* po = (uint8_t*)&o_data;

	size_t i = 0;
	for (i = 0; i < 8; ++i)
	{
		po[i] = pi[7 - i];
	}

	return o_data;
}
#endif

static void setup_des_key(unsigned char key_56[], DES_key_schedule &ks) noexcept
{
	DES_cblock key;

	key[0] = key_56[0];
	key[1] = ((key_56[0] << 7) & 0xFF) | (key_56[1] >> 1);
	key[2] = ((key_56[1] << 6) & 0xFF) | (key_56[2] >> 2);
	key[3] = ((key_56[2] << 5) & 0xFF) | (key_56[3] >> 3);
	key[4] = ((key_56[3] << 4) & 0xFF) | (key_56[4] >> 4);
	key[5] = ((key_56[4] << 3) & 0xFF) | (key_56[5] >> 5);
	key[6] = ((key_56[5] << 2) & 0xFF) | (key_56[6] >> 6);
	key[7] =  (key_56[6] << 1) & 0xFF;

	DES_set_odd_parity(&key);
	DES_set_key(&key, ks);
}

static void des_enc(uint8_t* key, DES_cblock* data, DES_cblock* result) noexcept
{
    DES_key_schedule ks;
    setup_des_key(key, ks);
    DES_ecb_encrypt(data, result, ks, DES_ENCRYPT);
}

static void md4_enc(uint8_t* data, size_t data_len, uint8_t* result) noexcept
{
    //MD4(data, data_len, result);
	CMD4Cacl c;
	c.Update(data, (unsigned)data_len);
	c.GetHash(result);
}

static void md5_enc(uint8_t* data, size_t data_len, uint8_t* result) noexcept
{
    //MD5(data, data_len, result);  
	CMD5Cacl c;
	c.Update(data, (unsigned)data_len);
	c.GetHash(result);
}

static void hmac_md5_enc(void* key, int key_len, uint8_t* data, int data_len, uint8_t* digest, unsigned int digest_len) noexcept
{
	// digest_len == 16
#if 0
	HMAC_CTX ctx;
	HMAC_CTX * hmac_ctx = HMAC_CTX_new(&ctx);
    HMAC_Init_ex(hmac_ctx, key, key_len, EVP_md5(), NULL);
    HMAC_Update(hmac_ctx, data, data_len);
    HMAC_Final(hmac_ctx, digest, &digest_len);
    HMAC_CTX_free(hmac_ctx);
#else
	/*
	static CMaaFile f("c:\\maa\\log.txt", "WC|SrSw", eNoExcept);
	f.fprintf("%m%d %d\r\n\r\n", key, key_len, data_len, digest_len);
	f.Flush();
	*/

	//may be addon like: // https://github.com/NewYaroslav/hmac-cpp.git for 256 and 512 bits shaxxx
	char* key_ = (char*)key;
	char TruncKey[16];
	if (key_len > 16)
	{
		memset(TruncKey, 0, 16);
		CMD5Cacl md5_1;
		md5_1.Update(key, key_len);
		md5_1.GetHash(TruncKey);
		key_ = TruncKey;
		key_len = 16;
	}

	char ipad[64], opad[64];
	memset(ipad, 0x36, sizeof(ipad));
	memset(opad, 0x5c, sizeof(opad));
	for (int i = 0; i < key_len; i++)
	{
		ipad[i] ^= key_[i];
		opad[i] ^= key_[i];
	}
	char data2[16];
	memset(data2, 0, sizeof(data2));
	CMD5Cacl md5_2;
	md5_2.Update(ipad, 64);
	md5_2.Update(data, data_len);
	md5_2.GetHash(data2);

	CMD5Cacl md5_3;
	md5_3.Update(opad, 64);
	md5_3.Update(data2, 16);
	md5_3.GetHash(digest);
	memset(data2, 0, sizeof(data2));
	memset(opad, 0, sizeof(opad));
	memset(ipad, 0, sizeof(ipad));
	memset(TruncKey, 0, sizeof(TruncKey));
#endif
}

/*
void ascii_to_unicode(CMaaString ascii_str, char* unicode_str)
{
	size_t l = ascii_str.Length();
	for (size_t i = 0; i < l; i++) {
		unicode_str[2*i] = ASCII_CHAR(ascii_str[i]);
		unicode_str[2*i +1] = '\0';
	}
}
*/

static void concat(const uint8_t* data1, size_t data1_len, const uint8_t* data2, size_t data2_len, uint8_t* result) noexcept
{
    memcpy(result, data1, data1_len);
    memcpy(result + data1_len, data2, data2_len);
}

static uint64_t create_timestamp() noexcept
{
    /*
    * calc Timestamp
    * the windows epoch starts 1601-01-01T00:00:00Z. It's 11644473600 seconds before the UNIX/Linux epoch (1970-01-01T00:00:00Z). The Windows ticks are in 100 nanoseconds. 
    */	
    uint64_t windows_tick = 10000000;
    uint64_t win_unix_time_diff = 11644473600ULL;
    uint64_t timestamp;
    time_t cur = time(NULL);
    uint64_t win_cur = cur + win_unix_time_diff;
    timestamp = (uint64_t) win_cur * windows_tick;
    
    if(is_big_endian())
    {
        timestamp = to_little_endian(timestamp);
    }
    
    return timestamp;
}

#if 0
size_t base64_decode(const char *src, uint8_t *dst) {
    /*
	BIO* bio, * b64;

    bio = BIO_new_mem_buf(src, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); 
    size_t decode_len = BIO_read(bio, (void*)dst, strlen(src));
    BIO_free_all(bio);
    return decode_len;
	*/
	CMaaString s(src);
	CMaaString d = s.Base64Decode();
	memcpy(dst, d, d.Length());
	return d.Length();
}

void base64_encode (const char *src, char *dst, size_t length) {
    /*
	BIO* bio, * b64;
    BUF_MEM *result;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); 
    BIO_write(bio, src, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &result);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    memmove(dst, (*result).data, (*result).length);
    BUF_MEM_free(result);
	*/
	
	CMaaString s(src, length);
	CMaaString d = s.Base64Encode(-1);
	memcpy(dst, d, d.Length());
}
#endif
