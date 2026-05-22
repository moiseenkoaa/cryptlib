#ifndef	__NTLM_UTIL_INCLUDE
#define	__NTLM_UTIL_INCLUDE
//#include <string>
//#include <cstring>
//using namespace std;
/*
#include <openssl/des.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>
*/

#define DES_cblock des_cblock
#define DES_key_schedule des_key_schedule
#define DES_set_odd_parity des_set_odd_parity
#define DES_set_key des_set_key
#define DES_ecb_encrypt des_ecb_encrypt
#define MD4_DIGEST_LENGTH 16
//#define HMAC_CTX HMACContext

extern "C" {
//#include "libcrypto-compat.h"
}

//#define ASCII_CHAR(ch)  (ch)
#define ASCII_STR(s) (s)
//#define BASE64_ENCODE_LENGTH(len)	(4 * (((len) + 2) / 3))
//#define BASE64_DECODE_LENGTH(len)	(3 * (((len) + 3) / 4))

//std::string to_uppercase(const string& s);

#if 1
#ifdef TOOLSLIB_LITTLE_ENDIAN
inline constexpr bool is_big_endian() noexcept { return false; }
inline constexpr uint16_t to_little_endian(uint16_t i_data) noexcept { return i_data; }
inline constexpr uint32_t to_little_endian(uint32_t i_data) noexcept { return i_data; }
inline constexpr uint64_t to_little_endian(uint64_t i_data) noexcept { return i_data; }
#else
inline constexpr bool is_big_endian() noexcept { return true; }
inline constexpr uint16_t to_little_endian(uint16_t i_data) noexcept { return my_htons_le(i_data); }
inline constexpr uint32_t to_little_endian(uint32_t i_data) noexcept { return my_htonl_le(i_data); }
inline constexpr uint64_t to_little_endian(uint64_t i_data) noexcept { return (uint64_t)my_htonq_le((_qword)i_data); }
#endif

#else
static bool is_big_endian() noexcept;
static uint16_t to_little_endian(uint16_t i_data) noexcept;
static uint32_t to_little_endian(uint32_t i_data) noexcept;
static uint64_t to_little_endian(uint64_t i_data) noexcept;
#endif


static void des_enc(uint8_t* key, DES_cblock* data, DES_cblock* result) noexcept;
static void md4_enc(uint8_t* data, size_t data_len, uint8_t* result) noexcept;
static void md5_enc(uint8_t* data, size_t data_len, uint8_t* result) noexcept;
static void hmac_md5_enc(void* key, int key_len, uint8_t* data, int data_len, uint8_t* digest, unsigned int digest_len) noexcept;

//void ascii_to_unicode(CMaaString ascii_str, char *unicode_str);
static void concat(const uint8_t* data1, size_t data1_len, const uint8_t* data2, size_t data2_len, uint8_t* result) noexcept;
static uint64_t create_timestamp() noexcept;


//void base64_encode(const char *src, char *dst, size_t length);

//size_t base64_decode(const char *src, uint8_t *dst);
#endif
