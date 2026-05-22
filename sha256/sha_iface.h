
class CSHACacl
{
     int m_err;
     USHAContext m_ctx;
     CMaaString m_Hash;
public:
     CSHACacl(SHAversion HashNo = SHA256);
     ~CSHACacl();
     void Update(const void * ptr, unsigned int Len);
     int HashSize() noexcept;
     void GetHash(void * ptr, int bits = 0, int bitcount = 0); // HashSize() bytes;
     CMaaString GetHash(int bits = 0, int bitcount = 0); // HashSize() bytes string
     CMaaString GetTextHash(int bits = 0, int bitcount = 0); // 16 bytes string
     static bool ChkPassword(CMaaString password, CMaaString Hash);
     static CMaaString HashPassword(CMaaString password, SHAversion HashNo = SHA256);
};

#if 0
int test_sha()
{
    CMaaString fff = CMaaFile("main.cpp", CMaaFile::eR_SrSw, eNoExcept).Read();
    CSHACacl c;
    c.Update(fff, fff.Length());
    CMaaString h = c.GetTextHash();
    __utf8_printf("hash of main.cpp is %S\n", &h);
    h = c.GetTextHash();
    __utf8_printf("hash of main.cpp is %S\n", &h);
    CMaaString p = "abcff";
    h = CSHACacl::HashPassword(p);
    __utf8_printf("HashPassword of %S is %S\n", &p, &h);
    __utf8_printf("test ChkPassword(%S,%S): %s\n", &p, &p, CSHACacl::ChkPassword(p, p) ? "true" : "false");
    __utf8_printf("test ChkPassword(%S,%S): %s\n", &p, &h, CSHACacl::ChkPassword(p, h) ? "true" : "false");
    __utf8_printf("test ChkPassword(%SX,%S): %s\n", &p, &p, CSHACacl::ChkPassword(p + "X", p) ? "true" : "false");
    __utf8_printf("test ChkPassword(,): %s\n", CSHACacl::ChkPassword("", "") ? "true" : "false");
    __utf8_printf("test ChkPassword(,\\0): %s\n", CSHACacl::ChkPassword("", CMaaString("", 1)) ? "true" : "false");
    __utf8_printf("test ChkPassword(\\0,\\0): %s\n", CSHACacl::ChkPassword(CMaaString("", 1), CMaaString("", 1)) ? "true" : "false");
    p += "X";
    __utf8_printf("test ChkPassword(%S,%S): %s\n", &p, &h, CSHACacl::ChkPassword(p, h) ? "true" : "false");
    return 0;
}
#endif