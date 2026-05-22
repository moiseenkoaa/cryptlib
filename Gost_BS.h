
struct gost_ctx;
class CGostBS
{
    gost_ctx * m_gc;
public:
    CGostBS();
    ~CGostBS();

    // Key - 32 bytes, Salt - 8 bytes, OutSalt - 8 bytes
    void Encrypt(const void * Key, const void * InData, size_t Size, const void * Salt, void * OutData, void *OutSalt = NULL);
    void Decrypt(const void * Key, const void * InData, size_t Size, const void * Salt, void * OutData, void *OutSalt = NULL);
};

#if 0
// GOST
// Брюс Шнайдер
// /*unsigned*/ char  k87[256],k65[256],k43[256],k21[256];

//typedef  unsigned   long   u4;
typedef  _dword   u4;
typedef  unsigned  char  byte;
typedef   struct
{
    u4   k[8];
    /*   Constant   s-boxes   --  set   up   in   gost_init().   */
    unsigned char  k87[256],k65[256],k43[256],k21[256];
}   gost_ctx;
/*   Note:     encrypt  and  decrypt   expect   full   blocks�padding  blocks   is
                        caller's   responsibility.      All  bulk  encryption   is  done   in
                        ECB  node by   these  calls.      Other  modes  may  be  added  easily
                        enough.
*/
void  gost_enc(gost_ctx *, u4 *, int);
void  gost_dec(gost_ctx *, u4 *, int);
void  gost_key(gost_ctx *, u4 *);
void  gost_init(gost_ctx *);
void  gost_destroy(gost_ctx *);

#endif
