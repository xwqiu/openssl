#include <stdio.h>
#include <openssl/hmac.h>

typedef unsigned char uchar;


int HmacEncode(const void *key, const EVP_MD *md, uchar *data, uchar **output, int *outl)         
{
    HMAC_CTX *ctx;
    ctx = HMAC_CTX_new();

    HMAC_Init_ex(ctx, key, strlen(key), md, NULL);
    HMAC_Update(ctx, data, strlen(data));
    HMAC_Final(ctx, *output, outl);

    HMAC_CTX_free(ctx);
  
    return 0;  
}

/*
摘要算法
const EVP_MD *EVP_md_null(void);
const EVP_MD *EVP_md2(void);
const EVP_MD *EVP_md4(void);
const EVP_MD *EVP_md5(void);

const EVP_MD *EVP_sha(void);
const EVP_MD *EVP_sha1(void);
const EVP_MD *EVP_sha224(void);
const EVP_MD *EVP_sha256(void);
const EVP_MD *EVP_sha384(void);
const EVP_MD *EVP_sha512(void);       

const EVP_MD *EVP_dss(void);
const EVP_MD *EVP_dss1(void);
const EVP_MD *EVP_ecdsa(void);
const EVP_MD *EVP_mdc2(void);
const EVP_MD *EVP_ripemd160(void);
const EVP_MD *EVP_whirlpool(void);
*/
int main()
{
    int i;
    char key[] = "012345678";  
    char data[] = "hello world";  

    uchar *output = NULL;  
    int  outl = 0; 
    output = malloc(EVP_MAX_MD_SIZE);

    int ret = HmacEncode(key, EVP_sha1(), data, &output, &outl);  

    for(i = 0; i < outl; i++) {  
            printf("%02x", output[i]);  
    }  
    printf("\n");

    return 0;  
}




