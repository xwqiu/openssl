#include <stdio.h>
#include <openssl/evp.h>

typedef unsigned char uchar;


int AbstractAlgorithm(const EVP_MD *type,  
                           ENGINE *impl,      
                           const uchar *text, 
                           uchar *encrypt,   
                           int len)         
{
    int outl = 0;
    int tempLen = 0;
    EVP_MD_CTX *ctx;
    ctx = EVP_MD_CTX_new();

    if (!EVP_DigestInit_ex(ctx, type, NULL)){
        ERR_print_errors_fp( stderr );
        fprintf( stderr, "EVP_DigestInit_ex error\n" );
        return -1;
    }

    if (!EVP_DigestUpdate(ctx, text, len)){
        ERR_print_errors_fp( stderr );
        fprintf( stderr, "EVP_DigestUpdate error\n" );
        return -1;
    }

    if (!EVP_DigestFinal_ex(ctx, encrypt, &outl)){
        ERR_print_errors_fp( stderr );
        fprintf( stderr, "%d: EVP_DigestFinal_ex error\n",__LINE__);
        return -1;
    }

    return outl;    
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
    uchar msg[] = "hello this is";
    uchar encrypt[64];
    
    int len = AbstractAlgorithm(EVP_sha224(), NULL, msg, encrypt, strlen(msg));

    for (i = 0; i <  len; i++)
        printf("%02x", encrypt[i]);
    printf("\n");
}



