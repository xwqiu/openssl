#include <stdio.h>
#include <openssl/evp.h>

typedef unsigned char uchar;

//生成密钥对
EVP_PKEY * RSA_get_key()
{
    RSA *r = RSA_new();

    int bits = 512;
    BIGNUM *e = BN_new();
    BN_set_word(e, 65537);

    EVP_PKEY *key;
    key = EVP_PKEY_new();

    RSA_generate_key_ex(r, bits, e, NULL);

    EVP_PKEY_set1_RSA(key, r);

    return key;
}

size_t AsymmetricEncrypt(EVP_PKEY *key,
                           const uchar *text,
                           uchar *encrypt,
                           size_t len)
{
    size_t outl = 0, i;
    EVP_PKEY_CTX *ctx;
    ctx = EVP_PKEY_CTX_new(key, NULL);

    EVP_PKEY_encrypt_init(ctx);
    
    EVP_PKEY_encrypt(ctx, encrypt, &outl, text, len);
     for(i = 0; i < outl; i++)
        printf("%02x ", encrypt[i]);
    printf("\n");

    return outl;
}

size_t AsymmetricDecrypt(EVP_PKEY *key,
                           const uchar *encrypt,
                           uchar *decrypt,
                           size_t len)
{
    size_t outl = 0;
    EVP_PKEY_CTX *ctx;
    ctx = EVP_PKEY_CTX_new(key, NULL);

    EVP_PKEY_decrypt_init(ctx);

    EVP_PKEY_decrypt(ctx, decrypt, &outl, encrypt, len);

    return outl;
}

/*

*/
int main(int argc, char *argv[])
{
     //生成密钥对
    RSA *r = RSA_new();
    int bits = 512;
    BIGNUM *e = BN_new();
    BN_set_word(e, 65537);
    RSA_generate_key_ex(r, bits, e, NULL);

    EVP_PKEY *key;
    key = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(key, r);

    //默认使用的是 RSA_PKCS1_PADDING，即这里最大加密块为64-11=53,大量数组需要分组处理
    char *srcStr = "01234567890123456789012345678901234567890123456789123";
    //char *srcStr = "hello world";
    int enclen = 0;
    char encData[1024] = {0};
    char decData[1024] = {0};
    int declen = 0;
    printf("src=%s\n",srcStr);
    
    
    //加密
    EVP_PKEY_CTX *ectx;
    ectx = EVP_PKEY_CTX_new(key, NULL);
    EVP_PKEY_encrypt_init(ectx);
    EVP_PKEY_encrypt(ectx, encData, &enclen, srcStr, strlen(srcStr));
    
    //解密
    EVP_PKEY_CTX *dctx;
    dctx = EVP_PKEY_CTX_new(key, NULL);
    EVP_PKEY_decrypt_init(dctx);
    EVP_PKEY_decrypt(dctx, decData, &declen, encData, enclen);
    printf("dec=%s\n",decData);

    EVP_PKEY_CTX_free(ectx);
    EVP_PKEY_CTX_free(dctx);

    
    EVP_PKEY_free(key);
    BN_free(e);
    RSA_free(r);

}

