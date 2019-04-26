#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/aes.h>


typedef unsigned char uchar;

/*使用openssl提供的API实现*/
int aes_encrypt_api()
{
    uchar userkey[AES_BLOCK_SIZE];
    uchar *data = malloc(AES_BLOCK_SIZE*3);
    uchar *encrypt = malloc(AES_BLOCK_SIZE*6);
    uchar *plain = malloc(AES_BLOCK_SIZE*3);
    AES_KEY key;

    memset((void*)userkey, 'k', AES_BLOCK_SIZE);
    memset((void*)data, 'h', AES_BLOCK_SIZE*3);
    memset((void*)encrypt, 0, AES_BLOCK_SIZE*6);
    memset((void*)plain, 0, AES_BLOCK_SIZE*3);

    /*设置加密key及密钥长度*/
    AES_set_encrypt_key(userkey, AES_BLOCK_SIZE*8, &key);


    int len = 0;
    /*循环加密，每次只能加密AES_BLOCK_SIZE长度的数据*/
    while(len < AES_BLOCK_SIZE*3) {
        AES_encrypt(data+len, encrypt+len, &key);    
        len += AES_BLOCK_SIZE;
    }
    /*设置解密key及密钥长度*/    
    AES_set_decrypt_key(userkey, AES_BLOCK_SIZE*8, &key);

    len = 0;
    /*循环解密*/
    while(len < AES_BLOCK_SIZE*3) {
        AES_decrypt(encrypt+len, plain+len, &key);    
        len += AES_BLOCK_SIZE;
    }

    printf("encrypt: ");
    int i = 0;
    for(i = 0; i < AES_BLOCK_SIZE*6; i++){
        printf("%02x", encrypt[i]);
        if((i+1) % 32 == 0){
            printf("\n");    
        }
    }
    printf("\n");   
    printf("plain: %s\n", plain);

    return 0;
}


/*使用EVP框架*/
int aes_encrypt_evp()
{
    char userkey[EVP_MAX_KEY_LENGTH];
    char iv[EVP_MAX_IV_LENGTH];
    uchar *data = malloc(AES_BLOCK_SIZE*3);
    uchar *encrypt = malloc(AES_BLOCK_SIZE*6);
    uchar *plain = malloc(AES_BLOCK_SIZE*6);
    EVP_CIPHER_CTX *ctx;
    int ret;
    int tlen = 0;
    int mlen = 0;
    int flen = 0;

    memset((void*)userkey, 'k', EVP_MAX_KEY_LENGTH);
    memset((void*)iv, 'i', EVP_MAX_IV_LENGTH);
    memset((void*)data, 'h', AES_BLOCK_SIZE*3);
    memset((void*)encrypt, 0, AES_BLOCK_SIZE*6);
    memset((void*)plain, 0, AES_BLOCK_SIZE*6);

    /*初始化ctx*/
    ctx = EVP_CIPHER_CTX_new();

    /*指定加密算法及key和iv(此处IV没有用)*/
                      
    ret = EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, userkey, iv);
    if(ret != 1) {
        printf("EVP_EncryptInit_ex failed\n");
        exit(-1);
    }
    
    /*禁用padding功能*/
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    /*进行加密操作*/
    ret = EVP_EncryptUpdate(ctx, encrypt, &mlen, data, AES_BLOCK_SIZE*3);
    if(ret != 1) {
        printf("EVP_EncryptUpdate failed\n");
        exit(-1);
    }
    /*结束加密操作*/
    ret = EVP_EncryptFinal_ex(ctx, encrypt+mlen, &flen);
    if(ret != 1) {
        printf("EVP_EncryptFinal_ex failed\n");
        exit(-1);
    }

    tlen = mlen + flen;

    tlen = 0;
    mlen = 0;
    flen = 0;

    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_init(ctx);
     
    ret = EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, userkey, iv);
    if(ret != 1) {
        printf("EVP_DecryptInit_ex failed\n");
        exit(-1);
    }
    
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    ret = EVP_DecryptUpdate(ctx, plain, &mlen, encrypt, AES_BLOCK_SIZE*3);
    if(ret != 1) {
        printf("EVP_DecryptUpdate failed\n");
        exit(-1);
    }

    ret = EVP_DecryptFinal_ex(ctx, plain+mlen, &flen);
    if(ret != 1) {
        printf("EVP_DecryptFinal_ex failed\n");
        exit(-1);
    }
    /*对比解密后与原数据是否一致*/
    if(!memcmp(plain, data, AES_BLOCK_SIZE*3)) {
        printf("test success\n");    
    } else {
        printf("test failed\n");    
    }

    printf("encrypt: ");
    int i;
    for(i = 0; i < AES_BLOCK_SIZE*3+4; i ++){
        printf("%.2x ", encrypt[i]);    
        if((i+1)%32 == 0){
            printf("\n");
        }
    }
    printf("\n");

    return 0;
}

/*gcc AES.c -L/home/xwqiu/mygithub/opensslOutput/lib/ -lssl -lcrypto -Wall -g -o AES*/
int main()
{
    aes_encrypt_api();
    aes_encrypt_evp();
    
    return 0;
}


