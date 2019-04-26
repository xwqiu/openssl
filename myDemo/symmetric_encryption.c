#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/bio.h>

typedef unsigned char uchar;


int SymmetricEncrypt(const EVP_CIPHER *cipher,            //加密函数
                                       ENGINE *impl,      //Engine
                                       const uchar * key, //加密密钥
                                       const uchar * iv,  //算法向量
                                       const uchar *text, //明文
                                       uchar *encrypt,    //密文
                                       int len)           //明文长度
{
    int outl = 0;
    int tempLen = 0;
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();

    int padding = (len % 128 == 0 ? 0 :(128 - len % 128));

    EVP_CIPHER_CTX_set_padding(ctx, padding);

    if (!EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, 1)){
        ERR_print_errors_fp( stderr );
        fprintf( stderr, "EVP_CipherInit_ex error\n" );
        return -1;
    }

    if (!EVP_CipherUpdate(ctx, encrypt, &outl, text, len)){
        ERR_print_errors_fp( stderr );
        fprintf( stderr, "EVP_CipherUpdate error\n" );
        return -1;
    }

    if (!EVP_CipherFinal_ex(ctx, encrypt+outl, &tempLen)){
        ERR_print_errors_fp( stderr );
        fprintf( stderr, "%d: EVP_CipherFinal_ex error\n",__LINE__);
        return -1;
    }
    outl += tempLen;

    return outl;
    
}

int SymmetricDecrypt(const EVP_CIPHER *cipher,            //加密函数
                                       ENGINE *impl,      //Engine
                                       const uchar * key, //加密密钥
                                       const uchar * iv,  //算法向量
                                       const uchar *text, //密文
                                       uchar *encrypt,    //明文
                                       int len)           //密文长度
{
   int outl = 0;
   int tempLen = 0;
   EVP_CIPHER_CTX *ctx;
   ctx = EVP_CIPHER_CTX_new();

   int padding = (len % 128 == 0 ? 0 : (128 - len % 128));

   EVP_CIPHER_CTX_set_padding(ctx, padding);

   if (!EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, 0)){
       ERR_print_errors_fp( stderr );
       fprintf( stderr, "EVP_CipherInit_ex error\n" );
       return -1;
   }

   if (!EVP_CipherUpdate(ctx, encrypt, &outl, text, len)){
       ERR_print_errors_fp( stderr );
       fprintf( stderr, "EVP_CipherUpdate error\n" );
       return -1;
   }

   if (!EVP_CipherFinal_ex(ctx, encrypt+outl, &tempLen)){
       //ERR_print_errors_fp( stderr );
       printf("EVP_CipherFinal_ex error!!\n" );
       return -1;
   }
   outl += tempLen;

   return outl;
   
}

struct buf_mem_st {
    size_t length;              /* current number of bytes */
    char *data;
    size_t max;                 /* size of buffer */
    unsigned long flags;
};

//base64加密
int Base64Encode(char *in_str, int in_len, char *out_str)
{
   BIO *b64, *bio;
   BUF_MEM *bptr = NULL;
   size_t size = 0;

   if (in_str == NULL || out_str == NULL)
       return -1;

   b64 = BIO_new(BIO_f_base64());
   bio = BIO_new(BIO_s_mem());
   bio = BIO_push(b64, bio);

   BIO_write(bio, in_str, in_len);
   BIO_flush(bio);

   BIO_get_mem_ptr(bio, &bptr);
   memcpy(out_str, bptr->data, bptr->length);
   out_str[bptr->length] = '\0';
   size = bptr->length;

   BIO_free_all(bio);
   return size;
}

//base64解密
int Base64Decode(char *in_str, int in_len, char *out_str)
{
    BIO *b64, *bio;
    BUF_MEM *bptr = NULL;
    int counts;
    int size = 0;
 
    if (in_str == NULL || out_str == NULL)
        return -1;
 
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
 
    bio = BIO_new_mem_buf(in_str, in_len);
    bio = BIO_push(b64, bio);
 
    size = BIO_read(bio, out_str, in_len);
    out_str[size] = '\0';
 
    BIO_free_all(bio);
    return size;
}


/*
加密算法
【NULL算法】 
函数：EVP_enc_null()该算法不作任何事情，也就是没有进行加密处理

【DES算法】 
函数：EVP_des_cbc(void), EVP_des_ecb(void), EVP_des_cfb(void), EVP_des_ofb(void) 
说明：分别是CBC方式、ECB方式、CFB方式以及OFB方式的DES算法

【使用两个密钥的3DES算法】 
函数：EVP_des_ede_cbc(void), EVP_des_ede(), EVP_des_ede_ofb(void),EVP_des_ede_cfb(void) 
说明：分别是CBC方式、ECB方式、CFB方式以及OFB方式的3DES算法，算法的第一个密钥和最后一个密钥相同，事实上就只需要两个密钥

【使用三个密钥的3DES算法】 
函数：EVP_des_ede3_cbc(void), EVP_des_ede3(), EVP_des_ede3_ofb(void), EVP_des_ede3_cfb(void) 
说明：分别是CBC方式、ECB方式、CFB方式以及OFB方式的3DES算法，算法的三个密钥都不相同

【DESX算法】 
函数：EVP_desx_cbc(void) 
说明：CBC方式DESX算法

【RC2算法】 
函数：EVP_rc2_cbc(void), EVP_rc2_ecb(void), EVP_rc2_cfb(void), EVP_rc2_ofb(void) 
说明：分别是CBC方式、ECB方式、CFB方式以及OFB方式的RC2算法，该算法的密钥长度是可变的，可以通过设置有效密钥长度或有效密钥位来设置参数来改变。缺省的是128位。

【定长的两种RC2算法】 
函数：EVP_rc2_40_cbc(void), EVP_rc2_64_cbc(void) 
说明：分别是40位和64位CBC模式的RC2算法。

【RC4算法】 
函数：EVP_rc4(void) 
说明：RC4流加密算法。该算法的密钥长度可以改变，缺省是128位。

【40位RC4算法】 
函数：EVP_rc4_40(void) 
说明：密钥长度40位的RC4流加密算法。该函数可以使用EVP_rc4和EVP_CIPHER_CTX_set_key_length函数代替

【RC5算法】 
函数：EVP_rc5_32_12_16_cbc(void), EVP_rc5_32_12_16_ecb(void), EVP_rc5_32_12_16_cfb(void), EVP_rc5_32_12_16_ofb(void) 
说明：分别是CBC方式、ECB方式、CFB方式以及OFB方式的RC5算法，该算法的密钥长度可以根据参数“number of rounds”（算法中一个数据块被加密的次数）来设置，缺省的是128位密钥，加密次数为12次。目前来说，由于RC5算法本身实现代码的限制，加密次数只能设置为8、12或16。

【IDEA算法】 
函数：EVP_idea_cbc()，EVP_idea_ecb(void), EVP_idea_cfb(void), EVP_idea_ofb(void) 
说明：分别是CBC方式、ECB方式、CFB方式以及OFB方式的IDEA算法。

【Blowfish算法】 
函数：EVP_bf_cbc(void), EVP_bf_ecb(void), EVP_bf_cfb(void), EVP_bf_ofb(void) 
说明：分别是CBC方式、ECB方式、CFB方式以及OFB方式的Blowfish算法，该算法的密钥长度是可变的

【CAST算法】 
函数：EVP_cast5_cbc(void), EVP_cast5_ecb(void), EVP_cast5_cfb(void), EVP_cast5_ofb(void) 
说明：分别是CBC方式、ECB方式、CFB方式以及OFB方式的CAST算法，该算法的密钥长度是可变的

【128位AES算法】 
函数：EVP_aes_128_ecb(void)，EVP_aes_128_cbc(void)，PEVP_aes_128_cfb(void)，EVP_aes_128_ofb(void) 
说明：分别是CBC方式、ECB方式、CFB方式以及OFB方式的128位AES算法

【192位AES算法】 
函数：EVP_aes_192_ecb(void)，EVP_aes_192_cbc(void)，PEVP_aes_192_cfb(void)，EVP_aes_192_ofb(void) 
说明：分别是CBC方式、ECB方式、CFB方式以及OFB方式的192位AES算法

【256位AES算法】 
函数：EVP_aes_256_ecb(void)，EVP_aes_256_cbc(void)，PEVP_aes_256_cfb(void)，EVP_aes_256_ofb(void) 
说明：分别是CBC方式、ECB方式、CFB方式以及OFB方式的256位AES算法

注： 这些加密算法函数调用时返回的都是对应EVP_CIPHER结构体指针
*/

/*实现功能：文件A->对称加密->BASE64编码->存入文件B->......文件B->BASE64解码->解密->存入文件C*/
int main(int argc, char *argv[])
{
    const EVP_CIPHER *cipher = EVP_aes_128_cbc();
    uchar iv[32];
    uchar key[32] = "1112"; //密钥
    uchar cKey[32];

    EVP_BytesToKey(cipher, EVP_sha1(), NULL, key, strlen(key), 1, cKey, iv);
    
    int ret;
    int clen;
    int flen;
    uchar inBuff[1024];
    uchar outBuff[1024];
    FILE *fpIn = fopen("AES.c", "rb");
    FILE *fpOut = fopen("en.txt", "wb");

    /*-----------------加密-------------------------*/
    while(1)
    {
        ret = fread(inBuff, 1, 1024, fpIn);
        if (ret <= 0)
            break;
        
        //加密
        clen = SymmetricEncrypt(cipher, NULL, cKey, iv, inBuff, outBuff, ret);
        
        flen = Base64Encode(inBuff, clen, outBuff);
        fwrite(outBuff, 1, flen, fpOut);
    }

    fclose(fpIn);
    fclose(fpOut);


    /*-----------------解密-------------------------*/
    fpIn = fopen("en.txt", "rb");
    fpOut = fopen("de.txt", "wb");

    uchar tempBuff[1024];
    
    while(1)
    {
        ret = fread(inBuff, 1, 1024, fpIn);
        if (ret <= 0)
            break;

        //解码
        flen = Base64Decode(inBuff, ret, outBuff);
        
        //解密
        clen = SymmetricDecrypt(cipher, NULL, cKey, iv, outBuff, tempBuff, flen);

        fwrite(tempBuff, 1, clen, fpOut);
        
    }

    fclose(fpIn);
    fclose(fpOut);
    
    return 0;

}
