#include <stdio.h>
#include <openssl/evp.h>

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

    //EVP_CIPHER_CTX_set_padding(ctx, 0);

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
                                       const uchar *text, //明文
                                       uchar *encrypt,    //密文
                                       int len)           //明文长度
{
   int outl = 0;
   int tempLen = 0;
   EVP_CIPHER_CTX *ctx;
   ctx = EVP_CIPHER_CTX_new();

   //EVP_CIPHER_CTX_set_padding(ctx, 0);

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
       printf("password error!!\n" );
       return -1;
   }
   outl += tempLen;

   return outl;
   
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
int EncryptString()
{
    int i ;
    int cipherNo = -1;
    const EVP_CIPHER *cipher = EVP_bf_cbc();
    uchar iv[] = "\x00\x00\x00\x00\x00\x00\x00\x00";
    uchar key[64] = "1112"; //密钥
    uchar text[] = "hello world"; //明文
    uchar encrypt[1024];
    uchar plain[1024] = {0};
    int outl;


    //加密
    int clen = SymmetricEncrypt(cipher, NULL, key, iv, text, encrypt, strlen(text));
    for (i = 0; i < clen ; i++){
        printf("%02x", encrypt[i]);
    }
    printf("\n");

    
    //解密
    SymmetricDecrypt(cipher, NULL, key, iv, encrypt, plain, clen);
    printf("%s \n", plain);

    return 0;

}

int EncryptFile()
{
    FILE *fpIn;
    FILE *fpOut;
    int inl;
    uchar in[1024];
    uchar out[1024];
    uchar key[EVP_MAX_KEY_LENGTH] = "1112";
    uchar iv[] = "\x00\x00\x00\x00\x00\x00\x00\x00";

    //打开待加密文件
    fpIn = fopen("/home/xwqiu/mygithub/openssl/myDemo/ssl.txt","rb");

    //打开保存密文的文件
    fpOut = fopen("/home/xwqiu/mygithub/openssl/myDemo/ssl_en.txt","wb");


    for(;;)
    {
        inl = fread(in, 1, 1024, fpIn);
        if (inl <= 0)
            break;

        int outl = SymmetricEncrypt(EVP_des_cbc(), NULL, key, iv, in, out, inl);
        
        fwrite(out, 1, outl, fpOut);

    }

    fclose(fpIn);
    fclose(fpOut);
    printf("加密完成\n");

    return 0;
    
}

int DecryptFile()
{
    FILE *fpIn;
    FILE *fpOut;
    int inl;
    uchar in[1024];
    uchar out[1024];
    uchar key[EVP_MAX_KEY_LENGTH];
    //uchar key[EVP_MAX_KEY_LENGTH] = "1112";
    uchar iv[] = "\x00\x00\x00\x00\x00\x00\x00\x00";

    printf("解密密码：");
    scanf("%s", key);

    //打开待加密文件
    fpIn = fopen("/home/xwqiu/mygithub/openssl/myDemo/ssl_en.txt","rb");

    //打开保存密文的文件
    fpOut = fopen("/home/xwqiu/mygithub/openssl/myDemo/ssl_de.txt","wb");

    for(;;)
    {
        inl = fread(in, 1, 1024, fpIn);
        if (inl <= 0)
            break;

        int outl = SymmetricDecrypt(EVP_des_cbc(), NULL, key, iv, in, out, inl);

        if (outl == -1)
        {
            printf("解密失败\n");
            return 0;
        }
        fwrite(out, 1, outl, fpOut);
    }

    fclose(fpIn);
    fclose(fpOut);
    printf("解密完成\n");

    return 0;
}


int main()
{
    OpenSSL_add_all_algorithms();

    EncryptFile();
    DecryptFile();
    return 0;
}
