#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/x509.h>


typedef unsigned char uchar;
typedef unsigned long ulong;

struct X509_name_entry_st {
    ASN1_OBJECT *object;        /* AttributeType */
    ASN1_STRING *value;         /* AttributeValue */
    int set;                    /* index of RDNSequence for this entry */
    int size;                   /* temp variable */
};
struct X509_name_st {
    STACK_OF(X509_NAME_ENTRY) *entries; /* DN components */
    int modified;               /* true if 'bytes' needs to be built */
    BUF_MEM *bytes;             /* cached encoding: cannot be NULL */
    /* canonical encoding used for rapid Name comparison */
    unsigned char *canon_enc;
    int canon_enclen;
} /* X509_NAME */ ;


void X509Verify()
{
    FILE *fp;
    //获取根证书
    fp = fopen("root.cert", "rb");
    uchar derRootCert[4096];
    ulong derRootCertLen;
    derRootCertLen = fread(derRootCert, 1, 4096, fp);
    fclose(fp);

    //读取CRL文件
    fp = fopen("crl.crl", "rb");
    uchar derCrl[4096];
    ulong derCrlLen;
    derCrlLen = fread(derCrl, 1, 4096, fp);
    fclose(fp);

    //读取待验证的用户证书
    fp = fopen("x.cer", "rb");
    uchar derUsrCert[4096]; // DER证书buff
    ulong derUsrCertLen;   //证书长度
    derUsrCertLen = fread(derUsrCert, 1, 4096, fp);
    fclose(fp);

    //DER编码的根证书转化为X509结构体
    X509 *rootCert = NULL; //x509证书结构体，保持根证书
    uchar *pTmp = derRootCert;
    rootCert = d2i_X509(NULL, (const uchar**)&pTmp, derRootCertLen); 

    //DER编码的用户证书转化为X509结构体
    X509 *usrCert = NULL; //x509证书结构体，保持用户证书
    pTmp = derUsrCert;
    usrCert = d2i_X509(NULL, (const uchar**)&pTmp, derUsrCertLen);

    //DER编码的CRL转化为X509结构体
    X509_CRL *crt = NULL;
    pTmp = derCrl;
    crt = d2i_X509_CRL(NULL, (const uchar**)&pTmp, derCrlLen);

    //新建证书存储区
    X509_STORE *rootCertStore = X509_STORE_new();
    //添加根证书到证书存储区
    X509_STORE_add_cert(rootCertStore, rootCert);
    //设置检查CRL标志位，如果设置此标志位，则检查CRL
    X509_STORE_set_flags(rootCertStore, X509_V_FLAG_CRL_CHECK);
    //添加CRL到证书存储区
    X509_STORE_add_crl(rootCertStore, crt);
    //新建证书存储区句柄
    X509_STORE_CTX *ctx = X509_STORE_CTX_new(); 

    //初始化根证书存储区、用户证书
    STACK_OF(X509) *caCertStack = NULL;
    X509_STORE_CTX_init(ctx, rootCertStore, usrCert, caCertStack);
    //验证用户证书
    int ret = X509_verify_cert(ctx);
    if (ret == 1)
    {
        printf("验证成功！！\n");
    }

    //释放内存
    X509_free(rootCert);
    X509_free(usrCert);
    X509_STORE_CTX_cleanup(ctx);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(rootCertStore);

    return;
}

void GetX509Info()
{

    //读取待验证的用户证书
    FILE *fp = fopen("file.cer", "rb");
    uchar derUsrCert[4096]; // DER证书buff
    ulong derUsrCertLen;   //证书长度
    derUsrCertLen = fread(derUsrCert, 1, 4096, fp);
    fclose(fp);

    
    //DER编码的用户证书转化为X509结构体
    X509 *usrCert = NULL; //x509证书结构体，保持用户证书
    uchar *pTmp = derUsrCert;
    usrCert = d2i_X509(NULL, (const uchar**)&pTmp, derUsrCertLen);

    //获取版本号
    long version = X509_get_version(usrCert);
    printf("[版本]: %ld\n", version);

    //获取SN
    ASN1_INTEGER *serial = X509_get_serialNumber(usrCert);
    int i;
    printf("[序列号]: ");
    for (i = 0; i < serial->length; i++)
    {
        printf("%02x", serial->data[i]);
    }
    printf("\n");

    //获取证书颁发者信息
    X509_NAME *issuer = X509_get_issuer_name(usrCert);
    int item = sk_X509_NAME_ENTRY_num(issuer->entries);

    uchar msgInfo[1024];
    int msgInfoLen;
    X509_NAME_ENTRY *name_entry = NULL;
    long nid; 
    
    for (i = 0; i < item; i++)
    {
        //获取第一个条目值
        name_entry = sk_X509_NAME_ENTRY_value(issuer->entries, i);
        //获取对象ID
        nid = OBJ_obj2nid(name_entry->object);
        //判断条目编码类型
#if 0
        if (name_entry->value->type == V_ASN1_UTF8STRING)
        {
            int nUtf8 = 2*name_entry->value->length;
            short *pUtf8 = malloc(nUtf8);
            memeset(pUtf8, 0, nUtf8);
            int rv = MultiByteToWideChar(CP_UTF8, 0, name_entry->value->data, name_entry->value->length, pUtf8, nUtf8);
            rv = WideCharToMultiByte(CP_ACP, 0, pUtf8, rv, msgInfo, nUtf8, NULL, NULL);

            free(pUtf8);
            pUtf8 = NULL;
            msgInfoLen = rv;
            msgInfo[msgInfoLen] = '\0';
        }
        else
#endif
        {
            msgInfoLen = name_entry->value->length;
            memcpy(msgInfo, name_entry->value->data, msgInfoLen);
            msgInfo[msgInfoLen] = '\0';
        }

        //根据NID打印信息
        switch(nid)
        {
            case NID_countryName:
                printf("[国家]: %s \n", msgInfo);
                break;
            case NID_stateOrProvinceName:
                printf("[省份]: %s \n", msgInfo);
                break;
            case NID_localityName:
                printf("[地区]: %s \n", msgInfo);
                break;
            case NID_organizationName:
                printf("[组织]: %s \n", msgInfo);
                break;
            case NID_organizationalUnitName:
                printf("[单位]: %s \n", msgInfo);
                break;
            case NID_commonName:
                printf("[通用名]: %s \n", msgInfo);
                break;
            case NID_pkcs9_emailAddress:
                printf("[Mail]: %s \n", msgInfo);
                break;
            default:
                break;
        }        
    }

    //获取证书主题
    X509_NAME *subject = X509_get_subject_name(usrCert);
    item = sk_X509_NAME_ENTRY_num(subject->entries);
    for (i = 0; i < item; i++)
    {
        //获取第一个条目值
        name_entry = sk_X509_NAME_ENTRY_value(subject->entries, i);
        //获取对象ID
        nid = OBJ_obj2nid(name_entry->object);
        msgInfoLen = name_entry->value->length;
        memcpy(msgInfo, name_entry->value->data, msgInfoLen);
        msgInfo[msgInfoLen] = '\0';

        //根据NID打印信息
        switch(nid)
        {
            case NID_countryName:
                printf("[国家]: %s \n", msgInfo);
                break;
            case NID_stateOrProvinceName:
                printf("[省份]: %s \n", msgInfo);
                break;
            case NID_localityName:
                printf("[地区]: %s \n", msgInfo);
                break;
            case NID_organizationName:
                printf("[组织]: %s \n", msgInfo);
                break;
            case NID_organizationalUnitName:
                printf("[单位]: %s \n", msgInfo);
                break;
            case NID_commonName:
                printf("[通用名]: %s \n", msgInfo);
                break;
            case NID_pkcs9_emailAddress:
                printf("[Mail]: %s \n", msgInfo);
                break;
            default:
                break;
        } 
    }

    //获取证书生效日期
    ASN1_TIME *time = X509_getm_notBefore(usrCert);
    printf("[生效日期]: %s \n", time->data);

    time = X509_getm_notAfter(usrCert);
    printf("[失效日期]: %s \n", time->data);

    //获取证书公钥
    EVP_PKEY *pubKey = X509_get_pubkey(usrCert);
    uchar derPubKey[1024];
    long derPubKeyLen;
    pTmp = derPubKey;
    derPubKeyLen = i2d_PublicKey(pubKey, &pTmp);
    printf("[公钥]: ");
    for (i = 0; i < derPubKeyLen; i++)
    {
        printf("%02x", derPubKey[i]);
    }
    printf("\n");

    X509_free(usrCert);

    return;
    
}

int main()
{
    GetX509Info();
    return 0;
}

