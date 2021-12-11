#include <openssl/pkcs7.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <string.h>

// Func: 读取证书文件到X509
X509 *fileio_read_cert(const char *filename)
{
    X509 *cert = NULL;
    BIO *bio;

    bio = BIO_new_file(filename, "r");
    if (!bio)
        goto out;

    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);

out:
    BIO_free_all(bio);
    if (!cert)
    {
        fprintf(stderr, "Can't load certificate from file '%s'\n",
                filename);
        ERR_print_errors_fp(stderr);
    }
    return cert;
}

// Func: 读取PEM私钥文件到EVP_PKEY
EVP_PKEY *fileio_read_pkey(const char *filename)
{
    EVP_PKEY *key = NULL;
    BIO *bio;

    bio = BIO_new_file(filename, "r");
    if (!bio)
        goto out;

    key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);

out:
    BIO_free_all(bio);
    if (!key)
    {
        fprintf(stderr, "Can't load key from file '%s'\n", filename);
        ERR_print_errors_fp(stderr);
    }
    return key;
}

// Func: 打印PKCS7_SIGNER_INFO信息
void print_p7sign_si(PKCS7_SIGNER_INFO *si)
{
    //version
    printf("version:%ld\n", ASN1_INTEGER_get(si->version));
    //issuer
    X509_NAME_print_ex_fp(stdout, si->issuer_and_serial->issuer, 0, XN_FLAG_ONELINE);
    //searial
    BIGNUM *bnser = ASN1_INTEGER_to_BN(si->issuer_and_serial->serial, NULL);
    char *asciiHex = BN_bn2hex(bnser);
    printf("\nserial:%s\n", asciiHex);

    //digest_alg
    char digest_alg[20];
    OBJ_obj2txt(digest_alg, sizeof(digest_alg), si->digest_alg->algorithm, 0);
    printf("digest_alg:%s\n", digest_alg);

    //auth_attr
    printf("auth_attr num:%d\n", sk_X509_ATTRIBUTE_num(si->auth_attr));
    ASN1_TYPE *attr_type;
    void *attrData;
    char data[256] = {0};
    X509_ATTRIBUTE *attr;
    for (int i = 0; i < sk_X509_ATTRIBUTE_num(si->auth_attr); i++)
    {
        attr = sk_X509_ATTRIBUTE_value(si->auth_attr, i);
        printf("  attr[%d] num:%d\n", i, X509_ATTRIBUTE_count(attr));
        for (int j = 0; j < X509_ATTRIBUTE_count(attr); j++)
        {
            attr_type = X509_ATTRIBUTE_get0_type(attr, j);
            printf("    attr_type[%d]:%d\n", j, attr_type->type);
            attrData = X509_ATTRIBUTE_get0_data(attr, j, attr_type->type, NULL);

            switch (attr_type->type)
            {
            case V_ASN1_OBJECT:
                OBJ_obj2txt(data, sizeof(data), (ASN1_OBJECT *)attrData, 0);
            case V_ASN1_OCTET_STRING:;
                ASN1_OCTET_STRING *octet_str = (ASN1_OCTET_STRING *)attrData;
                memcpy(data, octet_str->data, strlen(octet_str->data));
            case V_ASN1_UTCTIME:;
                BIO *b = BIO_new(BIO_s_mem());
                ASN1_UTCTIME_print(b, (ASN1_UTCTIME *)attrData);
                BIO_read(b,data,256);
                BIO_free(b);
            }

            printf("    auth_attr[%d][%d]:%s\n", i, j, data);
            memset(data, 0, sizeof(data));
            attrData = NULL;
            attr_type = NULL;
        }
        attr = NULL;
    }

    //digest_enc_alg
    char digest_enc_alg[20];
    OBJ_obj2txt(digest_enc_alg, sizeof(digest_enc_alg), si->digest_enc_alg->algorithm, 0);
    printf("digest_enc_alg:%s\n", digest_enc_alg);

    //enc_digest
    printf("enc_digest len:%d\n", si->enc_digest->length);

    // unauth_attr
    printf("unauth_attr num:%d\n", X509_ATTRIBUTE_count(si->unauth_attr));

    //pkey (maybe prikey or pubkey..., both ok. )
    RSA *rsa = EVP_PKEY_get1_RSA(si->pkey);
    // RSA_print_fp(stdout, rsa, 4);
}

int main()
{
    X509 *cert = fileio_read_cert("./root.crt");
    if (!cert)
        return EXIT_FAILURE;

    EVP_PKEY *pkey = X509_get_pubkey(cert);
    // EVP_PKEY *pkey = fileio_read_pkey("./root.key");
    if (!pkey)
        return EXIT_FAILURE;

    const EVP_MD *md = EVP_get_digestbyname("SHA256");

    PKCS7 *p7 = PKCS7_new();
    PKCS7_set_type(p7, NID_pkcs7_signed);
    PKCS7_SIGNER_INFO *si = PKCS7_sign_add_signer(p7, cert, pkey, md, PKCS7_BINARY); //no add cert chain
    if (!si)
    {
        fprintf(stderr, "error in key/certificate chain\n");
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }
    /* print PKCS7_SIGNER_INFO */
    print_p7sign_si(si);

    // PKCS7_content_new(p7, NID_pkcs7_data);
    // PKCS7_set_detached(p7, 0); //分离签名
    // BIO *p7bio = PKCS7_dataInit(p7, NULL);
    // BIO_write(p7bio, "How are you!", strlen("How are you!"));
    // PKCS7_dataFinal(p7, p7bio);

    // int derlen = i2d_PKCS7(p7, NULL);
    // unsigned char *dertmp = malloc(derlen);
    // i2d_PKCS7(p7, &dertmp);
    // print_p7sign_si(si);

    // PKCS7_free(p7);
    // BIO_free(p7bio);

    // PKCS7 *p71 = d2i_PKCS7(NULL, &dertmp, derlen);
    // if (!p71)
    // {
    //     fprintf(stderr, "Unable to parse signature data\n");
    //     ERR_print_errors_fp(stderr);
    //     return EXIT_FAILURE;
    // }
    // BIO *p7bio1 = PKCS7_dataDecode(p71, NULL, NULL, NULL); //org data
    // char *src;
    // int srcLen;
    // srcLen = BIO_read(p7bio1, src, 1024);
    // printf("src:%s\n", src);
    // STACK_OF(PKCS7_SIGNER_INFO) *sk = PKCS7_get_signer_info(p71);
    // int signCount = sk_PKCS7_SIGNER_INFO_num(sk);
    // for (int i = 0; i < signCount; i++)
    // {
    //     PKCS7_SIGNER_INFO *signInfo = sk_PKCS7_SIGNER_INFO_value(sk, i);
    //     X509 *cert = PKCS7_cert_from_signer_info(p71, signInfo);
    //     if (PKCS7_signatureVerify(p7bio1, p71, signInfo, cert) != 1)
    //     {
    //         printf("signatureVerify Err\n");
    //     }
    // }
}