#include "u_rsa.h"
#include <string.h>

int rsa_pubkey_encrypt(EVP_PKEY *key, const unsigned char *orig_data,
                       size_t orig_data_len, unsigned char *enc_data,
                       size_t *enc_data_len) {
  EVP_PKEY_CTX *ctx = NULL;
  OpenSSL_add_all_ciphers();

  ctx = EVP_PKEY_CTX_new(key, NULL);
  if (NULL == ctx) {
    printf("ras_pubkey_encrypt failed to open ctx.\n");
    EVP_PKEY_free(key);
    return -1;
  }

  if (EVP_PKEY_encrypt_init(ctx) <= 0) {
    printf("ras_pubkey_encrypt failed to EVP_PKEY_encrypt_init.\n");
    EVP_PKEY_free(key);
    return -1;
  }

  printf("orig_data_len:%d\n",orig_data_len);
  // unsigned char *tmp = malloc(sizeof(unsigned char *) * 256);
  unsigned char tmp[1024] ={0};
  int ret = 0;
  ret = EVP_PKEY_encrypt(ctx, tmp, enc_data_len, orig_data,
                       orig_data_len);
  if (ret <=0)
  {
    printf("ret:%d\n",ret);
    printf("ras_pubkey_encrypt failed to EVP_PKEY_encrypt.\n");
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);

    return -1;
  }
  printf("enc_data_len: %d\n",*enc_data_len);
  memcpy(enc_data,tmp,128);

  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(key);

  return 0;
}

int rsa_prikey_decrypt(EVP_PKEY *key, const unsigned char *enc_data,
                    size_t enc_data_len, unsigned char *orig_data,
                    size_t *orig_data_len ) {
  EVP_PKEY_CTX *ctx = NULL;
  OpenSSL_add_all_ciphers();

  ctx = EVP_PKEY_CTX_new(key, NULL);
  if (NULL == ctx) {
    printf("ras_prikey_decryptfailed to open ctx.\n");
    EVP_PKEY_free(key);
    return -1;
  }

  if (EVP_PKEY_decrypt_init(ctx) <= 0) {
    printf("ras_prikey_decryptfailed to EVP_PKEY_decrypt_init.\n");
    EVP_PKEY_free(key);
    return -1;
  }

  if (EVP_PKEY_decrypt(ctx, orig_data, *orig_data_len, enc_data,
                       enc_data_len) <= 0) {
    printf("ras_prikey_decryptfailed to EVP_PKEY_decrypt.\n");
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);

    return -1;
  }

  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(key);
  return 0;
}

int main() {
  generate_key_file();
  unsigned char *msg="This is a plain txt";
  EVP_PKEY *prikey, *pubkey;
  unsigned char enc_data[1024] ={0};
  size_t enc_len =0;
  int ret=0;
  pubkey = read_pem_pubkey("pubkey.pem");
  prikey = read_pem_prikey("prikey.pem");
 
  // ret=rsa_pubkey_encrypt(pubkey, msg, strlen(msg), enc_data, &enc_len);
   //加密
   EVP_PKEY_CTX *ectx;
   ectx = EVP_PKEY_CTX_new(pubkey, NULL);
   EVP_PKEY_encrypt_init(ectx);
   
   printf("%d\n",strlen(msg));
   ret = EVP_PKEY_encrypt(ectx, enc_data, &enc_len, msg, strlen(msg));

  if (ret != 1){
    printf("ret:%d\n",ret);
    printf("pubkey encrypt fail!!\n");
    return 1 ;
  }
  printf("enc_len:%d\n",enc_len);
  BIO_dump_fp(stdout, enc_data, 128);  








  EVP_PKEY_free(prikey);
  EVP_PKEY_free(pubkey);
  return 0;
}










