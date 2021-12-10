#include "u_rsa.h"
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>

int rsa_pubkey_encrypt(EVP_PKEY *key, const unsigned char *orig_data,
                       size_t orig_data_len, unsigned char **enc_data,
                       size_t *enc_data_len)
{
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
  if (NULL == ctx)
  {
    printf("ras_pubkey_encrypt failed to open ctx.\n");
    return -1;
  }

  if (EVP_PKEY_encrypt_init(ctx) <= 0)
  {
    printf("ras_pubkey_encrypt failed to EVP_PKEY_encrypt_init.\n");
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }
  EVP_PKEY_encrypt(ctx, NULL, enc_data_len, orig_data,
                   orig_data_len);
  *enc_data = OPENSSL_malloc(*enc_data_len);
  int ret = EVP_PKEY_encrypt(ctx, *enc_data, enc_data_len, orig_data,
                             orig_data_len);
  if (ret <= 0)
  {
    printf("ras_pubkey_encrypt failed to EVP_PKEY_encrypt.\n");
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  EVP_PKEY_CTX_free(ctx);

  return 0;
}

int rsa_prikey_decrypt(EVP_PKEY *key, const unsigned char *enc_data,
                       size_t enc_data_len, unsigned char **out_data, size_t *out_len)
{
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
  if (NULL == ctx)
  {
    printf("ras_prikey_decryptfailed to open ctx.\n");
    return -1;
  }

  if (EVP_PKEY_decrypt_init(ctx) <= 0)
  {
    printf("ras_prikey_decryptfailed to EVP_PKEY_decrypt_init.\n");
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }
  EVP_PKEY_CTX_set_rsa_padding(ctx, 1);
  EVP_PKEY_decrypt(ctx, NULL, out_len, enc_data,
                   enc_data_len);
  printf("malloc:%ld\n", *out_len);
  *out_data = OPENSSL_malloc(*out_len);
  if (EVP_PKEY_decrypt(ctx, *out_data, out_len, enc_data,
                       enc_data_len) <= 0)
  {
    printf("ras_prikey_decryptfailed to EVP_PKEY_decrypt.\n");
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  EVP_PKEY_CTX_free(ctx);
  return 0;
}

int main()
{
  generate_key_file();
  unsigned char *msg = (unsigned char *)"This is a plain txt";
  EVP_PKEY *prikey, *pubkey;
  unsigned char *enc_data, *out_data;
  size_t enc_len = 0;
  size_t out_len = 0;

  pubkey = read_pem_pubkey("pubkey.pem");
  prikey = read_pem_prikey("prikey.pem");
  printf("msglen:%ld\n", strlen((char *)msg));

  /* 公钥加密 */
  rsa_pubkey_encrypt(pubkey, msg, strlen((char *)msg), &enc_data, &enc_len);
  printf("enc_len:%ld\n", enc_len);
  BIO_dump_fp(stdout, (char *)enc_data, 128);

  /* 私钥加密 */
  rsa_prikey_decrypt(prikey, enc_data, enc_len, &out_data, &out_len);
  printf("%ld\n", out_len);
  printf("strlen(out_data):%ld\n", strlen((char *)out_data));
  printf("dencrypt:%s\n", out_data);

  OPENSSL_free(enc_data);
  OPENSSL_free(out_data);
  EVP_PKEY_free(prikey);
  EVP_PKEY_free(pubkey);
  return 0;
}
