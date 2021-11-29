#include <openssl/rsa.h>
#include <openssl/pem.h>
#include "u_rsa.h"

#define RSA_KEY_LENGTH 1024


int save_pem_file(char *prikey_filename, char *pubkey_filename ,RSA *rsa){
  BIO *bf;

  bf = BIO_new_file(prikey_filename, "w");
  if (PEM_write_bio_RSAPrivateKey(bf, rsa, NULL, NULL, 0, NULL, NULL) != 1){
    printf("PEM_write_bio_RSAPrivateKey error!\n");
		return -1;
  }
  BIO_free(bf);

  bf = BIO_new_file(pubkey_filename, "w");
  PEM_write_bio_RSAPublicKey(bf, rsa);
  BIO_free(bf);
  
  return 0;
}


int generate_key_file(){
  int ret;
  RSA *rsa = RSA_new();
  unsigned long e = RSA_F4; //公钥指数，openssl提供两个常数。
  BIGNUM *bne = BN_new();
  BN_set_word(bne, e);
  ret = RSA_generate_key_ex(rsa, RSA_KEY_LENGTH, bne, NULL);
  if (ret != 1) {
    printf("RSA_generate_key_ex err\n");
    return -1;
  }
  save_pem_file("prikey.pem", "pubkey.pem", rsa);
  
  return 0;
}
