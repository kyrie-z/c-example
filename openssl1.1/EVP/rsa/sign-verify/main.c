#include "u_rsa.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <string.h>

// Func: 读取PEM RSA公钥文件
EVP_PKEY *read_pem_pubkey(const char *keyfile) {
  EVP_PKEY *pkey = EVP_PKEY_new();
  BIO *bf;
  RSA *rsa = NULL;

  bf = BIO_new_file(keyfile, "r");
  rsa = PEM_read_bio_RSAPublicKey(bf, NULL, NULL, NULL);
  EVP_PKEY_set1_RSA(pkey, rsa);

  BIO_free(bf);
  // RSA_free(rsa);
  return pkey;
}

// Func: 读取PEM RSA私钥文件
EVP_PKEY *read_pem_prikey(const char *keyfile) {
  EVP_PKEY *pkey = EVP_PKEY_new();
  BIO *bf;
  RSA *rsa = NULL;

  bf = BIO_new_file(keyfile, "r");
  rsa = PEM_read_bio_RSAPrivateKey(bf, NULL, NULL, NULL);
  // RSA_print_fp(stdout, rsa, 2);
  EVP_PKEY_set1_RSA(pkey, rsa);

  BIO_free(bf);
  // RSA_free(rsa);
  return pkey;
}

// Func: EVP私钥签名
int EVP_digest_sign_it(const unsigned char *msg, EVP_PKEY *pkey,
                       unsigned char **sig_data, int *slen) {

  EVP_MD_CTX *mdctx = NULL;
  *sig_data = NULL;
  *slen = 0;

  /* Create the Message Digest Context */
  if (!(mdctx = EVP_MD_CTX_create()))
    goto err;

  /* Initialise the DigestSign operation - SHA-256 has been selected as the
   * message digest function in this example */
  if (1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey))
    goto err;

  /* Call update with the message */
  if (1 != EVP_DigestSignUpdate(mdctx, msg, strlen((const char *)msg)))
    goto err;

  /* Finalise the DigestSign operation */
  /* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the
   * length of the signature. Length is returned in slen */
  if (1 != EVP_DigestSignFinal(mdctx, NULL, slen))
    goto err;
  /* Allocate memory for the signature based on size in slen */
  unsigned char *tmp;
  if (!(tmp = OPENSSL_malloc(sizeof(unsigned char) * (*slen)))) {
    printf("malloc failed\n");
    goto err;
  }
  /* Obtain the signature */
  if ( 1 != EVP_DigestSignFinal(mdctx, tmp, slen))
    goto err;
  *sig_data = tmp;
  EVP_MD_CTX_free(mdctx);
  return 0;
err:
  /* Do some error handling */
  printf("something error!!\n");
  EVP_MD_CTX_free(mdctx);
  return 1;
}

// Func: EVP公钥验证
int EVP_digest_verify_it(const unsigned char *msg, EVP_PKEY *pubkey,
                         const unsigned char *sig) {

  EVP_MD_CTX *mdctx = NULL;
  int slen=0;
  /* Create the Message Digest Context */
  if (!(mdctx = EVP_MD_CTX_create()))
    goto err;
  /* Initialize `key` with a public key */
  if (1 != EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pubkey))
    goto err;

  /* Initialize `key` with a public key */
  if (1 != EVP_DigestVerifyUpdate(mdctx, msg, strlen((const char *)msg)))
    goto err;

  slen = EVP_PKEY_size(pubkey);

  if (1 != EVP_DigestVerifyFinal(mdctx, sig, slen))
    goto err;

  EVP_MD_CTX_free(mdctx);
  return 0;
err:
  /* Do some error handling */
  printf("something error!!\n");
  EVP_MD_CTX_free(mdctx);
  return 1;
}

int main() {
  EVP_PKEY *pkey = NULL;
  generate_key_file();
  pkey = read_pem_prikey("prikey.pem");
  // printf("%d\n",EVP_PKEY_size(pkey));

  unsigned char *sig = NULL;
  unsigned char *msg =
      (unsigned char *)"The quick brown fox jumps over the lazy dog.";
  int slen;

  if (EVP_digest_sign_it(msg, pkey, &sig, &slen) != 0) {
    return 1;
  }
  printf("密文:\n");
  BIO_dump_fp(stdout, (const char *)sig, 128);



  printf("验证\n");
  EVP_PKEY *pubkey = NULL;
  pubkey = read_pem_pubkey("pubkey.pem");
  if (EVP_digest_verify_it(msg, pubkey, sig) == 0) {
    /* Success */
    printf("verify succes!\n");
  }

  EVP_PKEY_free(pkey);
  EVP_PKEY_free(pubkey);
  free(sig);
  return 0;
}
