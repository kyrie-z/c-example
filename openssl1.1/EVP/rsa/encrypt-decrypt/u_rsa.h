#ifndef U_RSA
#define U_RSA
#include <openssl/evp.h>

int generate_key_file();
EVP_PKEY *read_pem_pubkey(const char *keyfile);
EVP_PKEY *read_pem_prikey(const char *keyfile); 
#endif
