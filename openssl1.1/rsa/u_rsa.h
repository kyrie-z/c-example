#ifndef U_RSA_H
#define U_RSA_H

//私钥签名，公钥验证
int public_key_verify(unsigned char *signed_data, int data_len, unsigned char *key, unsigned char *data);
int private_key_sign(unsigned char *data, int data_len, unsigned char *key, unsigned char *signed_data);

//公钥加密，私钥解密
int public_key_encrypt(unsigned char *data, int data_len, unsigned char *key, unsigned char *enc_data);
int public_key_decrypt(unsigned char *enc_data, int data_len, unsigned char *key, unsigned char *data);

#endif
