#include <string.h>
#include <stdio.h>
#include <openssl/evp.h>

int main(){
  /* A 256 bit key */
  unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
  /* A 128 bit IV （向量长度应该和CBC单次加密块大小一致，为128bits）*/
  unsigned char *iv = (unsigned char *)"0123456789012345";
  /* Message to be encrypted */
  unsigned char *plaintext =(unsigned char *)"The quick brown fox jumps over the lazy dog.";
  unsigned char plainbuf[1024]={0}, outbuf[1024]={0};//保证密文buffer大于明文
  int ret;
  int datalen, tmplen, outlen;
  printf("明文: %s\n", plaintext);
  printf("明文长度: %ld\n",strlen((char *)plaintext));

  EVP_CIPHER_CTX *ctx= EVP_CIPHER_CTX_new();
  // AES 128bits CBC mode
  const EVP_CIPHER *cipher=EVP_aes_256_cbc();
 

  // 加密
  printf("\t-------加密-------\n");
  EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);
  EVP_EncryptUpdate(ctx, outbuf, &tmplen, plaintext, strlen((char *)plaintext));
  outlen = tmplen;
  ret = EVP_EncryptFinal_ex(ctx,outbuf+tmplen,&tmplen);//涉及padding填充,填充为16bytes的整数倍，若不凑整，会导致被加密的明文丢失。
  if (ret != 1) {
    printf("AES CBC encrypt fail!!\n");
  }
  outlen += tmplen;

  printf("密文:\n");
  BIO_dump_fp (stdout, (const char *)outbuf, outlen);
  printf("AES密文长度: %d\n",outlen);



  // 解密 (密文，密钥和初始向量)
  printf("\t-------解密-------\n");
  EVP_DecryptInit_ex(ctx,cipher,NULL,key,iv);
  EVP_DecryptUpdate(ctx, plainbuf, &tmplen, outbuf, outlen);
  datalen = tmplen;
  EVP_DecryptFinal_ex(ctx, plainbuf + tmplen, &tmplen);
  datalen += tmplen;

  plainbuf[datalen]='\0';
  printf("解密: %s\n", plainbuf);


  EVP_CIPHER_CTX_free(ctx);

}
















