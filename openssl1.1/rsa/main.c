
#include <openssl/rsa.h>
#include <openssl/pem.h>

int main() {
  RSA *r, *rf;          //公私钥信息
  int bits = 1024; //模数比特数
  int ret;
  unsigned long e = RSA_3; //公钥指数publicExponent
  BIGNUM *bne;
  BIO *b, *bf;
  unsigned char *prikey;
  unsigned char *out;
  int len;

  bne = BN_new();
  ret = BN_set_word(bne, e);
  r = RSA_new(); //生成RSA结构
  ret = RSA_generate_key_ex(r, bits, bne, NULL);
  if (ret != 1) {
    printf("RSA_generate_key_ex err\n");
    return -1;
  }
  RSA_print_fp(stdout, r, 4); //打印私钥信息 offset为终端输出偏移行数

  /* 公钥 PEM */
  bf = BIO_new_file("rsaPub.pem", "w");
  PEM_write_bio_RSAPublicKey(bf, r);
  BIO_free(bf);
  bf = BIO_new_file("rsaPub.pem", "r");
  rf = RSA_new();
  rf = PEM_read_bio_RSAPublicKey(bf, NULL, NULL, NULL);
  RSA_print_fp(stdout, rf, 8);
  RSA_free(rf);
  BIO_free(bf);


  /* 私钥 i2d */
  b = BIO_new(BIO_s_mem()); //生成一个 mem 类型的 BIO
  ret = i2d_RSAPrivateKey_bio(b, r);
  prikey = (unsigned char *)malloc(1024);
  len = BIO_read(b, prikey, 1024);
  BIO_free(b);
  printf("%s\n",prikey);
         
  //保存到文件中
  bf = BIO_new_file("rsaPri.der", "w");
  ret = i2d_RSAPrivateKey_bio(bf, r);
  BIO_free(bf);
  RSA_free(r);

  /* 读取私钥 d2i */
  b = BIO_new_file("rsaPri.key", r);
  r=RSA_new();
  out = (unsigned char *)malloc(1024);
  BIO_read(b, out , 1024);
  d2i_RSAPrivateKey(&r, &out, 1024);
  RSA_print_fp(stdout, r, 8);
  RSA_free(r);

}
