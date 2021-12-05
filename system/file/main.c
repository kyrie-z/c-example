#include <stdio.h>
#include <sys/xattr.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#define MAX_DIGEST_LENGTH 128
#define MD5_DIGEST_LENGTH 16

void craete_file(char *filename)
{
    FILE *fp = NULL;
    fp = fopen(filename, "w+");
    fprintf(fp, "this is a text for test.\n");
    fclose(fp);
}

int set_EA(char *key, unsigned char *value, int value_len)
{
    char *name = NULL;
    name = (char *)malloc(strlen("user.") + strlen(key));
    strcpy(name, "user.");
    strcat(name, key);
    printf("name:%s=%s\n", name, value);
    setxattr("text", name, value, value_len, 0);
    free(name);
    return 0;
}

void calc_file_hash(char *filename, const EVP_MD *type, unsigned char **out, int *out_len)
{
    BIO *fb = BIO_new_file(filename, "r");
    char *file_buf = (char *)malloc(1024);
    BIO_read(fb, file_buf, 1024);

    /* use openssl EVP calc hash */
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit(mdctx, type);
    EVP_DigestUpdate(mdctx, file_buf, strlen(file_buf));
    EVP_DigestFinal(mdctx, *out, out_len);
    // BIO_dump_fp(stdout, (char *)*out, *out_len);

    free(file_buf);
    EVP_MD_CTX_free(mdctx);
    BIO_free(fb);
}

const char hex_table[] = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

void to_hex2(unsigned char *s, int l, char *d)
{
    while (l--)
    {
        *(d++) = hex_table[*s >> 4];       // high 4 of byte
        *(d++) = hex_table[*(s++) & 0x0F]; // low 4 of byte
    }
}

int main(int argc, char *argv[])
{
    char *file = "text";
    craete_file(file);

    // get hash
    unsigned char *hash = (unsigned char *)malloc(MAX_DIGEST_LENGTH);
    memset(hash, 0, MAX_DIGEST_LENGTH);
    int hash_len = 0;
    calc_file_hash(file, EVP_md5(), &hash, &hash_len);

    // convert string to HEX array
    unsigned char hash_hex[MAX_DIGEST_LENGTH * 2] = {0};
    to_hex2(hash, hash_len, hash_hex);
    set_EA("hash", hash_hex, hash_len * 2);

    free(hash);
}