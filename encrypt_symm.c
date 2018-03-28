#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <sys/file.h>

typedef struct _cipher_params_t{
   unsigned char *key;
   unsigned char *iv;
   unsigned int  encrypt;
   const EVP_CIPHER *cipher_type;
}cipher_params_t;


int AES_256_KEY_SIZE = 256;
int AES_BLOCK_SIZE   = 64;
int main (int argc, char *argv[])
{
   FILE *f_input;
   FILE *f_enc;
   FILE *f_dec;

   if(argc != 2) {
      printf("Usage: %s need to pass in /path/to/file \n", argv[0]);
      return -1;
   }

   cipher_params_t *params = (cipher_params_t *)malloc(sizeof(cipher_params_t));
   if(!params) {
      //unable to allocate memory on heap
      fprintf(stderr, "ERROR: malloc error: %s\n", stderror(errno));
      return errno;
   }
   //key to use for encryption and decryption
   unsigned char key[AES_256_KEY_SIZE];
   
   //Initialization vector
   unsigned char iv[AES_BLOCK_SIZE];
   
   params->key = key;
   params->iv = iv;
   // indicate that we want to encrypt
   params->encrypt = 1;
   
   // set the cipher type you want for encryption-decryption
   params->cipher_type = EVP_aes256_cbc();
   
   
   return 0;
   
}
