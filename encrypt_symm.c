#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
//#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/aes.h>

#define AES_256_KEY_SIZE 32 /*32 byte key (256 bit key)*/
#define AES_BLOCK_SIZE  16 /*16 byte block size (128 bits)*/
#define BUFSIZE 1024

#define ERR_EVP_CIPHER_INIT -1 
#define ERR_EVP_CIPHER_UPDATE -2 
#define ERR_EVP_CIPHER_FINAL -3 
#define ERR_EVP_CTX_NEW -4 

typedef struct _cipher_params_t{
   unsigned char *key;
   unsigned char *iv;
   unsigned int  encrypt;
   const EVP_CIPHER *cipher_type;
}cipher_params_t;

typedef enum CIPHER_MODE {ECB, CBC, CFB, OFB, CTR} ciphermode_alias;
const static struct {
    ciphermode_alias mode;
    char *str;
} mapper[] = {{ECB, "ECB"}, {CBC,"CBC"}, {CFB, "CFB"}, {CTR, "CTR"}};

/*Function prototypes*/
ciphermode_alias str2enum (char *);
void file_encrypt_decrypt(cipher_params_t *params, FILE *infptr, FILE *ofptr);
void upstr (char *);
void cleanup(cipher_params_t *, FILE *, FILE *, int);

/*BEGIN MAIN*/
int main (int argc, char *argv[])
{
    FILE *f_input;
    FILE *f_enc;
    FILE *f_dec;
    FILE *f_enc_prop;
    FILE *f_dec_prop;
    unsigned char  copybuff[BUFSIZE];
    size_t n;
    int a; // for choosing cipher mode from user input at runtime
    char *usermode;

    if(argc != 3) {
      printf("Usage: %s need to pass in /path/to/file \n", argv[0]);
      return -1;
    }
    
    cipher_params_t *params = (cipher_params_t *)malloc(sizeof(cipher_params_t));
    if(!params) {
       //unable to allocate memory on heap
       fprintf(stderr, "ERROR: malloc error: %s\n", strerror(errno));
       return errno;
    }
    
    /*VALIDATE CIPHER MODE user input*/
    //printf("You entered: %s as the cipher mode.\n", argv[2]);
    usermode = argv[2];
        
    a = str2enum (usermode);
    printf("You entered: %s as the cipher mode and %d as enum.\n", usermode, a);    
    /*pass in mode as a runtime parameter and act accordingly*/
  

   switch (a) {
        case 0:/* ECB*/
            params->cipher_type = EVP_aes_256_ecb();
            break;
        case 1:/*CBC*/
            params->cipher_type = EVP_aes_256_cbc();
            break;
        case 2:/*CFB*/ 
            params->cipher_type = EVP_aes_256_cfb1();
            break;
        case 3:/* OFB*/
            params->cipher_type = EVP_aes_256_ofb();
            break;
        case 4:/*CTR*/
            params->cipher_type = EVP_aes_256_ctr();
            break;
        default:
            printf("NO cipher mode was interpreted,defaulting to CBC\n");
            params->cipher_type = EVP_aes_256_cbc();
            break;
    }
    
    //key to use for encryption and decryption
    unsigned char key[AES_256_KEY_SIZE];
   
    //Initialization vector
    unsigned char iv[AES_BLOCK_SIZE];
   
    /*Print error if PRNG does not seed with enough randomness*/
    if(!RAND_bytes(key, sizeof(key)) || !RAND_bytes(iv, sizeof(iv))) {
        /*OpenSSL reports a failure, act accordingly*/
        fprintf(stderr, "ERROR: RAND_bytes error: %s \n", strerror(errno));
        return errno;
    }
    
    params->key = key;
    params->iv = iv;
    
    // indicate that we want to encrypt
    params->encrypt = 1;
    // set the cipher type you want for encryption-decryption
    //params->cipher_type = EVP_aes_256_cbc();
   
    //Open the plain text file for reading in binary
    f_input = fopen(argv[1], "rb");
    if(!f_input) {
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
        return errno;
    }
    //open the encrypted file for reading in binary "rb" mode
    f_enc = fopen("encrypted_file", "wb");
    if(!f_enc) {
       fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno)); 
       return errno;
    }
    // Encrypt the input file
    file_encrypt_decrypt(params, f_input, f_enc);
    
    /*encryption is done, close the 2 files*/
    fclose(f_input);
    fclose(f_enc);
   
    /*DECRYPTION
    ****zero means we want to decrypt*********/
    params->encrypt = 0;
    
    f_input = fopen("encrypted_file", "rb");
    if(!f_input) {
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
        return errno;
    }
    /*TODO finish doing the the byte change in the propagation file*/
    f_enc_prop= fopen("prop_file", "wb");
    if(!f_enc_prop) {
       fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno)); 
       return errno;
    }
    while((n = fread(copybuff, 1, BUFSIZE, f_input)) != 0) {
        fwrite(copybuff, sizeof(unsigned char), n, f_enc_prop);
    }
    fclose(f_input);
    fclose(f_enc_prop);
    
    //reopen the f_enc_prop file in r+b mode
    f_enc_prop = fopen("prop_file", "r+b");
    if (!f_enc_prop) {
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
        return errno;
    }
    char somechar = 'e'; /*1 byte of data*/
    /*MODIFY a byte in the f_enc_prop file*/
    fseek(f_enc_prop, 5, SEEK_SET);
    fwrite(&somechar, sizeof(char), 1, f_enc_prop);
    fclose(f_enc_prop);
    /*Open the file dec_prop that will be compared to the original text file to see the encryption propagation error.*/
    
    f_enc_prop = fopen("prop_file", "rb");
    f_dec_prop = fopen("dec_prop", "wb");
    if(! f_enc_prop || ! f_dec_prop) {
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
        return errno;
    }
    
    file_encrypt_decrypt(params, f_enc_prop, f_dec_prop);
   
    /*TODO Close the files*/
    fclose(f_enc_prop);
    fclose(f_dec_prop);
    
    /************END of file byte modification************/
    f_input = fopen("encrypted_file", "rb");
    if(!f_input) {
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
        return errno;
    }
    // open and truncate file to zero length or create decrypted file for for writting
    f_dec = fopen("decrypted_file", "wb");
    if (!f_dec) {
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
        return errno;
    }    
    file_encrypt_decrypt(params, f_input, f_dec);
   
    fclose(f_input);
    fclose(f_dec);
   
    free(params);
    
    return 0;
}

/*BEGIN file_encrypt_decrypt function*/
void file_encrypt_decrypt(cipher_params_t* params, FILE* infptr, FILE* ofptr) {
    int cipher_block_size = EVP_CIPHER_block_size(params->cipher_type);
    unsigned char in_buf[BUFSIZE];
    unsigned char out_buf[BUFSIZE + cipher_block_size];

    
    int num_bytes_read;
    int out_len;
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    
    if(ctx == NULL) {
        fprintf(stderr, "ERROR: EVP_CIPHER_CTX_new failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL) );
        cleanup(params, infptr, ofptr, ERR_EVP_CTX_NEW);
    }
    /*Don't set the key or IV right away, as we need to check thier lengths*/
    if(!EVP_CipherInit_ex(ctx, params->cipher_type, NULL, NULL, NULL, params->encrypt)) {
        fprintf(stderr, "ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        cleanup(params, infptr, ofptr, ERR_EVP_CIPHER_INIT);
    }
    
    OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == AES_256_KEY_SIZE);
    OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx)  == AES_BLOCK_SIZE);
    
    /* Now we can set the key and IV */
    if(!EVP_CipherInit_ex(ctx, NULL, NULL, params->key, params->iv, params->encrypt)) {
        fprintf(stderr, "ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_cleanup(ctx);
        cleanup(params, infptr, ofptr, ERR_EVP_CIPHER_INIT);
    }
    
    //printf("\nKey: %s \t IV: %s\n", params->key, params->iv);
    
    while(1) {
        // read in data in blocks until EOF. Update the ciphering with each read.
        num_bytes_read = fread(in_buf, sizeof(unsigned char), BUFSIZE, infptr);
        if(ferror(infptr)){
            fprintf(stderr, "ERROR: fread error: %s\n", strerror(errno));
            EVP_CIPHER_CTX_cleanup(ctx);
            cleanup(params, infptr, ofptr, errno);
        }
        if(!EVP_CipherUpdate(ctx, out_buf, &out_len, in_buf, num_bytes_read)){
            fprintf(stderr, "ERROR: EVP_CipherUdate failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_cleanup(ctx);
            cleanup(params, infptr, ofptr, ERR_EVP_CIPHER_UPDATE);
        }
        
        fwrite(out_buf, sizeof(unsigned char), out_len, ofptr);
        if(ferror(ofptr)) {
            fprintf(stderr, "ERROR: fwrite error: %s\n", strerror(errno));
            EVP_CIPHER_CTX_cleanup(ctx);
            cleanup(params, infptr, ofptr, errno);
        }
        if(num_bytes_read < BUFSIZE) {
            //reached EOF
            break;
        }
    }

        /*Now cipher the final block and write it out to file*/
        if(!EVP_CipherFinal_ex(ctx, out_buf, &out_len)){
            fprintf(stderr, "ERROR: EVP_CipherFinal_ex failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_cleanup(ctx);
            cleanup(params, infptr, ofptr, ERR_EVP_CIPHER_FINAL);
        }        
        fwrite(out_buf, sizeof(unsigned char), out_len, ofptr);
        if(ferror(ofptr)) {
            fprintf(stderr, "ERROR: fwrite error: %s\n", strerror(errno));
            EVP_CIPHER_CTX_cleanup(ctx);
            cleanup(params, infptr, ofptr, errno);
        }
        EVP_CIPHER_CTX_cleanup(ctx);
}

void upstr (char *s) {
    char *p;
    for (p = s; *p != '\0'; p++){
        *p = (char) toupper(*p);
    }
}
ciphermode_alias str2enum (char *str) {
    
//     char *p = str;
//     while (*p != '\0') {
//         *p = (char)toupper(*p);
//          p++;
//     }
    upstr(str);
    printf("TOUPPER:\t %s\n", str);
    for (ciphermode_alias j = ECB; j <= CTR; (ciphermode_alias) (j++)) {
        //puts(mapper[1].str);
        if (strcmp(str, mapper[j].str) == 0){
            printf("in for loop string to enum\n");
            puts(str);
           // printf("here is the mode: %s\n", mapper[j].mode);
            return mapper[j].mode;
        }
       /* else 
            printf("You entered as the mode: %s   No such CIPHER_MODE!\n",upper);*/
    }
}

void cleanup(cipher_params_t *params, FILE *ifp, FILE *ofp, int rc) {
    free(params);
    fclose(ifp);
    fclose(ofp);
    exit(rc);
}
