#ifndef KEY_GENERATION_H
#define KEY_GENERATION_H

#include <stddef.h>
#include <openssl/evp.h>
#include "parser.h"

#define AES_KEYLEN 32 // AES-256
#define AES_BLOCK_SIZE 16

typedef struct
{
    unsigned char *signature;
    size_t length;
} Signature;

struct HybridEncrypted
{
    char *ciphertext_hex;
    char *enc_key_hex;
};

struct HybridDecryptionResult
{
    unsigned char *plaintext;
    size_t length;
};

struct HybridEncrypted hybrid_encrypt(const unsigned char *data, size_t data_len, EVP_PKEY *rsa_pubkey);
struct HybridDecryptionResult hybrid_decrypt(const char *ciphertext_hex, const char *enc_key_hex, EVP_PKEY *rsa_privkey);
char *hybrid_pack(const struct HybridEncrypted *enc);
void hybrid_unpack(const char *packed, char **out_enc_key_hex, char **out_ciphertext_hex);

EVP_PKEY *generate_rsa_key(int bits);

char *get_public_key(EVP_PKEY *pkey);
char *get_private_key(EVP_PKEY *pkey);
void free_rsa_key(EVP_PKEY *pkey);

int write_key_to_file(const char *filename, const char *key);

Signature sign_buffer(const unsigned char *data, size_t data_len, EVP_PKEY *priv_key);
int verify_buffer(const unsigned char *data, size_t data_len,
                  const unsigned char *signature, size_t sig_len,
                  EVP_PKEY *pub_key);
void free_signature(Signature *sig);

EVP_PKEY *load_public_key_from_pem(const char *pem_str);
EVP_PKEY *load_key_from_file(const char *filepath, int is_private);
EVP_PKEY *load_decrypted_key(const char *packed, EVP_PKEY *rsa_privkey);

#endif 