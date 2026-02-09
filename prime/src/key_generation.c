#include "key_generation.h"
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>

static unsigned char *aes_encrypt_ecb(const unsigned char *plaintext, size_t plaintext_len,
                               const unsigned char *key, size_t *out_len);
static unsigned char *aes_decrypt_ecb(const unsigned char *ciphertext, size_t ciphertext_len,
                                      const unsigned char *key, size_t *out_len);
static unsigned char *generate_symmetric_key();
static unsigned char *rsa_encrypt(const unsigned char *data, size_t data_len, EVP_PKEY *pubkey, size_t *out_len);
static unsigned char *rsa_decrypt(const unsigned char *ciphertext, size_t ct_len,
                                  EVP_PKEY *private_key, size_t *out_len);
static char *hex_encode(const unsigned char *data, size_t len);
static unsigned char *hex_decode(const char *hexstr, size_t *out_len);

static char *hex_encode(const unsigned char *data, size_t len)
{
    char *hex = malloc(len * 2 + 1);
    if (!hex)
        return NULL;

    for (size_t i = 0; i < len; ++i)
    {
        sprintf(hex + i * 2, "%02x", data[i]);
    }
    hex[len * 2] = '\0';
    return hex;
}

static unsigned char *hex_decode(const char *hexstr, size_t *out_len)
{
    if (!hexstr || strlen(hexstr) % 2 != 0)
        return NULL;

    size_t len = strlen(hexstr) / 2;
    unsigned char *out = malloc(len);
    if (!out)
        return NULL;

    for (size_t i = 0; i < len; i++)
    {
        sscanf(hexstr + 2 * i, "%2hhx", &out[i]);
    }

    *out_len = len;
    return out;
}

static char *write_key_to_pem(EVP_PKEY *pkey, int is_public, const char *passphrase)
{
    if (!pkey)
        return NULL;

    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio)
        return NULL;

    int success = 0;
    if (is_public)
    {
        success = PEM_write_bio_PUBKEY(bio, pkey);
    }
    else if (passphrase)
    {
        success = PEM_write_bio_PrivateKey(bio, pkey, EVP_aes_256_cbc(),
                                           (unsigned char *)passphrase, strlen(passphrase), NULL, NULL);
    }
    else
    {
        success = PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);
    }

    if (!success)
    {
        BIO_free(bio);
        return NULL;
    }

    size_t len = BIO_pending(bio);
    char *pem = malloc(len + 1);
    if (!pem)
    {
        BIO_free(bio);
        return NULL;
    }

    BIO_read(bio, pem, len);
    pem[len] = '\0';
    BIO_free(bio);
    return pem;
}

// Generate an RSA key using EVP API
EVP_PKEY *generate_rsa_key(int bits)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); // Creates a context for rsa keygen

    if (!ctx)
    {
        fprintf(stderr, "Error: Failed to create EVP_PKEY_CTX\n");
        return NULL;
    }

    // Initialize the key generation context and set the key length
    if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0)
    {
        fprintf(stderr, "Error: RSA key generation initialization failed\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    // Generate the RSA key pair
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
    {
        fprintf(stderr, "Error: RSA key generation failed\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx); // Free the context after key generation
    return pkey;            // Return the generated key
}

char *get_public_key(EVP_PKEY *pkey)
{
    return write_key_to_pem(pkey, 1, NULL);
}

char *get_private_key(EVP_PKEY *pkey)
{
    return write_key_to_pem(pkey, 0, NULL);
}

// Free EVP_PKEY structure
void free_rsa_key(EVP_PKEY *pkey)
{
    if (pkey)
    {
        EVP_PKEY_free(pkey);
    }
}

// Write a key to a file
int write_key_to_file(const char *filename, const char *key)
{
    if (!filename || !key)
    {
        fprintf(stderr, "Error: Invalid filename or key\n");
        return -1;
    }

    FILE *file = fopen(filename, "w");
    if (!file)
    {
        perror("Error opening file for writing");
        return -1;
    }

    if (fprintf(file, "%s", key) < 0)
    {
        fprintf(stderr, "Error: Failed to write key to file\n");
        fclose(file);
        return -1;
    }

    fclose(file);
    return 0; // Success
}

Signature sign_buffer(const unsigned char *data, size_t data_len, EVP_PKEY *priv_key)
{
    Signature result = {NULL, 0};

    if (!data || !priv_key)
        return result;

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx)
    {
        perror("EVP_MD_CTX_new failed");
        return result;
    }

    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, priv_key) != 1 ||
        EVP_DigestSignUpdate(md_ctx, data, data_len) != 1 ||
        EVP_DigestSignFinal(md_ctx, NULL, &result.length) != 1)
    {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(md_ctx);
        return result;
    }

    result.signature = malloc(result.length);
    if (!result.signature)
    {
        perror("Memory allocation failed");
        EVP_MD_CTX_free(md_ctx);
        result.length = 0;
        return result;
    }

    if (EVP_DigestSignFinal(md_ctx, result.signature, &result.length) != 1)
    {
        ERR_print_errors_fp(stderr);
        free_signature(&result);
    }

    EVP_MD_CTX_free(md_ctx);
    return result;
}

int verify_buffer(const unsigned char *data, size_t data_len,
                  const unsigned char *signature, size_t sig_len,
                  EVP_PKEY *pub_key)
{
    if (!data || !signature || !pub_key)
        return 1;

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx)
    {
        perror("EVP_MD_CTX_new failed");
        return 1;
    }

    int result = 1;
    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pub_key) == 1 &&
        EVP_DigestVerifyUpdate(md_ctx, data, data_len) == 1 &&
        EVP_DigestVerifyFinal(md_ctx, signature, sig_len) == 1)
    {
        result = 0;
    }

    if (result != 0)
        printf("Signature is INVALID.\n");

    EVP_MD_CTX_free(md_ctx);
    return result;
}

// Free allocated memory for signature
void free_signature(Signature *sig)
{
    if (sig && sig->signature)
    {
        free(sig->signature);
        sig->signature = NULL;
        sig->length = 0;
    }
}

// Generate a random 256-bit AES key
static unsigned char *generate_symmetric_key()
{
    unsigned char *key = malloc(AES_KEYLEN);
    if (!key || RAND_bytes(key, AES_KEYLEN) != 1)
    {
        free(key);
        return NULL;
    }
    return key;
}

// AES-256-ECB encryption
static unsigned char *aes_encrypt_ecb(const unsigned char *plaintext, size_t plaintext_len,
                                      const unsigned char *key, size_t *out_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return NULL;

    size_t padded_len = ((plaintext_len + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    unsigned char *ciphertext = malloc(padded_len);
    if (!ciphertext)
    {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    int len = 0, total_len = 0;

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL))
        goto error;

    EVP_CIPHER_CTX_set_padding(ctx, 1);

    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        goto error;
    total_len += len;

    if (!EVP_EncryptFinal_ex(ctx, ciphertext + total_len, &len))
        goto error;
    total_len += len;

    *out_len = total_len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;

error:
    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);
    return NULL;
}

// AES-256-ECB decryption
static unsigned char *aes_decrypt_ecb(const unsigned char *ciphertext, size_t ciphertext_len,
                                      const unsigned char *key, size_t *out_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return NULL;

    unsigned char *plaintext = malloc(ciphertext_len);
    if (!plaintext)
    {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    int len = 0, total_len = 0;
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL))
        goto error;

    EVP_CIPHER_CTX_set_padding(ctx, 1);

    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        goto error;
    total_len = len;

    if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        goto error;
    total_len += len;

    EVP_CIPHER_CTX_free(ctx);
    *out_len = total_len;
    return plaintext;

error:
    EVP_CIPHER_CTX_free(ctx);
    free(plaintext);
    return NULL;
}

// RSA encrypt the AES key
static unsigned char *rsa_encrypt(const unsigned char *data, size_t data_len, EVP_PKEY *pubkey, size_t *out_len)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubkey, NULL);
    if (!ctx)
        return NULL;

    if (EVP_PKEY_encrypt_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_encrypt(ctx, NULL, out_len, data, data_len) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    unsigned char *out = malloc(*out_len);
    if (!out)
    {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_encrypt(ctx, out, out_len, data, data_len) <= 0)
    {
        free(out);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return out;
}

// RSA decrypt using private key
static unsigned char *rsa_decrypt(const unsigned char *ciphertext, size_t ct_len,
                                  EVP_PKEY *private_key, size_t *out_len)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(private_key, NULL);
    if (!ctx)
        return NULL;

    if (EVP_PKEY_decrypt_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_decrypt(ctx, NULL, out_len, ciphertext, ct_len) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    unsigned char *plaintext = malloc(*out_len);
    if (!plaintext)
    {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_decrypt(ctx, plaintext, out_len, ciphertext, ct_len) <= 0)
    {
        free(plaintext);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return plaintext;
}

// Hybrid encryption function
struct HybridEncrypted hybrid_encrypt(const unsigned char *data, size_t data_len, EVP_PKEY *rsa_pubkey)
{
    struct HybridEncrypted result = {0};

    // Generate AES key
    unsigned char *aes_key = generate_symmetric_key();
    if (!aes_key)
        return result;

    // Encrypt data with AES
    size_t ct_len = 0;
    unsigned char *ciphertext = aes_encrypt_ecb(data, data_len, aes_key, &ct_len);
    if (!ciphertext)
    {
        free(aes_key);
        return result;
    }

    // Encrypt AES key with RSA
    size_t enc_key_len = 0;
    unsigned char *enc_key = rsa_encrypt(aes_key, AES_KEYLEN, rsa_pubkey, &enc_key_len);
    free(aes_key);
    if (!enc_key)
    {
        free(ciphertext);
        return result;
    }

    // Hex encode both outputs
    result.ciphertext_hex = hex_encode(ciphertext, ct_len);
    result.enc_key_hex = hex_encode(enc_key, enc_key_len);

    free(ciphertext);
    free(enc_key);
    return result;
}

struct HybridDecryptionResult hybrid_decrypt(const char *ciphertext_hex,
                                             const char *enc_key_hex,
                                             EVP_PKEY *rsa_privkey)
{
    struct HybridDecryptionResult result = {0};

    size_t enc_key_len = 0, ct_len = 0;
    unsigned char *enc_key = hex_decode(enc_key_hex, &enc_key_len);
    unsigned char *ciphertext = hex_decode(ciphertext_hex, &ct_len);

    if (!enc_key || !ciphertext)
    {
        free(enc_key);
        free(ciphertext);
        return result;
    }

    // Decrypt AES key
    size_t aes_len = 0;
    unsigned char *aes_key = rsa_decrypt(enc_key, enc_key_len, rsa_privkey, &aes_len);
    if (!aes_key)
    {
        printf("[DEBUG] Failed to RSA decrypt AES key!\n");
    }
    free(enc_key);
    if (!aes_key || aes_len != 32)
    { // must be AES-256
        free(aes_key);
        free(ciphertext);
        return result;
    }

    // Decrypt ciphertext
    unsigned char *plaintext = aes_decrypt_ecb(ciphertext, ct_len, aes_key, &result.length);
    free(aes_key);
    free(ciphertext);
    result.plaintext = plaintext;
    return result;
}

// Concatenate into one string: enc_key_hex + ciphertext_hex
char *hybrid_pack(const struct HybridEncrypted *enc)
{
    size_t total_len = strlen(enc->enc_key_hex) + strlen(enc->ciphertext_hex) + 1;
    char *combined = malloc(total_len);
    if (!combined)
        return NULL;

    strcpy(combined, enc->enc_key_hex);
    strcat(combined, enc->ciphertext_hex);
    return combined;
}

void hybrid_unpack(const char *packed, char **out_enc_key_hex, char **out_ciphertext_hex)
{
    size_t rsa_hex_len = 384 * 2; // 3072-bit key = 384 bytes = 768 hex chars

    *out_enc_key_hex = strndup(packed, rsa_hex_len);
    *out_ciphertext_hex = strdup(packed + rsa_hex_len);
}

EVP_PKEY *load_public_key_from_pem(const char *pem_str)
{
    if (!pem_str)
    {
        fprintf(stderr, "Error: NULL PEM string provided.\n");
        return NULL;
    }

    BIO *bio = BIO_new_mem_buf((void *)pem_str, -1);
    if (!bio)
    {
        fprintf(stderr, "Error: Failed to create BIO for PEM string.\n");
        return NULL;
    }

    EVP_PKEY *pubkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!pubkey)
    {
        // Try as raw RSA public key
        BIO_free(bio);
        bio = BIO_new_mem_buf((void *)pem_str, -1);
        RSA *rsa = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
        if (rsa)
        {
            pubkey = EVP_PKEY_new();
            if (!pubkey || EVP_PKEY_assign_RSA(pubkey, rsa) != 1)
            {
                RSA_free(rsa);
                EVP_PKEY_free(pubkey);
                pubkey = NULL;
                fprintf(stderr, "Error: Failed to assign RSA to EVP_PKEY.\n");
            }
        }
        else
        {
            fprintf(stderr, "Error: Failed to read key in either PEM format.\n");
        }
    }

    BIO_free(bio);
    return pubkey;
}

// Load an EVP_PKEY from a PEM file (public or private)
EVP_PKEY *load_key_from_file(const char *filepath, int is_private)
{
    if (!filepath)
        return NULL;

    FILE *fp = fopen(filepath, "r");
    if (!fp)
    {
        fprintf(stderr, "Error opening key file: %s\n", filepath);
        return NULL;
    }

    EVP_PKEY *key = NULL;
    if (is_private)
        key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    else
        key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);

    fclose(fp);

    if (!key)
        ERR_print_errors_fp(stderr);

    return key;
}

EVP_PKEY *load_decrypted_key(const char *packed, EVP_PKEY *rsa_privkey)
{
    if (!packed || !rsa_privkey)
    {
        fprintf(stderr, "[ERROR] Missing packed key or TPM private key\n");
        return NULL;
    }

    char *enc_key_hex = NULL, *ciphertext_hex = NULL;
    hybrid_unpack(packed, &enc_key_hex, &ciphertext_hex);
    if (!enc_key_hex || !ciphertext_hex)
    {
        fprintf(stderr, "[ERROR] Failed to unpack hybrid key format\n");
        free(enc_key_hex);
        free(ciphertext_hex);
        return NULL;
    }

    struct HybridDecryptionResult dec = hybrid_decrypt(ciphertext_hex, enc_key_hex, rsa_privkey);
    free(enc_key_hex);
    free(ciphertext_hex);

    if (!dec.plaintext)
    {
        fprintf(stderr, "[ERROR] Hybrid decryption failed\n");
        ERR_print_errors_fp(stderr); // Dump OpenSSL errors
        return NULL;
    }

    BIO *bio = BIO_new_mem_buf(dec.plaintext, (int)dec.length);
    if (!bio)
    {
        fprintf(stderr, "[ERROR] Failed to create BIO for decrypted key\n");
        free(dec.plaintext);
        return NULL;
    }

    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!pkey)
    {
        fprintf(stderr, "[ERROR] PEM_read_bio_PrivateKey failed\n");
        ERR_print_errors_fp(stderr); // Again, useful for diagnosing PEM format problems
    }

    BIO_free(bio);
    free(dec.plaintext);
    return pkey;
}
