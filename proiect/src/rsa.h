#ifndef RSA_H
#define RSA_H
#include <stdint.h>
#include <gmp.h>

typedef struct
{
    mpz_t n, e, d;
} RSAKey;

int RSA_load_key(RSAKey *k, const char *path, int is_private);
void RSA_encrypt(const RSAKey *k,
                 const uint8_t *in, uint32_t in_len,
                 uint8_t *out, uint32_t *out_len);
void RSA_decrypt(const RSAKey *k,
                 const uint8_t *in, uint32_t in_len,
                 uint8_t *out, uint32_t *out_len);

uint32_t RSA_mod_bytes(const RSAKey *k); /* convenience */

#endif
