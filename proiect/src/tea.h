#ifndef TEA_H
#define TEA_H
#include <stdint.h>
void TEA_encrypt_block(uint32_t v[2], const uint32_t k[4]);
void TEA_decrypt_block(uint32_t v[2], const uint32_t k[4]);
void TEA_CBC_encrypt(uint8_t *data, uint32_t len, const uint32_t k[4], uint8_t iv[8]);
void TEA_CBC_decrypt(uint8_t *data, uint32_t len, const uint32_t k[4], uint8_t iv[8]);
#endif
