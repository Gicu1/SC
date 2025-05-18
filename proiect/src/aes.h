#ifndef AES_H
#define AES_H
#include <stdint.h>

uint32_t pkcs7_pad(uint8_t **buf, uint32_t len, uint32_t blocklen);
uint32_t pkcs7_unpad(uint8_t *buf, uint32_t len);
void AES_init_ctx(uint8_t *RoundKey, const uint8_t *Key);
void AES_ECB_encrypt(const uint8_t *input, const uint8_t *key, uint8_t *output);
void AES_ECB_decrypt(const uint8_t *input, const uint8_t *key, uint8_t *output);
void AES_CBC_encrypt_buffer(uint8_t *buffer, uint32_t length, const uint8_t *key, uint8_t *iv);
void AES_CBC_decrypt_buffer(uint8_t *buffer, uint32_t length, const uint8_t *key, uint8_t *iv);
void AES_CTR_xcrypt_buffer(uint8_t *buffer, uint32_t length, const uint8_t *key, uint8_t *nonce);
#endif
