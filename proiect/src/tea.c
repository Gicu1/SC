#include "tea.h"
#include <string.h>

void TEA_encrypt_block(uint32_t v[2], const uint32_t k[4])
{
    uint32_t v0 = v[0], v1 = v[1], sum = 0, i;
    uint32_t delta = 0x9E3779B9;
    for (i = 0; i < 32; i++)
    {
        sum += delta;
        v0 += ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        v1 += ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
    }
    v[0] = v0;
    v[1] = v1;
}

void TEA_decrypt_block(uint32_t v[2], const uint32_t k[4])
{
    uint32_t v0 = v[0], v1 = v[1], i;
    uint32_t delta = 0x9E3779B9;
    uint32_t sum = delta * 32;
    for (i = 0; i < 32; i++)
    {
        v1 -= ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
        v0 -= ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        sum -= delta;
    }
    v[0] = v0;
    v[1] = v1;
}

static void xor_block(uint8_t *dst, const uint8_t *a, const uint8_t *b)
{
    for (int i = 0; i < 8; i++)
        dst[i] = a[i] ^ b[i];
}

void TEA_CBC_encrypt(uint8_t *data, uint32_t len, const uint32_t k[4], uint8_t iv[8])
{
    uint8_t buf[8];
    for (uint32_t i = 0; i < len; i += 8)
    {
        xor_block(buf, data + i, iv);
        TEA_encrypt_block((uint32_t *)buf, k);
        memcpy(data + i, buf, 8);
        memcpy(iv, buf, 8);
    }
}

void TEA_CBC_decrypt(uint8_t *data, uint32_t len, const uint32_t k[4], uint8_t iv[8])
{
    uint8_t prev[8], cur[8];
    memcpy(prev, iv, 8);
    for (uint32_t i = 0; i < len; i += 8)
    {
        memcpy(cur, data + i, 8);
        TEA_decrypt_block((uint32_t *)cur, k);
        xor_block(cur, cur, prev);
        memcpy(prev, data + i, 8);
        memcpy(data + i, cur, 8);
    }
}
