#include "aes.h"
#include <string.h>
#include <stdlib.h>

#define AES_BLOCKLEN 16

uint32_t pkcs7_pad(uint8_t **buf, uint32_t len, uint32_t bl)
{
    uint32_t pad = bl - (len % bl ? len % bl : bl);
    *buf = realloc(*buf, len + pad);
    for (uint32_t i = 0; i < pad; ++i)
        (*buf)[len + i] = (uint8_t)pad;
    return len + pad;
}

uint32_t pkcs7_unpad(uint8_t *buf, uint32_t len)
{
    if (len == 0)
        return 0;
    uint8_t pad = buf[len - 1];
    if (pad == 0 || pad > 16)
        return len; /* corrupt */
    for (uint8_t i = 1; i <= pad; ++i)
        if (buf[len - i] != pad)
            return len; /* corrupt */
    return len - pad;
}

static const uint8_t sbox[256] = {
    /* 0     1    2    3      4     5     6     7     8     9     A     B     C     D     E    F */
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

static const uint8_t rsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

static const uint8_t Rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

#define xtime(x) ((uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1b)))

#define GET(state, r, c) (state[(r) + 4 * (c)])
#define SET(state, r, c, val) (state[(r) + 4 * (c)] = (val))

static void SubBytes(uint8_t state[16])
{
    for (int i = 0; i < 16; ++i)
        state[i] = sbox[state[i]];
}

static void InvSubBytes(uint8_t state[16])
{
    for (int i = 0; i < 16; ++i)
        state[i] = rsbox[state[i]];
}

static void ShiftRows(uint8_t state[16])
{
    uint8_t tmp;

    // Row 1
    tmp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = tmp;

    // Row 2
    tmp = state[2];
    state[2] = state[10];
    state[10] = tmp;
    tmp = state[6];
    state[6] = state[14];
    state[14] = tmp;

    // Row 3
    tmp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = tmp;
}

static void InvShiftRows(uint8_t state[16])
{
    uint8_t tmp;

    // Row 1
    tmp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = tmp;

    // Row 2
    tmp = state[2];
    state[2] = state[10];
    state[10] = tmp;
    tmp = state[6];
    state[6] = state[14];
    state[14] = tmp;

    // Row 3
    tmp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = tmp;
}

static void MixColumns(uint8_t state[16])
{
    for (int i = 0; i < 4; ++i)
    {
        uint8_t *col = &state[i * 4];
        uint8_t a = col[0], b = col[1], c = col[2], d = col[3];
        col[0] = xtime(a) ^ xtime(b) ^ b ^ c ^ d;
        col[1] = a ^ xtime(b) ^ xtime(c) ^ c ^ d;
        col[2] = a ^ b ^ xtime(c) ^ xtime(d) ^ d;
        col[3] = xtime(a) ^ a ^ b ^ c ^ xtime(d);
    }
}

static void InvMixColumns(uint8_t state[16])
{
    for (int i = 0; i < 4; ++i)
    {
        uint8_t *col = &state[i * 4];
        uint8_t a = col[0], b = col[1], c = col[2], d = col[3];
        uint8_t a2 = xtime(a), b2 = xtime(b), c2 = xtime(c), d2 = xtime(d);
        uint8_t a4 = xtime(a2), b4 = xtime(b2), c4 = xtime(c2), d4 = xtime(d2);
        uint8_t a8 = xtime(a4), b8 = xtime(b4), c8 = xtime(c4), d8 = xtime(d4);

        uint8_t a9 = a8 ^ a, b9 = b8 ^ b, c9 = c8 ^ c, d9 = d8 ^ d;
        uint8_t aB = a8 ^ a2 ^ a, bB = b8 ^ b2 ^ b, cB = c8 ^ c2 ^ c, dB = d8 ^ d2 ^ d;
        uint8_t aD = a8 ^ a4 ^ a, bD = b8 ^ b4 ^ b, cD = c8 ^ c4 ^ c, dD = d8 ^ d4 ^ d;
        uint8_t aE = a8 ^ a4 ^ a2, bE = b8 ^ b4 ^ b2, cE = c8 ^ c4 ^ c2, dE = d8 ^ d4 ^ d2;

        col[0] = aE ^ bB ^ cD ^ d9;
        col[1] = a9 ^ bE ^ cB ^ dD;
        col[2] = aD ^ b9 ^ cE ^ dB;
        col[3] = aB ^ bD ^ c9 ^ dE;
    }
}

static void AddRoundKey(uint8_t round, uint8_t state[16], const uint8_t *RoundKey)
{
    for (int i = 0; i < 16; ++i)
        state[i] ^= RoundKey[round * 16 + i];
}

/******************************************************************************/
/*                        Key expansion (AES-128)                             */
/******************************************************************************/
#define Nb 4
#define Nk 4
#define Nr 10

void AES_init_ctx(uint8_t *RoundKey, const uint8_t *Key)
{
    memcpy(RoundKey, Key, 16);

    uint8_t tempa[4];
    uint32_t i = Nk;
    while (i < Nb * (Nr + 1))
    {
        memcpy(tempa, &RoundKey[(i - 1) * 4], 4);

        if (i % Nk == 0)
        {
            // Rotate left
            uint8_t t = tempa[0];
            tempa[0] = tempa[1];
            tempa[1] = tempa[2];
            tempa[2] = tempa[3];
            tempa[3] = t;

            // SubByte
            tempa[0] = sbox[tempa[0]];
            tempa[1] = sbox[tempa[1]];
            tempa[2] = sbox[tempa[2]];
            tempa[3] = sbox[tempa[3]];

            tempa[0] ^= Rcon[i / Nk];
        }

        RoundKey[i * 4 + 0] = RoundKey[(i - Nk) * 4 + 0] ^ tempa[0];
        RoundKey[i * 4 + 1] = RoundKey[(i - Nk) * 4 + 1] ^ tempa[1];
        RoundKey[i * 4 + 2] = RoundKey[(i - Nk) * 4 + 2] ^ tempa[2];
        RoundKey[i * 4 + 3] = RoundKey[(i - Nk) * 4 + 3] ^ tempa[3];
        ++i;
    }
}

/******************************************************************************/
/*                           Single-block ECB                                 */
/******************************************************************************/
static void AES_encrypt_block(uint8_t state[16], const uint8_t *RoundKey)
{
    AddRoundKey(0, state, RoundKey);

    for (uint8_t round = 1; round < Nr; ++round)
    {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(round, state, RoundKey);
    }
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(Nr, state, RoundKey);
}

static void AES_decrypt_block(uint8_t state[16], const uint8_t *RoundKey)
{
    AddRoundKey(Nr, state, RoundKey);

    for (int round = Nr - 1; round >= 1; --round)
    {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(round, state, RoundKey);
        InvMixColumns(state);
    }
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(0, state, RoundKey);
}

void AES_ECB_encrypt(const uint8_t *input, const uint8_t *key, uint8_t *output)
{
    uint8_t buf[16];
    memcpy(buf, input, 16);
    uint8_t RoundKey[176];
    AES_init_ctx(RoundKey, key);
    AES_encrypt_block(buf, RoundKey);
    memcpy(output, buf, 16);
}

void AES_ECB_decrypt(const uint8_t *input, const uint8_t *key, uint8_t *output)
{
    uint8_t buf[16];
    memcpy(buf, input, 16);
    uint8_t RoundKey[176];
    AES_init_ctx(RoundKey, key);
    AES_decrypt_block(buf, RoundKey);
    memcpy(output, buf, 16);
}

/******************************************************************************/
/*                          CBC & CTR helpers                                 */
/******************************************************************************/
void AES_CBC_encrypt_buffer(uint8_t *buf, uint32_t len,
                            const uint8_t *key, uint8_t *iv)
{
    uint8_t RoundKey[176];
    AES_init_ctx(RoundKey, key);

    for (uint32_t i = 0; i < len; i += AES_BLOCKLEN)
    {
        for (int j = 0; j < AES_BLOCKLEN; ++j)
            buf[i + j] ^= iv[j];
        AES_encrypt_block(&buf[i], RoundKey);
        memcpy(iv, &buf[i], AES_BLOCKLEN);
    }
}

void AES_CBC_decrypt_buffer(uint8_t *buf, uint32_t len,
                            const uint8_t *key, uint8_t *iv)
{
    uint8_t RoundKey[176];
    AES_init_ctx(RoundKey, key);
    uint8_t prev_block[AES_BLOCKLEN];

    for (uint32_t i = 0; i < len; i += AES_BLOCKLEN)
    {
        memcpy(prev_block, &buf[i], AES_BLOCKLEN);
        AES_decrypt_block(&buf[i], RoundKey);
        for (int j = 0; j < AES_BLOCKLEN; ++j)
            buf[i + j] ^= iv[j];
        memcpy(iv, prev_block, AES_BLOCKLEN);
    }
}

static void inc32(uint8_t *ctr) /* increment right-most 32 bits */
{
    for (int i = 15; i >= 12; --i)
        if (++ctr[i])
            break;
}

void AES_CTR_xcrypt_buffer(uint8_t *buf, uint32_t len,
                           const uint8_t *key, uint8_t *nonce)
{
    uint8_t RoundKey[176];
    AES_init_ctx(RoundKey, key);
    uint8_t stream_block[16];
    uint8_t ctr[16];
    memcpy(ctr, nonce, 16);

    for (uint32_t i = 0; i < len; i += 16)
    {
        memcpy(stream_block, ctr, 16);
        AES_encrypt_block(stream_block, RoundKey);
        uint32_t blk = (len - i < 16) ? len - i : 16;
        for (uint32_t j = 0; j < blk; ++j)
            buf[i + j] ^= stream_block[j];
        inc32(ctr);
    }
}
