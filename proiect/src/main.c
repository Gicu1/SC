#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "tea.h"
#include "aes.h"
#include "rsa.h"
#include "utils.h"

static void usage(void)
{
    puts("Usage: crypto -e|-d -a <aes|tea|rsa> [options]\\n"
         "Options:\\n"
         "  -m <ecb|cbc|ctr>          Mode (block ciphers)\\n"
         "  -i <input_file>           Input file\\n"
         "  -k <key_file>             Key file (hex for symmetric, spec for RSA)\\n"
         "  -o <output_file>          Output file\\n");
}

int main(int argc, char *argv[])
{
    int enc = -1;
    const char *alg = NULL, *mode = "cbc", *in = NULL, *out = NULL, *kfile = NULL;
    for (int i = 1; i < argc; i++)
    {
        if (!strcmp(argv[i], "-e"))
            enc = 1;
        else if (!strcmp(argv[i], "-d"))
            enc = 0;
        else if (!strcmp(argv[i], "-a") && i + 1 < argc)
            alg = argv[++i];
        else if (!strcmp(argv[i], "-m") && i + 1 < argc)
            mode = argv[++i];
        else if (!strcmp(argv[i], "-i") && i + 1 < argc)
            in = argv[++i];
        else if (!strcmp(argv[i], "-k") && i + 1 < argc)
            kfile = argv[++i];
        else if (!strcmp(argv[i], "-o") && i + 1 < argc)
            out = argv[++i];
    }
    if (enc == -1 || !alg || !in || !kfile || !out)
    {
        usage();
        return 1;
    }

    uint8_t *buf = NULL;
    uint32_t len;
    if (read_file(in, &buf, &len))
    {
        perror("input");
        return 1;
    }

    if (!strcmp(alg, "tea"))
    {
        uint8_t key[16];
        if (hex_read_key(kfile, key, 16) != 16)
        {
            fputs("Bad TEA key\\n", stderr);
            return 1;
        }
        uint32_t k[4];
        memcpy(k, key, 16);
        uint8_t iv[8] = {0};
        if (enc)
        {
            len = pkcs7_pad(&buf, len, 8);
            TEA_CBC_encrypt(buf, len, k, iv);
        }
        else
        {
            TEA_CBC_decrypt(buf, len, k, iv);
            len = pkcs7_unpad(buf, len);
        }
        // enc ? TEA_CBC_encrypt(buf, len, k, iv) : TEA_CBC_decrypt(buf, len, k, iv);
    }
    else if (!strcmp(alg, "aes"))
    {
        uint8_t key[16];
        if (hex_read_key(kfile, key, 16) != 16)
        {
            fputs("Bad AES key\\n", stderr);
            return 1;
        }
        uint8_t iv[16] = {0};
        if (strcmp(mode, "cbc"))
        {
            fprintf(stderr, "Mode %s unimplemented\\n", mode);
            return 1;
        }
        if (enc)
        {
            len = pkcs7_pad(&buf, len, 16);
            AES_CBC_encrypt_buffer(buf, len, key, iv);
        }
        else
        {
            AES_CBC_decrypt_buffer(buf, len, key, iv);
            len = pkcs7_unpad(buf, len);
        }
        // enc ? AES_CBC_encrypt_buffer(buf, len, key, iv)
        //     : AES_CBC_decrypt_buffer(buf, len, key, iv);
    }
    /* ─────────────────────────  RSA  ───────────────────────── */
    else if (!strcmp(alg, "rsa"))
    {
        RSAKey key = {0};
        if (RSA_load_key(&key, kfile, !enc))
        {
            fputs("Key load failed\n", stderr);
            return 1;
        }
        const uint32_t modB = RSA_mod_bytes(&key);
        const uint32_t maxP = modB - 11;

        uint32_t blocks = 0;

        if (enc)
        { /* ── ENCRYPT ── */
            blocks = (len + maxP - 1) / maxP;
            uint8_t *obuf = malloc(blocks * modB);
            uint32_t olen = 0;

            for (uint32_t off = 0; off < len; off += maxP)
            {
                uint32_t chunk_len = (len - off > maxP) ? maxP : (len - off);

                uint8_t chunk[119];
                memcpy(chunk, buf + off, chunk_len);
                chunk[chunk_len] = (uint8_t)chunk_len;
                chunk[chunk_len + 1] = 0xAB;
                uint32_t plain_sz = chunk_len + 2;

                uint8_t tmp[256];
                uint32_t tmpLen;
                RSA_encrypt(&key, chunk, plain_sz, tmp, &tmpLen);

                memset(obuf + olen, 0, modB - tmpLen); /* left-pad */
                memcpy(obuf + olen + (modB - tmpLen), tmp, tmpLen);
                olen += modB;
            }
            free(buf);
            buf = obuf;
            len = olen;
        }
        else
        { /* ── DECRYPT ── */
            if (len % modB)
            {
                fputs("Cipher length not multiple of block size\n", stderr);
                return 1;
            }

            blocks = len / modB;
            uint8_t *obuf = malloc(blocks * maxP);
            uint32_t olen = 0;

            for (uint32_t b = 0; b < blocks; ++b)
            {
                uint8_t tmp[256];
                uint32_t tmpLen;
                RSA_decrypt(&key, buf + b * modB, modB, tmp, &tmpLen);

                uint8_t full[256] = {0};
                memcpy(full + (modB - tmpLen), tmp, tmpLen);

                if (full[modB - 1] != 0xAB)
                {
                    fputs("Bad RSA marker\n", stderr);
                    return 1;
                }

                uint8_t slice_len = full[modB - 2];
                if (slice_len == 0 || slice_len > maxP)
                {
                    fputs("Corrupt RSA block len\n", stderr);
                    return 1;
                }

                memcpy(obuf + olen, full + (modB - 2 - slice_len), slice_len);
                olen += slice_len;
            }
            free(buf);
            buf = obuf;
            len = olen;
        }
    }
    else
    {
        fprintf(stderr, "Unknown alg %s\\n", alg);
        return 1;
    }

    if (write_file(out, buf, len))
    {
        perror("output");
        return 1;
    }
    free(buf);
    return 0;
}
