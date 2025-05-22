// main.c
#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include "tea.h"
#include "aes.h"
#include "rsa.h"
#include "utils.h"

static void usage(void)
{
    puts("Usage: crypto -e|-d -a <aes|tea|rsa> [options]\n"
         "Options:\n"
         "  -m <ecb|cbc|ctr>          Mode (block ciphers)\n"
         "  -i <input_file>           Input file\n"
         "  -k <key_file>             Key file (hex for symmetric, spec for RSA)\n"
         "  -o <output_file>          Output file");
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
    off_t len;
    if (read_file(in, &buf, &len))
    {
        perror("input");
        return 1;
    }

    if (!strcmp(alg, "tea"))
    {
        uint8_t keyb[16], iv[8] = {0};
        if (hex_read_key(kfile, keyb, 16) != 16)
            ;
        // return puts("Bad TEA key"), 1;
        uint32_t k[4];
        memcpy(k, keyb, 16);
        if (enc)
        {
            uint32_t newlen = pkcs7_pad(&buf, (uint32_t)len, 8);
            if (!buf)
                return puts("OOM"), 1;
            len = newlen;
            TEA_CBC_encrypt(buf, (uint32_t)len, k, iv);
        }
        else
        {
            TEA_CBC_decrypt(buf, (uint32_t)len, k, iv);
            len = pkcs7_unpad(buf, (uint32_t)len);
        }
    }
    else if (!strcmp(alg, "aes"))
    {
        uint8_t keyb[16], iv[16] = {0};
        if (hex_read_key(kfile, keyb, 16) != 16)
            ;
        // return puts("Bad AES key"), 1;
        if (strcmp(mode, "cbc"))
            return fprintf(stderr, "Mode %s unimplemented\n", mode), 1;
        if (enc)
        {
            uint32_t newlen = pkcs7_pad(&buf, (uint32_t)len, 16);
            if (!buf)
                return puts("OOM"), 1;
            len = newlen;
            AES_CBC_encrypt_buffer(buf, (uint32_t)len, keyb, iv);
        }
        else
        {
            AES_CBC_decrypt_buffer(buf, (uint32_t)len, keyb, iv);
            len = pkcs7_unpad(buf, (uint32_t)len);
        }
    }
    else if (!strcmp(alg, "rsa"))
    {
        RSAKey key = {0};
        if (RSA_load_key(&key, kfile, !enc))
            return puts("Key load failed"), 1;
        uint32_t modB = RSA_mod_bytes(&key), maxP = modB - 11;
        uint32_t blocks, olen = 0;
        if (enc)
        {
            blocks = (len + maxP - 1) / maxP;
            uint8_t *obuf = malloc((size_t)blocks * modB);
            if (!obuf)
                return puts("OOM"), 1;
            for (uint32_t off = 0; off < (uint32_t)len; off += maxP)
            {
                uint32_t chunk = len - off > maxP ? maxP : (uint32_t)(len - off);
                uint8_t tmp[256];
                uint32_t tmpLen;
                uint8_t inb[256] = {0};
                memcpy(inb, buf + off, chunk);
                inb[chunk] = (uint8_t)chunk;
                inb[chunk + 1] = 0xAB;
                RSA_encrypt(&key, inb, chunk + 2, tmp, &tmpLen);
                memset(obuf + olen, 0, modB - tmpLen);
                memcpy(obuf + olen + modB - tmpLen, tmp, tmpLen);
                olen += modB;
            }
            free(buf);
            buf = obuf;
            len = olen;
        }
        else
        {
            if (len % modB)
                return puts("Cipher length not multiple"), 1;
            blocks = len / modB;
            uint8_t *obuf = malloc((size_t)blocks * maxP);
            if (!obuf)
                return puts("OOM"), 1;
            for (uint32_t b = 0; b < blocks; b++)
            {
                uint8_t tmp[256], full[256] = {0};
                uint32_t tmpLen;
                RSA_decrypt(&key, buf + b * modB, modB, tmp, &tmpLen);
                memcpy(full + modB - tmpLen, tmp, tmpLen);
                if (full[modB - 1] != 0xAB)
                    return puts("Bad RSA marker"), 1;
                uint8_t sl = full[modB - 2];
                if (!sl || sl > maxP)
                    return puts("Corrupt RSA block len"), 1;
                memcpy(obuf + olen, full + modB - 2 - sl, sl);
                olen += sl;
            }
            free(buf);
            buf = obuf;
            len = olen;
        }
    }
    else
        return fprintf(stderr, "Unknown alg %s\n", alg), 1;

    if (write_file(out, buf, len))
    {
        perror("output");
        return 1;
    }
    free(buf);
    return 0;
}
