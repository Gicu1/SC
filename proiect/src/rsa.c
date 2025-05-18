#include "rsa.h"
#include <gmp.h>
#include <stdio.h>
#include <string.h>

static void mpz_read_hex_file_line(mpz_t z, const char *line, const char *tag)
{
    size_t taglen = strlen(tag);
    if (strncmp(line, tag, taglen) == 0)
        mpz_set_str(z, line + taglen, 16); /* base 16 */
}

int RSA_load_key(RSAKey *k, const char *path, int is_private)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;

    mpz_inits(k->n, k->e, k->d, NULL);

    char line[4096];
    while (fgets(line, sizeof line, f))
    {
        mpz_read_hex_file_line(k->n, line, "n=");
        mpz_read_hex_file_line(k->e, line, "e=");
        if (is_private)
            mpz_read_hex_file_line(k->d, line, "d=");
    }
    fclose(f);

    return mpz_cmp_ui(k->n, 0) == 0 ? -1 : 0;
}

static void mpz_from_bytes(mpz_t z, const uint8_t *buf, size_t len)
{
    mpz_import(z, len, 1, 1, 1, 0, buf);
}

static void mpz_to_bytes(const mpz_t z, uint8_t *buf, size_t len)
{
    size_t got;
    memset(buf, 0, len);
    mpz_export(buf + (len - ((mpz_sizeinbase(z, 2) + 7) / 8)), &got, 1, 1, 1, 0, z);
}

void RSA_encrypt(const RSAKey *k,
                 const uint8_t *in, uint32_t in_len,
                 uint8_t *out, uint32_t *out_len)
{
    mpz_t m, c;
    mpz_inits(m, c, NULL);
    mpz_from_bytes(m, in, in_len);

    mpz_powm(c, m, k->e, k->n);

    uint32_t modB = (mpz_sizeinbase(k->n, 2) + 7) / 8;
    mpz_to_bytes(c, out, modB);
    *out_len = modB;

    mpz_clears(m, c, NULL);
}

void RSA_decrypt(const RSAKey *k,
                 const uint8_t *in, uint32_t in_len,
                 uint8_t *out, uint32_t *out_len)
{
    mpz_t c, m;
    mpz_inits(c, m, NULL);
    mpz_from_bytes(c, in, in_len);

    mpz_powm(m, c, k->d, k->n);

    uint32_t modB = (mpz_sizeinbase(k->n, 2) + 7) / 8;
    mpz_to_bytes(m, out, modB);
    *out_len = modB;

    mpz_clears(c, m, NULL);
}

uint32_t RSA_mod_bytes(const RSAKey *k)
{
    return (mpz_sizeinbase(k->n, 2) + 7) / 8;
}
