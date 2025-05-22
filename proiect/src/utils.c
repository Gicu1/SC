#define _FILE_OFFSET_BITS 64
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int read_file(const char *path, uint8_t **buf, off_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;
    if (fseeko(f, 0, SEEK_END) != 0)
    {
        fclose(f);
        return -1;
    }
    off_t sz = ftello(f);
    if (sz < 0)
    {
        fclose(f);
        return -1;
    }
    *len = sz;
    if (fseeko(f, 0, SEEK_SET) != 0)
    {
        fclose(f);
        return -1;
    }
    uint8_t *b = malloc((size_t)sz);
    if (!b)
    {
        fclose(f);
        return -1;
    }
    size_t r = fread(b, 1, (size_t)sz, f);
    fclose(f);
    if (r != (size_t)sz)
    {
        free(b);
        return -1;
    }
    *buf = b;
    return 0;
}

int write_file(const char *path, const uint8_t *buf, off_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return -1;
    size_t w = fwrite(buf, 1, (size_t)len, f);
    fclose(f);
    return w == (size_t)len ? 0 : -1;
}

static uint8_t hex_val(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return 0;
}

int hex_read_key(const char *path, uint8_t *buf, uint32_t buf_len)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    char line[2048];
    if (!fgets(line, sizeof(line), f))
    {
        fclose(f);
        return -1;
    }
    fclose(f);
    line[strcspn(line, "\r\n")] = '\0';
    size_t len = strlen(line);
    if (len & 1)
        return -1;
    size_t bytes = len / 2;
    if (bytes > buf_len)
        return -1;
    for (size_t i = 0; i < bytes; i++)
        buf[i] = (hex_val(line[2 * i]) << 4) | hex_val(line[2 * i + 1]);
    return bytes;
}
