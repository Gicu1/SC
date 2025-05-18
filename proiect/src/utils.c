#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int read_file(const char *path, uint8_t **buf, uint32_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;
    fseek(f, 0, SEEK_END);
    *len = ftell(f);
    fseek(f, 0, SEEK_SET);
    *buf = malloc(*len);
    if (!*buf)
    {
        fclose(f);
        return -1;
    }
    fread(*buf, 1, *len, f);
    fclose(f);
    return 0;
}

int write_file(const char *path, const uint8_t *buf, uint32_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return -1;
    fwrite(buf, 1, len, f);
    fclose(f);
    return 0;
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
