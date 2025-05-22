#ifndef UTILS_H
#define UTILS_H
#include <stdint.h>
#include <sys/types.h>
int read_file(const char *path, uint8_t **buf, off_t *len);
int write_file(const char *path, const uint8_t *buf, off_t len);
int hex_read_key(const char *path, uint8_t *buf, uint32_t buf_len);

#endif
