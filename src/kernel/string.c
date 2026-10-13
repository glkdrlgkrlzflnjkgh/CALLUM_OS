// string.c
#include "string.h"

void *memcpy(void *dst, const void *src, size_t n) {
    unsigned char *d = dst;
    const unsigned char *s = src;
    while (n--) *d++ = *s++;
    return dst;
}

void *memset(void *dst, int val, size_t n) {
    unsigned char *d = dst;
    while (n--) *d++ = (unsigned char)val;
    return dst;
}

int memcmp(const void *a, const void *b, size_t n) {
    const unsigned char *x = a, *y = b;
    while (n--) {
        if (*x != *y) return *x - *y;
        x++; y++;
    }
    return 0;
}

int strncmp(const char *a, const char *b, size_t n) {
    while (n--) {
        unsigned char left = (unsigned char)*a++;
        unsigned char right = (unsigned char)*b++;
        if (left != right) return left - right;
        if (!left) return 0;
    }
    return 0;
}

size_t strlen(const char *s) {
    size_t len = 0;
    while (*s++) len++;
    return len;
}
