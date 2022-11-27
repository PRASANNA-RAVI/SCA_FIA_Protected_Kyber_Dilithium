#ifndef VERIFY_H
#define VERIFY_H

#include <stddef.h>
#include <stdint.h>
#include "params.h"

#define verify KYBER_NAMESPACE(verify)
int verify(const uint8_t *a, const uint8_t *b, size_t len);

#define cmov KYBER_NAMESPACE(cmov)
void cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b);

void cmov_fia(unsigned char *r, unsigned char * c, const unsigned char *x, size_t len, int fail, uint8_t cmp_value);

int verify_fia(const unsigned char *a, const unsigned char *b, size_t len, uint8_t r_value);

#endif
