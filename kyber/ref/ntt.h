#ifndef NTT_H
#define NTT_H

#include <stdint.h>
#include "params.h"

#define zetas_old KYBER_NAMESPACE(zetas_old)
extern const int16_t zetas_old[128];

#define ntt KYBER_NAMESPACE(ntt)
void ntt(int16_t poly[256]);

#define invntt KYBER_NAMESPACE(invntt)
void invntt(int16_t poly[256]);

#define ntt_no_protect KYBER_NAMESPACE(ntt_no_protect)
void ntt_no_protect(int16_t poly[256]);

#define invntt_no_protect KYBER_NAMESPACE(invntt_no_protect)
void invntt_no_protect(int16_t poly[256]);

#define basemul KYBER_NAMESPACE(basemul)
void basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta);

#endif
