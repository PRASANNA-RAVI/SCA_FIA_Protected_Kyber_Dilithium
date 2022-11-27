#ifndef NTT_H
#define NTT_H

#include <stdint.h>
#include "params.h"

#define ntt DILITHIUM_NAMESPACE(ntt)
void ntt(int32_t a[N]);

#define invntt_tomont DILITHIUM_NAMESPACE(invntt_tomont)
void invntt_tomont(int32_t a[N]);

#define ntt_no_protect DILITHIUM_NAMESPACE(ntt_no_protect)
void ntt_no_protect(int32_t p[N]);

#define invntt_tomont_no_protect DILITHIUM_NAMESPACE(invntt_tomont_no_protect)
void invntt_tomont_no_protect(int32_t p[N]);

#endif
