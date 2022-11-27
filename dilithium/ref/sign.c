#include <stdint.h>
#include "params.h"
#include "sign.h"
#include "packing.h"
#include "polyvec.h"
#include "poly.h"
#include "randombytes.h"
#include "symmetric.h"
#include "fips202.h"
#include "reduce.h"
#include "sca_fia_protection.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*************************************************
* Name:        crypto_sign_keypair
*
* Description: Generates public and private key.
*
* Arguments:   - uint8_t *pk: pointer to output public key (allocated
*                             array of CRYPTO_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key (allocated
*                             array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_sign_keypair(uint8_t *pk, uint8_t *sk) {
  uint8_t seedbuf[2*SEEDBYTES + CRHBYTES];
  uint8_t tr[SEEDBYTES];
  const uint8_t *rho, *rhoprime, *key;
  polyvecl mat[K];
  polyvecl s1, s1hat;
  polyveck s2, t1, t0;

  /* Get randomness for rho, rhoprime and key */
  randombytes(seedbuf, SEEDBYTES);
  shake256(seedbuf, 2*SEEDBYTES + CRHBYTES, seedbuf, SEEDBYTES);
  rho = seedbuf;
  rhoprime = rho + SEEDBYTES;
  key = rhoprime + CRHBYTES;

  /* Expand matrix */
  polyvec_matrix_expand(mat, rho);

  /* Sample short vectors s1 and s2 */
  polyvecl_uniform_eta(&s1, rhoprime, 0);
  polyveck_uniform_eta(&s2, rhoprime, L);

  /* Matrix-vector multiplication */
  s1hat = s1;
  polyvecl_ntt(&s1hat, 1);
  polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
  polyveck_reduce(&t1);
  polyveck_invntt_tomont(&t1, 1);

  /* Add error vector s2 */
  polyveck_add(&t1, &t1, &s2);

  /* Extract t1 and write public key */
  polyveck_caddq(&t1);
  polyveck_power2round(&t1, &t0, &t1);
  pack_pk(pk, rho, &t1);

  /* Compute H(rho, t1) and write secret key */
  shake256(tr, SEEDBYTES, pk, CRYPTO_PUBLICKEYBYTES);
  pack_sk(sk, rho, tr, key, &t0, &s1, &s2);

  return 0;
}

/*************************************************
* Name:        crypto_sign_signature
*
* Description: Computes signature.
*
* Arguments:   - uint8_t *sig:   pointer to output signature (of length CRYPTO_BYTES)
*              - size_t *siglen: pointer to output length of signature
*              - uint8_t *m:     pointer to message to be signed
*              - size_t mlen:    length of message
*              - uint8_t *sk:    pointer to bit-packed secret key
*
* Returns 0 (success)
**************************************************/

#pragma GCC push_options
#pragma GCC optimize ("O0")

int original_verify_final_commpare_value;

static void compare_c_poly_fia(uint8_t *sig, uint8_t *c2, uint8_t * c, int * r)
{
  int i;
  for(i = 0; i < SEEDBYTES; ++i)
  {
    if(sig[i] == c2[i])
    {
      *r = *r + *c;
    }
  }
}

static int compare_c_poly_in_verify_fia(uint8_t *sig, uint8_t *c2, uint8_t * c, int * r)
{
  int i;
  int ret_value = 0;

  for(i = 0; i < SEEDBYTES; ++i)
  {
    if(sig[i] == c2[i])
    {
      *r = *r + *c;
    }
    else
    {
      ret_value = -1;
    }
  }

  return ret_value;
}

static void copy_sig_based_on_counter(uint8_t * sig, uint8_t * sig_f, uint8_t * cmp_r_value, int * final_commpare_value, int * original_final_commpare_value)
{

  int tt;

  for(int tt = 0; tt < CRYPTO_BYTES; tt++)
  {
    #if(VERIFY_AFTER_SIGN == 1 || VERIFY_ADD == 1 || VERIFY_Y_GEN == 1)

    if((*final_commpare_value == *original_final_commpare_value) && (final_commpare_value != 0))
    {
      sig_f[tt] = sig[tt];
    }

    #else

      sig_f[tt] = sig[tt];

    #endif
  }
}

#pragma GCC pop_options

static uint32_t shift_lfsr(unsigned int *lfsr, unsigned int polynomial_mask)
{
    uint32_t feedback;

    feedback = *lfsr & 1;
    *lfsr >>= 1;
    if(feedback == 1)
        *lfsr ^= polynomial_mask;
    return *lfsr;
}

static uint32_t get_random(void)
{
    uint32_t temp;
    uint32_t POLY_MASK_HERE_1 = 0xB765879A;
    uint32_t POLY_MASK_HERE_2 = 0x55BBEEFF;
    static uint32_t lfsr_1 = 0x55AAEEFF;
    static uint32_t lfsr_2 = 0xFFAA8844;
    shift_lfsr(&lfsr_1, POLY_MASK_HERE_1);
    shift_lfsr(&lfsr_2, POLY_MASK_HERE_2);
    temp = (shift_lfsr(&lfsr_1, POLY_MASK_HERE_1) ^ shift_lfsr(&lfsr_2, POLY_MASK_HERE_2));
    return (temp);
}

int crypto_sign_signature(uint8_t *sig_f,
                          size_t *siglen,
                          const uint8_t *m,
                          size_t mlen,
                          const uint8_t *sk, const uint8_t *pk)
{
  unsigned int n;
  uint8_t seedbuf[3*SEEDBYTES + 2*CRHBYTES];
  uint8_t *rho, *tr, *key, *mu, *rhoprime;
  uint16_t nonce = 0;
  polyvecl mat[K], s1, y, z;
  polyveck t0, s2, w1, w0, h;
  poly cp;
  keccak_state state;

  int i;

  uint8_t sig[CRYPTO_BYTES];
  uint8_t sig_f1[CRYPTO_BYTES];

  #if(VERIFY_AFTER_SIGN == 1)
    polyveck t1;
    uint8_t buf[K*POLYW1_PACKEDBYTES];
    uint8_t c[SEEDBYTES];
    uint8_t c2[SEEDBYTES];
  #endif

  uint8_t cmp_r_value;
  int final_commpare_value;
  int original_final_commpare_value;

  #if(VERIFY_AFTER_SIGN == 1 || VERIFY_ADD == 1 || VERIFY_Y_GEN == 1)

  randombytes(&cmp_r_value, 1);
  while(cmp_r_value == 0)
  {
    randombytes(&cmp_r_value, 1);
  }

  #endif

  #if((VERIFY_AFTER_SIGN == 1) && (VERIFY_ADD == 1) && (VERIFY_Y_GEN == 1))
    original_final_commpare_value = (cmp_r_value * L * N) + cmp_r_value * SEEDBYTES + cmp_r_value * L * N + cmp_r_value * L * N;
  #elif((VERIFY_AFTER_SIGN == 0) && (VERIFY_ADD == 1) && (VERIFY_Y_GEN == 1))
    original_final_commpare_value = (cmp_r_value * L * N) + cmp_r_value * L * N + cmp_r_value * L * N;
  #elif((VERIFY_AFTER_SIGN == 1) && (VERIFY_ADD == 0) && (VERIFY_Y_GEN == 1))
    original_final_commpare_value = cmp_r_value * SEEDBYTES + cmp_r_value * L * N + cmp_r_value * L * N;
  #elif((VERIFY_AFTER_SIGN == 0) && (VERIFY_ADD == 0) && (VERIFY_Y_GEN == 1))
    original_final_commpare_value = cmp_r_value * L * N + cmp_r_value * L * N;
  #elif((VERIFY_AFTER_SIGN == 1) && (VERIFY_ADD == 1) && (VERIFY_Y_GEN == 0))
    original_final_commpare_value = (cmp_r_value * L * N) + cmp_r_value * SEEDBYTES;
  #elif((VERIFY_AFTER_SIGN == 0) && (VERIFY_ADD == 1) && (VERIFY_Y_GEN == 0))
    original_final_commpare_value = (cmp_r_value * L * N);
  #elif((VERIFY_AFTER_SIGN == 1) && (VERIFY_ADD == 0) && (VERIFY_Y_GEN == 0))
    original_final_commpare_value = cmp_r_value * SEEDBYTES;
  #endif

  // printf("original_final_commpare_value: %d\n", original_final_commpare_value);

  poly unit;
  for(int jj = 0; jj < N; jj++)
  {
    unit.coeffs[jj] = 1;
  }

  rho = seedbuf;
  tr = rho + SEEDBYTES;
  key = tr + SEEDBYTES;
  mu = key + SEEDBYTES;
  rhoprime = mu + CRHBYTES;
  unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

  #if(VERIFY_AFTER_SIGN == 1)
    unpack_pk(rho, &t1, pk);
  #endif

  /* Compute CRH(tr, msg) */
  shake256_init(&state);
  shake256_absorb(&state, tr, SEEDBYTES);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, CRHBYTES, &state);

  #ifdef DILITHIUM_RANDOMIZED_SIGNING
    randombytes(rhoprime, CRHBYTES);
  #else
    shake256(rhoprime, CRHBYTES, key, SEEDBYTES + CRHBYTES);
  #endif

  /* Expand matrix and transform vectors */
  polyvec_matrix_expand(mat, rho);
  polyvecl_ntt(&s1, 1);
  polyveck_ntt(&s2, 1);
  polyveck_ntt(&t0, 0);

rej:
  // /* Sample intermediate vector y */

  #if(VERIFY_AFTER_SIGN == 1 || VERIFY_ADD == 1 || VERIFY_Y_GEN == 1)
    // final_commpare_value = original_final_commpare_value;
    final_commpare_value = 0;
  #endif

  #if(VERIFY_Y_GEN == 1)

  for(int ii = 0; ii < L; ii++)
  {
    for(int jj = 0; jj < N; jj++)
    {
      final_commpare_value = final_commpare_value + cmp_r_value;
      y.vec[ii].coeffs[jj] = 0xABCDABCD;
    }
  }

  #endif

  #if(VERIFY_Y_GEN == 1)
    polyvecl_uniform_gamma1_fia(&y, rhoprime, nonce++, &cmp_r_value, &final_commpare_value);
  #else
    polyvecl_uniform_gamma1(&y, rhoprime, nonce++);
  #endif


  #if(VERIFY_ADD == 0)
    z = y;
    polyvecl_ntt(&z, 1);
    polyvec_matrix_pointwise_montgomery(&w1, mat, &z);
  #else
    polyvecl_ntt(&y, 1);
    polyvec_matrix_pointwise_montgomery(&w1, mat, &y);
  #endif

  polyveck_reduce(&w1);
  polyveck_invntt_tomont(&w1, 1);

  /* Decompose w and call the random oracle */
  polyveck_caddq(&w1);
  polyveck_decompose(&w1, &w0, &w1);
  polyveck_pack_w1(sig, &w1);

  shake256_init(&state);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_absorb(&state, sig, K*POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(sig, SEEDBYTES, &state);
  poly_challenge(&cp, sig);
  poly_ntt(&cp, 0);

  /* Compute z, reject if it reveals secret */
  polyvecl_pointwise_poly_montgomery(&z, &cp, &s1);

  #if(VERIFY_ADD == 1)
    for(i = 0; i < L; ++i)
      poly_pointwise_montgomery(&y.vec[i], &unit, &y.vec[i]);
    polyvecl_add_fia(&z, &z, &y, &cmp_r_value, &final_commpare_value);

    polyvecl_reduce(&z);
    polyvecl_invntt_tomont(&z, 0);
  #else
    polyvecl_invntt_tomont(&z, 1);
    polyvecl_add(&z, &z, &y);
    polyvecl_reduce(&z);
  #endif

  if(polyvecl_chknorm(&z, GAMMA1 - BETA))
    goto rej;

  /* Check that subtracting cs2 does not change high bits of w and low bits
   * do not reveal secret information */
  polyveck_pointwise_poly_montgomery(&h, &cp, &s2);
  polyveck_invntt_tomont(&h, 1);
  polyveck_sub(&w0, &w0, &h);
  polyveck_reduce(&w0);
  if(polyveck_chknorm(&w0, GAMMA2 - BETA))
    goto rej;

  /* Compute hints for w1 */
  polyveck_pointwise_poly_montgomery(&h, &cp, &t0);
  polyveck_invntt_tomont(&h, 1);
  polyveck_reduce(&h);
  if(polyveck_chknorm(&h, GAMMA2))
    goto rej;

  polyveck_add(&w0, &w0, &h);
  n = polyveck_make_hint(&h, &w0, &w1);
  if(n > OMEGA)
    goto rej;

  #if(VERIFY_AFTER_SIGN == 1)

  polyvecl_ntt(&z, 0);
  polyvec_matrix_pointwise_montgomery(&w1, mat, &z);

  polyveck_shiftl(&t1);
  polyveck_ntt(&t1, 0);
  polyveck_pointwise_poly_montgomery(&t1, &cp, &t1);

  polyveck_sub(&w1, &w1, &t1);
  polyveck_reduce(&w1);
  polyveck_invntt_tomont(&w1, 0);

  /* Reconstruct w1 */
  polyveck_caddq(&w1);
  polyveck_use_hint(&w1, &w1, &h);

  polyveck_pack_w1(buf, &w1);

  //
  // /* Call random oracle and verify challenge */
  shake256_init(&state);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_absorb(&state, buf, K*POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(c2, SEEDBYTES, &state);

  compare_c_poly_fia(sig, c2, &cmp_r_value, &final_commpare_value);

  for(i = 0; i < L; ++i)
    poly_pointwise_montgomery(&z.vec[i], &unit, &z.vec[i]);
  polyvecl_invntt_tomont(&z, 0);
  polyvecl_reduce(&z);

  #endif

  /* Write signature */
  pack_sig(sig, sig, &z, &h);

  copy_sig_based_on_counter(sig, sig_f, &cmp_r_value, &final_commpare_value, &original_final_commpare_value);

  *siglen = CRYPTO_BYTES;

  #if(VERIFY_AFTER_SIGN == 1 || VERIFY_ADD == 1 || VERIFY_Y_GEN == 1)
    return final_commpare_value;
  #else
    return 0;
  #endif


}

/*************************************************
* Name:        crypto_sign
*
* Description: Compute signed message.
*
* Arguments:   - uint8_t *sm: pointer to output signed message (allocated
*                             array with CRYPTO_BYTES + mlen bytes),
*                             can be equal to m
*              - size_t *smlen: pointer to output length of signed
*                               message
*              - const uint8_t *m: pointer to message to be signed
*              - size_t mlen: length of message
*              - const uint8_t *sk: pointer to bit-packed secret key
*
* Returns 0 (success)
**************************************************/
int crypto_sign(uint8_t *sm,
                size_t *smlen,
                const uint8_t *m,
                size_t mlen,
                const uint8_t *sk, const uint8_t *pk)
{

  size_t i;

  #if(VERIFY_AFTER_SIGN == 1 || VERIFY_ADD == 1 || VERIFY_Y_GEN == 1)
    int ret_value;
    for(i = 0; i < mlen; ++i)
      sm[CRYPTO_BYTES + mlen - 1 - i] = m[mlen - 1 - i];
    ret_value = crypto_sign_signature(sm, smlen, sm + CRYPTO_BYTES, mlen, sk, pk);
    *smlen += mlen;
    return ret_value;

  #else

    for(i = 0; i < mlen; ++i)
      sm[CRYPTO_BYTES + mlen - 1 - i] = m[mlen - 1 - i];
    crypto_sign_signature(sm, smlen, sm + CRYPTO_BYTES, mlen, sk, pk);
    *smlen += mlen;
    return 0;
  #endif

}

/*************************************************
* Name:        crypto_sign_verify
*
* Description: Verifies signature.
*
* Arguments:   - uint8_t *m: pointer to input signature
*              - size_t siglen: length of signature
*              - const uint8_t *m: pointer to message
*              - size_t mlen: length of message
*              - const uint8_t *pk: pointer to bit-packed public key
*
* Returns 0 if signature could be verified correctly and -1 otherwise
**************************************************/
int crypto_sign_verify(const uint8_t *sig,
                       size_t siglen,
                       const uint8_t *m,
                       size_t mlen,
                       const uint8_t *pk)
{
  unsigned int i;
  uint8_t buf[K*POLYW1_PACKEDBYTES];
  uint8_t rho[SEEDBYTES];
  uint8_t mu[CRHBYTES];
  uint8_t c[SEEDBYTES];
  uint8_t c2[SEEDBYTES];
  poly cp;
  polyvecl mat[K], z;
  polyveck t1, w1, h;
  keccak_state state;

  if(siglen != CRYPTO_BYTES)
    return -1;

  unpack_pk(rho, &t1, pk);
  if(unpack_sig(c, &z, &h, sig))
    return -1;
  if(polyvecl_chknorm(&z, GAMMA1 - BETA))
    return -1;

  /* Compute CRH(H(rho, t1), msg) */
  shake256(mu, SEEDBYTES, pk, CRYPTO_PUBLICKEYBYTES);
  shake256_init(&state);
  shake256_absorb(&state, mu, SEEDBYTES);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, CRHBYTES, &state);

  /* Matrix-vector multiplication; compute Az - c2^dt1 */
  poly_challenge(&cp, c);
  polyvec_matrix_expand(mat, rho);

  polyvecl_ntt(&z, 0);
  polyvec_matrix_pointwise_montgomery(&w1, mat, &z);

  poly_ntt(&cp, 0);
  polyveck_shiftl(&t1);
  polyveck_ntt(&t1, 0);
  polyveck_pointwise_poly_montgomery(&t1, &cp, &t1);

  polyveck_sub(&w1, &w1, &t1);
  polyveck_reduce(&w1);
  polyveck_invntt_tomont(&w1, 0);

  /* Reconstruct w1 */
  polyveck_caddq(&w1);
  polyveck_use_hint(&w1, &w1, &h);
  polyveck_pack_w1(buf, &w1);

  /* Call random oracle and verify challenge */
  shake256_init(&state);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_absorb(&state, buf, K*POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(c2, SEEDBYTES, &state);

  #if(PROTECT_VERIFY_COMPARE == 1)

    uint8_t cmp_r_value;
    int final_commpare_value = 0xCDCDCDCD;

    randombytes(&cmp_r_value, 1);
    while(cmp_r_value == 0)
    {
      randombytes(&cmp_r_value, 1);
    }

    final_commpare_value = 0;
    original_verify_final_commpare_value = cmp_r_value * SEEDBYTES;

    int ret_from_compare = 0;
    ret_from_compare = compare_c_poly_in_verify_fia(sig, c2, &cmp_r_value, &final_commpare_value);

    if(ret_from_compare == -1)
    {
      return -1;
    }

    return final_commpare_value;

  #else

    for(i = 0; i < SEEDBYTES; ++i)
    {
      if(sig[i] != c2[i])
      {
        return -1;
      }
    }
    return 0;

  #endif

  return 0;
}

/*************************************************
* Name:        crypto_sign_open
*
* Description: Verify signed message.
*
* Arguments:   - uint8_t *m: pointer to output message (allocated
*                            array with smlen bytes), can be equal to sm
*              - size_t *mlen: pointer to output length of message
*              - const uint8_t *sm: pointer to signed message
*              - size_t smlen: length of signed message
*              - const uint8_t *pk: pointer to bit-packed public key
*
* Returns 0 if signed message could be verified correctly and -1 otherwise
**************************************************/

#pragma GCC push_options
#pragma GCC optimize ("O0")

int crypto_sign_open(uint8_t *m,
                     size_t *mlen,
                     const uint8_t *sm,
                     size_t smlen,
                     const uint8_t *pk)
{
  size_t i;

  if(smlen < CRYPTO_BYTES)
    goto badsig;

  #if(PROTECT_VERIFY_COMPARE == 1)

  int ret_value;
  *mlen = smlen - CRYPTO_BYTES;
  ret_value = crypto_sign_verify(sm, CRYPTO_BYTES, sm + CRYPTO_BYTES, *mlen, pk);

  if(ret_value != original_verify_final_commpare_value)
  {
    goto badsig;
  }
  else
  {
    /* All good, copy msg, return 0 */
    for(i = 0; i < *mlen; ++i)
    {
      if(ret_value == original_verify_final_commpare_value)
      {
        m[i] = sm[CRYPTO_BYTES + i];
      }
    }
    return ret_value - original_verify_final_commpare_value;
  }

  #else

  *mlen = smlen - CRYPTO_BYTES;
  if(crypto_sign_verify(sm, CRYPTO_BYTES, sm + CRYPTO_BYTES, *mlen, pk))
  {
    goto badsig;
  }
  else
  {
    /* All good, copy msg, return 0 */
    for(i = 0; i < *mlen; ++i)
        m[i] = sm[CRYPTO_BYTES + i];
    return 0;
  }

  #endif

badsig:
  /* Signature verification failed */
  *mlen = -1;
  for(i = 0; i < smlen; ++i)
    m[i] = 0;

  return -1;
}

#pragma GCC pop_options
