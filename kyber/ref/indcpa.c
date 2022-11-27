#include <stddef.h>
#include <stdint.h>
#include "params.h"
#include "indcpa.h"
#include "polyvec.h"
#include "poly.h"
#include "ntt.h"
#include "symmetric.h"
#include "randombytes.h"
#include "sca_fia_protection.h"
#include "check_sanity.h"

unsigned char init_rand_value = 0xAB;

/*************************************************
* Name:        pack_pk
*
* Description: Serialize the public key as concatenation of the
*              serialized vector of polynomials pk
*              and the public seed used to generate the matrix A.
*
* Arguments:   uint8_t *r: pointer to the output serialized public key
*              polyvec *pk: pointer to the input public-key polyvec
*              const uint8_t *seed: pointer to the input public seed
**************************************************/
static void pack_pk(uint8_t r[KYBER_INDCPA_PUBLICKEYBYTES],
                    polyvec *pk,
                    const uint8_t seed[KYBER_SYMBYTES])
{
  size_t i;
  polyvec_tobytes(r, pk);
  for(i=0;i<KYBER_SYMBYTES;i++)
    r[i+KYBER_POLYVECBYTES] = seed[i];
}

#pragma GCC push_options
#pragma GCC optimize ("O0")

void pack_pk_fia(uint8_t r[KYBER_INDCPA_PUBLICKEYBYTES], polyvec *pk, const uint8_t seed[KYBER_SYMBYTES], int cmp_value_1, int cmp_value_2, int output_from_check_s_and_e)
{
  size_t i;
  // polyvec_tobytes(r, pk);
  for(i=0;i<KYBER_K;i++)
    poly_tobytes_fia(r+i*KYBER_POLYBYTES, &pk->vec[i], cmp_value_1, cmp_value_2, output_from_check_s_and_e);

  for(i=0;i<KYBER_SYMBYTES;i++)
    r[i+KYBER_POLYVECBYTES] = seed[i];
}

#pragma GCC pop_options

/*************************************************
* Name:        unpack_pk
*
* Description: De-serialize public key from a byte array;
*              approximate inverse of pack_pk
*
* Arguments:   - polyvec *pk: pointer to output public-key polynomial vector
*              - uint8_t *seed: pointer to output seed to generate matrix A
*              - const uint8_t *packedpk: pointer to input serialized public key
**************************************************/
static void unpack_pk(polyvec *pk,
                      uint8_t seed[KYBER_SYMBYTES],
                      const uint8_t packedpk[KYBER_INDCPA_PUBLICKEYBYTES])
{
  size_t i;
  polyvec_frombytes(pk, packedpk);
  for(i=0;i<KYBER_SYMBYTES;i++)
    seed[i] = packedpk[i+KYBER_POLYVECBYTES];
}

/*************************************************
* Name:        pack_sk
*
* Description: Serialize the secret key
*
* Arguments:   - uint8_t *r: pointer to output serialized secret key
*              - polyvec *sk: pointer to input vector of polynomials (secret key)
**************************************************/
static void pack_sk(uint8_t r[KYBER_INDCPA_SECRETKEYBYTES], polyvec *sk)
{
  polyvec_tobytes(r, sk);
}

#pragma GCC push_options
#pragma GCC optimize ("O0")

void pack_sk_fia(uint8_t r[KYBER_INDCPA_SECRETKEYBYTES], polyvec *sk, int cmp_value_1, int cmp_value_2, int output_from_check_s_and_e)
{
  size_t i;
  // polyvec_tobytes(r, sk);
  for(i=0;i<KYBER_K;i++)
    poly_tobytes_fia(r+i*KYBER_POLYBYTES, &sk->vec[i], cmp_value_1, cmp_value_2, output_from_check_s_and_e);
}

#pragma GCC pop_options

/*************************************************
* Name:        unpack_sk
*
* Description: De-serialize the secret key; inverse of pack_sk
*
* Arguments:   - polyvec *sk: pointer to output vector of polynomials (secret key)
*              - const uint8_t *packedsk: pointer to input serialized secret key
**************************************************/
static void unpack_sk(polyvec *sk, const uint8_t packedsk[KYBER_INDCPA_SECRETKEYBYTES])
{
  polyvec_frombytes(sk, packedsk);
}

/*************************************************
* Name:        pack_ciphertext
*
* Description: Serialize the ciphertext as concatenation of the
*              compressed and serialized vector of polynomials b
*              and the compressed and serialized polynomial v
*
* Arguments:   uint8_t *r: pointer to the output serialized ciphertext
*              poly *pk: pointer to the input vector of polynomials b
*              poly *v: pointer to the input polynomial v
**************************************************/
static void pack_ciphertext(uint8_t r[KYBER_INDCPA_BYTES], polyvec *b, poly *v)
{
  polyvec_compress(r, b);
  poly_compress(r+KYBER_POLYVECCOMPRESSEDBYTES, v);
}

/*************************************************
* Name:        unpack_ciphertext
*
* Description: De-serialize and decompress ciphertext from a byte array;
*              approximate inverse of pack_ciphertext
*
* Arguments:   - polyvec *b: pointer to the output vector of polynomials b
*              - poly *v: pointer to the output polynomial v
*              - const uint8_t *c: pointer to the input serialized ciphertext
**************************************************/
static void unpack_ciphertext(polyvec *b, poly *v, const uint8_t c[KYBER_INDCPA_BYTES])
{
  polyvec_decompress(b, c);
  poly_decompress(v, c+KYBER_POLYVECCOMPRESSEDBYTES);
}

/*************************************************
* Name:        rej_uniform
*
* Description: Run rejection sampling on uniform random bytes to generate
*              uniform random integers mod q
*
* Arguments:   - int16_t *r: pointer to output buffer
*              - unsigned int len: requested number of 16-bit integers (uniform mod q)
*              - const uint8_t *buf: pointer to input buffer (assumed to be uniformly random bytes)
*              - unsigned int buflen: length of input buffer in bytes
*
* Returns number of sampled 16-bit integers (at most len)
**************************************************/
static unsigned int rej_uniform(int16_t *r,
                                unsigned int len,
                                const uint8_t *buf,
                                unsigned int buflen)
{
  unsigned int ctr, pos;
  uint16_t val0, val1;

  ctr = pos = 0;
  while(ctr < len && pos + 3 <= buflen) {
    val0 = ((buf[pos+0] >> 0) | ((uint16_t)buf[pos+1] << 8)) & 0xFFF;
    val1 = ((buf[pos+1] >> 4) | ((uint16_t)buf[pos+2] << 4)) & 0xFFF;
    pos += 3;

    if(val0 < KYBER_Q)
      r[ctr++] = val0;
    if(ctr < len && val1 < KYBER_Q)
      r[ctr++] = val1;
  }

  return ctr;
}

#define gen_a(A,B)  gen_matrix(A,B,0)
#define gen_at(A,B) gen_matrix(A,B,1)

/*************************************************
* Name:        gen_matrix
*
* Description: Deterministically generate matrix A (or the transpose of A)
*              from a seed. Entries of the matrix are polynomials that look
*              uniformly random. Performs rejection sampling on output of
*              a XOF
*
* Arguments:   - polyvec *a: pointer to ouptput matrix A
*              - const uint8_t *seed: pointer to input seed
*              - int transposed: boolean deciding whether A or A^T is generated
**************************************************/
#define GEN_MATRIX_NBLOCKS ((12*KYBER_N/8*(1 << 12)/KYBER_Q + XOF_BLOCKBYTES)/XOF_BLOCKBYTES)
// Not static for benchmarking
void gen_matrix(polyvec *a, const uint8_t seed[KYBER_SYMBYTES], int transposed)
{
  unsigned int ctr, i, j, k;
  unsigned int buflen, off;
  uint8_t buf[GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES+2];
  xof_state state;

  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_K;j++) {
      if(transposed)
        xof_absorb(&state, seed, i, j);
      else
        xof_absorb(&state, seed, j, i);

      xof_squeezeblocks(buf, GEN_MATRIX_NBLOCKS, &state);
      buflen = GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES;
      ctr = rej_uniform(a[i].vec[j].coeffs, KYBER_N, buf, buflen);

      while(ctr < KYBER_N) {
        off = buflen % 3;
        for(k = 0; k < off; k++)
          buf[k] = buf[buflen - off + k];
        xof_squeezeblocks(buf + off, 1, &state);
        buflen = off + XOF_BLOCKBYTES;
        ctr += rej_uniform(a[i].vec[j].coeffs + ctr, KYBER_N - ctr, buf, buflen);
      }
    }
  }
}



#pragma GCC push_options
#pragma GCC optimize ("O0")

static int check_s_and_e(polyvec *skpv, polyvec *ekpv, uint8_t * c, int * r)
{

  int i,j,k,ww;

  int same_count_now = 0;
  int some_polynomial_same = init_rand_value;

  // randomly take s[0] and compare with s[1] to s[K-1]...

  uint8_t random_index;

  for(i = 0; i < KYBER_K; i++)
  {
    for(j = i; j < KYBER_K; j++)
    {
      same_count_now = 0;
      if(i == j)
        continue;
      for(k = 0; k < NO_RAND_CHECK; k++)
      {
        randombytes(&random_index,1);
        *r = *r + *c;
        if(skpv->vec[i].coeffs[random_index] == skpv->vec[j].coeffs[random_index])
        {
          same_count_now = same_count_now + 1;
        }
      }
      for(ww = 0; ww < FAULT_REPET; ww++)
      {
        if(same_count_now == NO_RAND_CHECK)
        {
          some_polynomial_same = some_polynomial_same + init_rand_value;
          *r = *r + *c;
        }
        else
        {
          *r = *r + *c;
        }
      }
    }
  }

  // randomly take e[0] and compare with e[1] to e[K-1]...

  for(i = 0; i < KYBER_K; i++)
  {
    for(j = i; j < KYBER_K; j++)
    {
      same_count_now = 0;
      if(i == j)
        continue;
      for(k = 0; k < NO_RAND_CHECK; k++)
      {
        randombytes(&random_index,1);
        *r = *r + *c;
        if(ekpv->vec[i].coeffs[random_index] == ekpv->vec[j].coeffs[random_index])
        {
          same_count_now = same_count_now + 1;
        }
      }
      for(ww = 0; ww < FAULT_REPET; ww++)
      {
        if(same_count_now == NO_RAND_CHECK)
        {
          some_polynomial_same = some_polynomial_same + init_rand_value;
          *r = *r + *c;
        }
        else
        {
          *r = *r + *c;
        }
      }
    }
  }

  // compare s and e...

  for(i = 0; i < KYBER_K; i++)
  {
    for(j = 0; j < KYBER_K; j++)
    {
      same_count_now = 0;

      for(k = 0; k < NO_RAND_CHECK; k++)
      {
        randombytes(&random_index,1);
        *r = *r + *c;
        if(skpv->vec[i].coeffs[random_index] == ekpv->vec[j].coeffs[random_index])
        {
          same_count_now = same_count_now + 1;
        }
      }
      for(ww = 0; ww < FAULT_REPET; ww++)
      {
        if(same_count_now == NO_RAND_CHECK)
        {
          some_polynomial_same = some_polynomial_same + init_rand_value;
          *r = *r + *c;
        }
        else
        {
          *r = *r + *c;
        }
      }
    }
  }

  return some_polynomial_same;

}

static void copy_public_seed(uint8_t * pk, uint8_t * publicseed, int final_cmp_value, int final_cmp_value_we_calculate, int output_from_check_s_and_e)
{

  int i;

  for (i = 0; i < KYBER_SYMBYTES; i++)
  {
    if((final_cmp_value == final_cmp_value_we_calculate) && (output_from_check_s_and_e == 0))
    {
      *(pk + KYBER_POLYVECBYTES + i) = *(publicseed + i);
    }
    else
    {
      *(pk + KYBER_POLYVECBYTES + i) = 0xAB;
    }
  }

}

#pragma GCC pop_options


/*************************************************
* Name:        indcpa_keypair
*
* Description: Generates public and private key for the CPA-secure
*              public-key encryption scheme underlying Kyber
*
* Arguments:   - uint8_t *pk: pointer to output public key
*                             (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key
                              (of length KYBER_INDCPA_SECRETKEYBYTES bytes)
**************************************************/

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
    temp = (shift_lfsr(&lfsr_1, POLY_MASK_HERE_1) ^ shift_lfsr(&lfsr_2, POLY_MASK_HERE_2)) & 0xFFFF;
    return (temp);
}

void indcpa_keypair(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                    uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES])
{
  unsigned int i;
  uint8_t buf[2*KYBER_SYMBYTES];
  const uint8_t *publicseed = buf;
  const uint8_t *noiseseed = buf+KYBER_SYMBYTES;
  uint8_t nonce = 0;
  polyvec a[KYBER_K], e, pkpv, skpv;


  #if (NONCE_FAULT_CHECK == 1)

  unsigned char cmp_r_value = 0xAB;
  int final_cmp_value = 0xCDCDCDCD;
  int final_cmp_value_we_calculate = 0;
  int output_from_check_s_and_e = 0xABABABAB;

  #endif

  randombytes(buf, KYBER_SYMBYTES);
  hash_g(buf, buf, KYBER_SYMBYTES);

  gen_a(a, publicseed);

  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta1(&skpv.vec[i], noiseseed, nonce++);
  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta1(&e.vec[i], noiseseed, nonce++);


  #if (NONCE_FAULT_CHECK == 1)

  randombytes(&cmp_r_value, 1);
  while(cmp_r_value == 0)
  {
    randombytes(&cmp_r_value, 1);
  }

  randombytes(&init_rand_value, 1);
  while(init_rand_value == 0)
  {
    randombytes(&init_rand_value, 1);
  }

  final_cmp_value = cmp_r_value * (NO_RAND_CHECK + FAULT_REPET) * (KYBER_K * (KYBER_K - 1) + KYBER_K * KYBER_K);
  output_from_check_s_and_e = check_s_and_e(&skpv, &e, &cmp_r_value, &final_cmp_value_we_calculate);

  #endif

  polyvec_ntt(&skpv, 1);
  polyvec_ntt(&e, 1);

  // matrix-vector multiplication
  for(i=0;i<KYBER_K;i++)
  {
    polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a[i], &skpv);
    poly_tomont(&pkpv.vec[i]);
  }

  polyvec_add(&pkpv, &pkpv, &e);
  polyvec_reduce(&pkpv);

  #if (NONCE_FAULT_CHECK == 1)

  pack_sk_fia(sk, &skpv, final_cmp_value, final_cmp_value_we_calculate, output_from_check_s_and_e);
  pack_pk_fia(pk, &pkpv, publicseed, final_cmp_value, final_cmp_value_we_calculate, output_from_check_s_and_e);

  #else

  pack_sk(sk, &skpv);
  pack_pk(pk, &pkpv, publicseed);

  #endif
}

/*************************************************
* Name:        indcpa_enc
*
* Description: Encryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - uint8_t *c: pointer to output ciphertext
*                            (of length KYBER_INDCPA_BYTES bytes)
*              - const uint8_t *m: pointer to input message
*                                  (of length KYBER_INDCPA_MSGBYTES bytes)
*              - const uint8_t *pk: pointer to input public key
*                                   (of length KYBER_INDCPA_PUBLICKEYBYTES)
*              - const uint8_t *coins: pointer to input random coins used as seed
*                                      (of length KYBER_SYMBYTES) to deterministically
*                                      generate all randomness
**************************************************/
void indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[KYBER_SYMBYTES])
{
  unsigned int i;
  uint8_t seed[KYBER_SYMBYTES];
  uint8_t nonce = 0;
  polyvec sp, pkpv, ep, at[KYBER_K], b;
  poly v, k, epp;

  unpack_pk(&pkpv, seed, pk);
  poly_frommsg(&k, m);
  gen_at(at, seed);

  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta1(sp.vec+i, coins, nonce++);
  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta2(ep.vec+i, coins, nonce++);
  poly_getnoise_eta2(&epp, coins, nonce++);

  polyvec_ntt(&sp, 1);

  // matrix-vector multiplication
  for(i=0;i<KYBER_K;i++)
    polyvec_basemul_acc_montgomery(&b.vec[i], &at[i], &sp);

  polyvec_basemul_acc_montgomery(&v, &pkpv, &sp);

  polyvec_invntt_tomont(&b, 1);
  poly_invntt_tomont(&v, 1);

  polyvec_add(&b, &b, &ep);
  poly_add(&v, &v, &epp);
  poly_add(&v, &v, &k);
  polyvec_reduce(&b);
  poly_reduce(&v);

  pack_ciphertext(c, &b, &v);
}

/*************************************************
* Name:        indcpa_dec
*
* Description: Decryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - uint8_t *m: pointer to output decrypted message
*                            (of length KYBER_INDCPA_MSGBYTES)
*              - const uint8_t *c: pointer to input ciphertext
*                                  (of length KYBER_INDCPA_BYTES)
*              - const uint8_t *sk: pointer to input secret key
*                                   (of length KYBER_INDCPA_SECRETKEYBYTES)
**************************************************/
// void indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
//                 const uint8_t c[KYBER_INDCPA_BYTES],
//                 const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES])
// {
//   polyvec b, skpv;
//   poly v, mp;
//
//   unpack_ciphertext(&b, &v, c);
//   unpack_sk(&skpv, sk);
//
//   polyvec_ntt(&b);
//   polyvec_basemul_acc_montgomery(&mp, &skpv, &b);
//   poly_invntt_tomont(&mp);
//
//   poly_sub(&mp, &v, &mp);
//   poly_reduce(&mp);
//
//   poly_tomsg(m, &mp);
// }


void indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES])
{
  polyvec b, skpv;
  poly v, mp;

  unpack_ciphertext(&b, &v, c);

  #if (CT_SANITY_CHECK == 1)

  int ct_sanity_ok;
  ct_sanity_ok = check_ct_sanity(&b, &v);

  if(ct_sanity_ok > 0)
  {
    for(int jj = 0; jj < KYBER_INDCPA_MSGBYTES; jj++)
    {
      m[jj] = 0x55;
    }

    printf("Failed ct sanity Check...\n");

  }
  else
  {
    printf("Passed ct sanity Check...\n");

    unpack_sk(&skpv, sk);

    polyvec_ntt(&b, 0);
    polyvec_basemul_acc_montgomery(&mp, &skpv, &b);
    poly_invntt_tomont(&mp, 1);

    poly_sub(&mp, &v, &mp);
    poly_reduce(&mp);

    #if (MP_SANITY_CHECK == 1)

    int mp_sanity_ok;
    mp_sanity_ok = check_mp_sanity(&mp);

    if(mp_sanity_ok > 0)
    {
      printf("Failed mp sanity Check...\n");
    }
    else
    {
      printf("Passed mp sanity Check...\n");
    }

    #endif

    poly_tomsg(m, &mp);
  }

  #endif

}
