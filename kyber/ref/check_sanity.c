#include <math.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include "params.h"
#include "check_sanity.h"
#include "poly.h"
#include "polyvec.h"

#define EXPECTED_MEAN_U   1663
#define DEV_MEAN_U 60

#define EXPECTED_STD_DEV_U  959
#define DEV_STD_DEV_U 27

#define EXPECTED_MEAN_V   1560
#define DEV_MEAN_V 60

#define EXPECTED_STD_DEV_V  957
#define DEV_STD_DEV_V 27

#define TAIL_COVERAGE 6

#define STANDARD_DEV_OF_MP 79
#define TAIL_COVERAGE_OF_MP 6

static int64_t calculateMEAN(const poly * a)
{
    // float summ = 0.0, meann;
    int64_t summ = 0, meann;
    int i;

    for (i = 0; i < KYBER_N; ++i)
    {
        summ = summ + a->coeffs[i];
    }
    meann = summ / KYBER_N;

    return meann;
}

static int64_t calculateSD(const poly * a, int64_t meann)
{
    int64_t SD = 0;
    int i;
    int64_t int_mean_diff;

    for (i = 0; i < KYBER_N; ++i)
    {
        int_mean_diff = (a->coeffs[i] - meann);
        SD = SD + int_mean_diff * int_mean_diff;
    }
    return (SD / KYBER_N);

}

int check_mp_sanity(const poly * v)
{
  // Here, I need to calculate the mean, standard deviation...

  int span_to_consider = TAIL_COVERAGE_OF_MP*STANDARD_DEV_OF_MP;
  int flag_ok = 0;
  int i;
  int coeff_now;

  for (i = 0; i < KYBER_N; ++i)
  {
    coeff_now = v->coeffs[i];

    // if(abs(coeff_now) > 3*KYBER_Q/4)
    //   coeff_now = coeff_now + KYBER_Q;

    if(((coeff_now >= (0 + span_to_consider)) && (coeff_now <= (KYBER_Q/2 - span_to_consider))) || ((coeff_now >= (KYBER_Q/2 + span_to_consider)) && (coeff_now <= (KYBER_Q - span_to_consider))))
      flag_ok = flag_ok+1;

    // if((coeff_now >= (KYBER_Q/2 + span_to_consider)) && (coeff_now <= (KYBER_Q - span_to_consider)))
    //   flag_ok = flag_ok+1;


    // if(!((coeff_now <= (0 + TAIL_COVERAGE_OF_MP*STANDARD_DEV_OF_MP)
    //           && coeff_now >= (KYBER_Q - TAIL_COVERAGE_OF_MP*STANDARD_DEV_OF_MP))
    //           || (coeff_now <= (KYBER_Q/2 + TAIL_COVERAGE_OF_MP*STANDARD_DEV_OF_MP)
    //                     && coeff_now >= (KYBER_Q/2 - TAIL_COVERAGE_OF_MP*STANDARD_DEV_OF_MP))
    //         ))
    // {
    //   flag_ok = flag_ok+1;
    // }

    // if(!(coeff_now <= (0 + TAIL_COVERAGE_OF_MP*STANDARD_DEV_OF_MP)
    //           && coeff_now >= (0 - TAIL_COVERAGE_OF_MP*STANDARD_DEV_OF_MP))
    //         )
    // {
    //   flag_ok = flag_ok+1;
    // }
    //
    // if(!((coeff_now <= (0 + TAIL_COVERAGE_OF_MP*STANDARD_DEV_OF_MP)
    //           && coeff_now >= (0 - TAIL_COVERAGE_OF_MP*STANDARD_DEV_OF_MP))
    //           || (coeff_now <= (KYBER_Q/2 + TAIL_COVERAGE_OF_MP*STANDARD_DEV_OF_MP)
    //                     && coeff_now >= (KYBER_Q/2 - TAIL_COVERAGE_OF_MP*STANDARD_DEV_OF_MP))
    //         ))
    // {
    //   flag_ok = flag_ok+1;
    // }

  }

  return flag_ok;
}

int check_ct_sanity(const polyvec * u, const poly * v)
{
  // Here, I need to calculate the mean, standard deviation...

  int flag_ok = 0;
  int64_t mean_check, std_check;

  int ii, jj;

  int64_t u_mean_check_1 = EXPECTED_MEAN_U + TAIL_COVERAGE*DEV_MEAN_U;
  int64_t u_mean_check_2 = EXPECTED_MEAN_U - TAIL_COVERAGE*DEV_MEAN_U;
  int64_t u_std_check_1 = (EXPECTED_STD_DEV_U + TAIL_COVERAGE*DEV_STD_DEV_U) * (EXPECTED_STD_DEV_U + TAIL_COVERAGE*DEV_STD_DEV_U);
  int64_t u_std_check_2 = (EXPECTED_STD_DEV_U - TAIL_COVERAGE*DEV_STD_DEV_U) * (EXPECTED_STD_DEV_U - TAIL_COVERAGE*DEV_STD_DEV_U);

  int64_t v_mean_check_1 = EXPECTED_MEAN_V + TAIL_COVERAGE*DEV_MEAN_V;
  int64_t v_mean_check_2 = EXPECTED_MEAN_V - TAIL_COVERAGE*DEV_MEAN_V;
  int64_t v_std_check_1 = (EXPECTED_STD_DEV_V + TAIL_COVERAGE*DEV_STD_DEV_V) * (EXPECTED_STD_DEV_V + TAIL_COVERAGE*DEV_STD_DEV_V);
  int64_t v_std_check_2 = (EXPECTED_STD_DEV_V - TAIL_COVERAGE*DEV_STD_DEV_V) * (EXPECTED_STD_DEV_V - TAIL_COVERAGE*DEV_STD_DEV_V);


  for(ii = 0; ii < KYBER_K; ii++)
  {
    mean_check = calculateMEAN(u->vec+ii);
    std_check = calculateSD(u->vec+ii, mean_check);

    if((mean_check >= u_mean_check_1) || (mean_check <= u_mean_check_2))
    {
      flag_ok = flag_ok+1;
    }

    // if(mean_check <= u_mean_check_2)
    // {
    //   flag_ok = flag_ok+1;
    // }


    if((std_check >= u_std_check_1) || (std_check <= u_std_check_2))
    {
      flag_ok = flag_ok+1;
    }

    // if(std_check <= u_std_check_2)
    // {
    //   flag_ok = flag_ok+1;
    // }


  }

  mean_check = calculateMEAN(&v->coeffs);
  std_check = calculateSD(&v->coeffs, mean_check);


  if((mean_check >= v_mean_check_1) || (mean_check <= v_mean_check_2))
  {
    flag_ok = flag_ok+1;
  }

  // if(mean_check <= v_mean_check_2)
  // {
  //   flag_ok = flag_ok+1;
  // }


  if((std_check >= v_std_check_1) || (std_check <= v_std_check_2))
  {
    flag_ok = flag_ok+1;
  }

  // if(std_check <= v_std_check_2)
  // {
  //   flag_ok = flag_ok+1;
  // }



  return flag_ok;
}
