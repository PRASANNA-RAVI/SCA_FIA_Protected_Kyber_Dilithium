#ifndef SANITY_CHECK_H
#define SANITY_CHECK_H

#include "params.h"
#include <stdint.h>
#include "poly.h"
#include "polyvec.h"

int check_mp_sanity(const poly * v);
int check_ct_sanity(const polyvec * u, const poly * v);

#endif
