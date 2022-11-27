"""
Slightly adapted version of proba_util in https://github.com/pq-crystals/kyber/

Authors: Joppe Bos,
         Leo Ducas,
         Eike Kiltz ,
         Tancrede Lepoint,
         Vadim Lyubashevsky,
         John Schanck,
         Peter Schwabe,
         Gregor Seiler,
         Damien Stehle
"""

from math import factorial as fac
from math import log, ceil, erf, sqrt
import scipy.stats

# build pdf's


def binomial(x, y):
    """ Binomial coefficient
    :param x: (integer)
    :param y: (integer)
    :returns: y choose x
    """
    try:
        binom = fac(x) // fac(y) // fac(x - y)
    except ValueError:
        binom = 0
    return binom


def centered_binomial_pdf(k, x):
    """ Probability density function of the centered binomial law of param k at x
    :param k: (integer)
    :param x: (integer)
    :returns: p_k(x)
    """
    return binomial(2 * k, x + k) / 2.**(2 * k)


def build_centered_binomial_law(k):
    """ Construct the binomial law as a dictionnary
    :param k: (integer)
    :param x: (integer)
    :returns: A dictionnary {x:p_k(x) for x in {-k..k}}
    """
    D = {}
    for i in range(-k, k + 1):
        D[i] = centered_binomial_pdf(k, i)
    return D

def build_gaussian(var):
    D = {}
    sum = 0
    for i in range(-4*var, 4*var, 10):
        tmp = scipy.stats.norm.pdf(i, loc=0, scale=var**0.5)
        D[i] = tmp
        sum += tmp

    for i in D.keys():
        D[i] = D[i] / sum

    return clean_dist(D)


def mod_switch(x, q, rq):
    """ Modulus switching (rounding to a different discretization of the Torus)
    :param x: value to round (integer)
    :param q: input modulus (integer)
    :param rq: output modulus (integer)
    """
    return int(round(1. * rq * x / q + 0.00001) % rq)


def mod_centered(x, q):
    """ reduction mod q, centered (ie represented in -q/2 .. q/2)
    :param x: value to round (integer)
    :param q: input modulus (integer)
    """
    a = x % q
    if a < q / 2:
        return a
    return a - q


def build_mod_switching_error_law(q, rq):
    """ Construct Error law: law of the difference introduced by switching from and back a uniform value mod q
    :param q: original modulus (integer)
    :param rq: intermediate modulus (integer)
    """
    D = {}
    V = {}
    for x in range(q):
        y = mod_switch(x, q, rq)
        z = mod_switch(y, rq, q)
        d = mod_centered(x - z, q)
        D[d] = D.get(d, 0) + 1. / q
        V[y] = V.get(y, 0) + 1

    return D


def law_convolution(A, B):
    """ Construct the convolution of two laws (sum of independent variables from two input laws)
    :param A: first input law (dictionnary)
    :param B: second input law (dictionnary)
    """

    C = {}
    for a in A:
        for b in B:
            c = a + b
            C[c] = C.get(c, 0) + A[a] * B[b]
    C = clean_dist(C)
    return C


def law_product(A, B):
    """ Construct the law of the product of independent variables from two input laws
    :param A: first input law (dictionnary)
    :param B: second input law (dictionnary)
    """
    C = {}
    for a in A:
        for b in B:
            c = a * b
            C[c] = C.get(c, 0) + A[a] * B[b]
    return C


def clean_dist(A):
    """ Clean a distribution to accelerate further computation (drop element of the support with proba less than 2^-300)
    :param A: input law (dictionnary)
    """        
    B = {}
    for (x, y) in A.items():
        if y>2**(-300):
            B[x] = y
    return B


def iter_law_convolution(A, i):
    """ compute the -ith forld convolution of a distribution (using double-and-add)
    :param A: first input law (dictionnary)
    :param i: (integer)
    """
    D = {0: 1.0}
    i_bin = bin(i)[2:]  # binary representation of n
    for ch in i_bin:
        D = law_convolution(D, D)
        D = clean_dist(D)
        if ch == '1':
            D = law_convolution(D, A)
            D = clean_dist(D)
    return D


