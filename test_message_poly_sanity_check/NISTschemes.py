from dist import Dist
from math import sqrt
from proba_util import build_centered_binomial_law, build_mod_switching_error_law


# FRODOKEM
FrodoKEM640 = {}
FrodoKEM640['thres'] = (2**15) / 2**3
FrodoKEM640['s'] = Dist({-11: 4.57763671875e-05, -10: 0.0001983642578125, -9: 0.0007171630859375, -8: 0.002197265625, -7: 0.005859375, -6: 0.013702392578125, -5: 0.02813720703125, -4: 0.0506744384765625, -3: 0.0800933837890625, -2: 0.111083984375, -1: 0.1351470947265625,
                    0: 0.144287109375, 1: 0.1351470947265625, 2: 0.111083984375, 3: 0.0800933837890625, 4: 0.0506744384765625, 5: 0.02813720703125, 6: 0.013702392578125, 7: 0.005859375, 8: 0.002197265625, 9: 0.0007171630859375, 10: 0.0001983642578125, 11: 4.57763671875e-05})
FrodoKEM640['e'] = FrodoKEM640['s']
FrodoKEM640['sprime'] = FrodoKEM640['s']
FrodoKEM640['eprime'] = FrodoKEM640['s']
FrodoKEM640['eprimeprime'] = FrodoKEM640['s']
FrodoKEM640['n'] = 640
FrodoKEM640['n2'] = 8
FrodoKEM640['n3'] = 8
FrodoKEM640['name'] = 'FrodoKEM-640'

FrodoKEM976 = {}
FrodoKEM976['thres'] = (2**16) / 2**4
FrodoKEM976['s'] = Dist({-10: 1.52587890625e-05, -9: 9.1552734375e-05, -8: 0.0004425048828125, -7: 0.001800537109375, -6: 0.00604248046875, -5: 0.0167999267578125, -4: 0.0388336181640625, -3: 0.074493408203125, -2: 0.118621826171875, -1: 0.1568145751953125,
                    0: 0.172088623046875, 1: 0.1568145751953125, 2: 0.118621826171875, 3: 0.074493408203125, 4: 0.0388336181640625, 5: 0.0167999267578125, 6: 0.00604248046875, 7: 0.001800537109375, 8: 0.0004425048828125, 9: 9.1552734375e-05, 10: 1.52587890625e-05})
FrodoKEM976['e'] = FrodoKEM976['s']
FrodoKEM976['sprime'] = FrodoKEM976['s']
FrodoKEM976['eprime'] = FrodoKEM976['s']
FrodoKEM976['eprimeprime'] = FrodoKEM976['s']
FrodoKEM976['n'] = 976
FrodoKEM976['n2'] = 8
FrodoKEM640['n3'] = 8
FrodoKEM976['name'] = 'FrodoKEM-976'


# Kyber
Kyber512 = {}
Kyber512['thres'] = 3329 / 2**2
Kyber512['s'] = Dist(build_centered_binomial_law(3))
Kyber512['e'] = Dist(build_centered_binomial_law(3))
u = Dist(build_mod_switching_error_law(3329, 2**10))
Kyber512['sprime'] = Dist(build_centered_binomial_law(3))
Kyber512['eprime'] = Dist(build_centered_binomial_law(2)) + u
u2 = Dist(build_mod_switching_error_law(3329, 2**4))
Kyber512['eprimeprime'] = Kyber512['sprime'] + u2
Kyber512['n'] = 256 * 2
Kyber512['n2'] = 256
Kyber512['AES'] = 2**128
Kyber512['name'] = 'Kyber512'

Kyber512_r2 = {}
Kyber512_r2['thres'] = 3329 / 2**2
Kyber512_r2['s'] = Dist(build_centered_binomial_law(2))
Kyber512_r2['e'] = Dist(build_centered_binomial_law(2))
u = Dist(build_mod_switching_error_law(3329, 2**10))
Kyber512_r2['sprime'] = Dist(build_centered_binomial_law(2))
Kyber512_r2['eprime'] = Dist(build_centered_binomial_law(2)) + u
u2 = Dist(build_mod_switching_error_law(3329, 2**3))
Kyber512_r2['eprimeprime'] = Kyber512_r2['sprime'] + u2
Kyber512_r2['n'] = 256 * 2
Kyber512_r2['n2'] = 256
Kyber512_r2['AES'] = 2**128
Kyber512_r2['name'] = 'Kyber512_r2'

Kyber768 = {}
Kyber768['thres'] = 3329 / 2**2
Kyber768['s'] = Dist(build_centered_binomial_law(2))
Kyber768['e'] = Kyber768['s']
u = Dist(build_mod_switching_error_law(3329, 2**10))
Kyber768['sprime'] = Dist(build_centered_binomial_law(2))
Kyber768['eprime'] = Kyber768['sprime'] + u
u2 = Dist(build_mod_switching_error_law(3329, 2**4))
Kyber768['eprimeprime'] = Kyber768['sprime'] + u2
Kyber768['n'] = 256 * 3
Kyber768['n2'] = 256
Kyber768['AES'] = 2**192
Kyber768['name'] = 'Kyber768'

Kyber1024 = {}
Kyber1024['thres'] = 3329 / 2**2
Kyber1024['s'] = Dist(build_centered_binomial_law(2))
Kyber1024['e'] = Kyber1024['s']
u = Dist(build_mod_switching_error_law(3329, 2**11))
Kyber1024['sprime'] = Kyber1024['s']
Kyber1024['eprime'] = Kyber1024['s'] + u
u2 = Dist(build_mod_switching_error_law(3329, 2**5))
Kyber1024['eprimeprime'] = Kyber1024['s'] + u2
Kyber1024['n'] = 256 * 4
Kyber1024['n2'] = 256
Kyber1024['AES'] = 2**256
Kyber1024['name'] = 'Kyber1024'

# SABER
LightSaber = {}
LightSaber['thres'] = 2**13 / 2**2
LightSaber['s'] = Dist(build_centered_binomial_law(5))
LightSaber['e'] = Dist(build_mod_switching_error_law(2**13, 2**10))
LightSaber['sprime'] = LightSaber['s']
LightSaber['eprime'] = LightSaber['e']
LightSaber['eprimeprime'] = Dist(build_mod_switching_error_law(2**13, 2**3))
LightSaber['n'] = 256 * 2
LightSaber['n2'] = 256
LightSaber['AES'] = 2**128
LightSaber['name'] = 'LightSaber'

Saber = {}
Saber['thres'] = 2**13 / 2**2
Saber['s'] = Dist(build_centered_binomial_law(4))
Saber['e'] = Dist(build_mod_switching_error_law(2**13, 2**10))
Saber['sprime'] = Saber['s']
Saber['eprime'] = Saber['e']
Saber['eprimeprime'] = Dist(build_mod_switching_error_law(2**13, 2**4))
Saber['n'] = 256 * 3
Saber['n2'] = 256
Saber['AES'] = 2**192
Saber['name'] = 'Saber'

FireSaber = {}
FireSaber['thres'] = 2**13 / 2**2
FireSaber['s'] = Dist(build_centered_binomial_law(3))
FireSaber['e'] = Dist(build_mod_switching_error_law(2**13, 2**10))
FireSaber['sprime'] = FireSaber['s']
FireSaber['eprime'] = FireSaber['e']
FireSaber['eprimeprime'] = Dist(build_mod_switching_error_law(2**13, 2**6))
FireSaber['n'] = 256 * 4
FireSaber['n2'] = 256
FireSaber['AES'] = 2**256
FireSaber['name'] = 'FireSaber'

# SABER adaptations
LightSaberTplus1 = {}
LightSaberTplus1['thres'] = 2**13 / 2**2
LightSaberTplus1['s'] = Dist(build_centered_binomial_law(5))
LightSaberTplus1['e'] = Dist(build_mod_switching_error_law(2**13, 2**10))
LightSaberTplus1['sprime'] = LightSaberTplus1['s']
LightSaberTplus1['eprime'] = LightSaberTplus1['e']
LightSaberTplus1['eprimeprime'] = Dist(build_mod_switching_error_law(2**13, 2**4))
LightSaberTplus1['n'] = 256 * 2
LightSaberTplus1['n2'] = 256
LightSaberTplus1['name'] = 'LightSaberT+1'

SaberTplus1 = {}
SaberTplus1['thres'] = 2**13 / 2**2
SaberTplus1['s'] = Dist(build_centered_binomial_law(4))
SaberTplus1['e'] = Dist(build_mod_switching_error_law(2**13, 2**10))
SaberTplus1['sprime'] = SaberTplus1['s']
SaberTplus1['eprime'] = SaberTplus1['e']
SaberTplus1['eprimeprime'] = Dist(build_mod_switching_error_law(2**13, 2**5))
SaberTplus1['n'] = 256 * 3
SaberTplus1['n2'] = 256
SaberTplus1['AES'] = 2**192
SaberTplus1['name'] = 'SaberT+1'

SaberTplus2 = {}
SaberTplus2['thres'] = 2**13 / 2**2
SaberTplus2['s'] = Dist(build_centered_binomial_law(4))
SaberTplus2['e'] = Dist(build_mod_switching_error_law(2**13, 2**10))
SaberTplus2['sprime'] = SaberTplus2['s']
SaberTplus2['eprime'] = SaberTplus2['e']
SaberTplus2['eprimeprime'] = Dist(build_mod_switching_error_law(2**13, 2**6))
SaberTplus2['n'] = 256 * 3
SaberTplus2['n2'] = 256
SaberTplus2['AES'] = 2**192
SaberTplus2['name'] = 'SaberT+2'

FireSaberTplus1 = {}
FireSaberTplus1['thres'] = 2**13 / 2**2
FireSaberTplus1['s'] = Dist(build_centered_binomial_law(3))
FireSaberTplus1['e'] = Dist(build_mod_switching_error_law(2**13, 2**10))
FireSaberTplus1['sprime'] = FireSaberTplus1['s']
FireSaberTplus1['eprime'] = FireSaberTplus1['e']
FireSaberTplus1['eprimeprime'] = Dist(build_mod_switching_error_law(2**13, 2**7))
FireSaberTplus1['n'] = 256 * 4
FireSaberTplus1['n2'] = 256
FireSaberTplus1['name'] = 'FireSaberT+1'

FireSaberTplus2 = {}
FireSaberTplus2['thres'] = 2**13 / 2**2
FireSaberTplus2['s'] = Dist(build_centered_binomial_law(3))
FireSaberTplus2['e'] = Dist(build_mod_switching_error_law(2**13, 2**10))
FireSaberTplus2['sprime'] = FireSaberTplus2['s']
FireSaberTplus2['eprime'] = FireSaberTplus2['e']
FireSaberTplus2['eprimeprime'] = Dist(build_mod_switching_error_law(2**13, 2**8))
FireSaberTplus2['n'] = 256 * 4
FireSaberTplus2['n2'] = 256
FireSaberTplus2['name'] = 'FireSaberT+2'

FireSaberTplus3 = {}
FireSaberTplus3['thres'] = 2**13 / 2**2
FireSaberTplus3['s'] = Dist(build_centered_binomial_law(3))
FireSaberTplus3['e'] = Dist(build_mod_switching_error_law(2**13, 2**10))
FireSaberTplus3['sprime'] = FireSaberTplus3['s']
FireSaberTplus3['eprime'] = FireSaberTplus3['e']
FireSaberTplus3['eprimeprime'] = Dist(build_mod_switching_error_law(2**13, 2**9))
FireSaberTplus3['n'] = 256 * 4
FireSaberTplus3['n2'] = 256
FireSaberTplus3['name'] = 'FireSaberT+3'


uLightSaber = {}
uLightSaber['thres'] = 2**12 / 2**2
uLightSaber['s'] = Dist({1: 0.25, 0: 0.25, -1: 0.25, -2: 0.25})
uLightSaber['e'] = Dist(build_mod_switching_error_law(2**12, 2**10))
uLightSaber['sprime'] = uLightSaber['s']
uLightSaber['eprime'] = uLightSaber['e']
uLightSaber['eprimeprime'] = Dist(build_mod_switching_error_law(2**12, 2**3))
uLightSaber['n'] = 256 * 2
uLightSaber['n2'] = 256
uLightSaber['AES'] = 2**128
uLightSaber['name'] = 'uLightSaber'

uSaber = {}
uSaber['thres'] = 2**12 / 2**2
uSaber['s'] = Dist({1: 0.25, 0: 0.25, -1: 0.25, -2: 0.25})
uSaber['e'] = Dist(build_mod_switching_error_law(2**12, 2**10))
uSaber['sprime'] = uSaber['s']
uSaber['eprime'] = uSaber['e']
uSaber['eprimeprime'] = Dist(build_mod_switching_error_law(2**12, 2**4))
uSaber['n'] = 256 * 3
uSaber['n2'] = 256
uSaber['AES'] = 2**192
uSaber['name'] = 'uSaber'

uFireSaber = {}
uFireSaber['thres'] = 2**12 / 2**2
uFireSaber['s'] = Dist({1: 0.25, 0: 0.25, -1: 0.25, -2: 0.25})
uFireSaber['e'] = Dist(build_mod_switching_error_law(2**12, 2**10))
uFireSaber['sprime'] = uFireSaber['s']
uFireSaber['eprime'] = uFireSaber['e']
uFireSaber['eprimeprime'] = Dist(build_mod_switching_error_law(2**12, 2**6))
uFireSaber['n'] = 256 * 4
uFireSaber['n2'] = 256
uFireSaber['AES'] = 2**256
uFireSaber['name'] = 'uFireSaber'



from math import exp
sigma = 724
f = lambda x: exp(-x**2/2./sigma**2)

dist_s = { sign * i : f(i) for i in range(0,20*sigma,sigma) for sign in [-1,1] } #stepsize to reduce distribution
dist_s = Dist(dist_s).normalize()
dist_s = dist_s * {1: 0.5, -1: 0.5}

ssntrupke = {}
ssntrupke['thres'] = (2**30 + 2**13 + 1) / 2**2
ssntrupke['s'] = dist_s
ssntrupke['e'] = dist_s
ssntrupke['sprime'] = dist_s
ssntrupke['eprime'] = dist_s
ssntrupke['eprimeprime'] = dist_s
ssntrupke['n'] = 1024
ssntrupke['n2'] = 256
ssntrupke['name'] = 'ssntrupke'