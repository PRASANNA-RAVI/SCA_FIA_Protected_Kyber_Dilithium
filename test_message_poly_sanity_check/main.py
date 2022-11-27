from NISTschemes import Kyber768, Kyber512, Kyber1024, Kyber512_r2
from dist import Dist
from proba_util import build_centered_binomial_law, build_mod_switching_error_law

# from math import round

# scheme parameters
L = 6
q = 3329
p = 2**10 
T = 2**4 

dist = (Kyber768['s'] * Kyber768['eprime'] + Kyber768['sprime'] * Kyber768['e'])**Kyber768['n'] + Kyber768['eprimeprime']
print('Variance Kyber768', dist.var(), dist.var()**0.5)
sigma = dist.var()**0.5
s = list(Kyber768['s'].keys())

dist = (Kyber512['s'] * Kyber512['eprime'] + Kyber512['sprime'] * Kyber512['e'])**Kyber512['n'] + Kyber512['eprimeprime']
print('Variance Kyber512', dist.var(), dist.var()**0.5)
sigma_512 = dist.var()**0.5
s_512 = list(Kyber512['s'].keys())

dist = (Kyber512_r2['s'] * Kyber512_r2['eprime'] + Kyber512_r2['sprime'] * Kyber512_r2['e'])**Kyber512_r2['n'] + Kyber512_r2['eprimeprime']
print('Variance Kyber512_r2', dist.var(), dist.var()**0.5)
sigma_512_r2 = dist.var()**0.5
s_512_r2 = list(Kyber512_r2['s'].keys())

dist = (Kyber1024['s'] * Kyber1024['eprime'] + Kyber1024['sprime'] * Kyber1024['e'])**Kyber1024['n'] + Kyber1024['eprimeprime']
print('Variance Kyber1024', dist.var(), dist.var()**0.5)
sigma_1024 = dist.var()**0.5
s_1024 = list(Kyber1024['s'].keys())

# # attack parameters
attacks = []

# # generic side-channel attacks on ...
attacks.append([round(211 * p/q), round(416 * T/q), 3329, 2**10, 2**4, sigma_512_r2, s_512_r2])
attacks.append([round(211 * p/q), round(2913 * T/q), 3329, 2**10, 2**4, sigma_512_r2, s_512_r2])
attacks.append([round(101 * p/q), round(832 * T/q), 3329, 2**10, 2**4, sigma_512_r2, s_512_r2])
attacks.append([round(101 * p/q), round(2497 * T/q), 3329, 2**10, 2**4, sigma_512_r2, s_512_r2])
attacks.append([round(416 * p/q), round(1248 * T/q), 3329, 2**10, 2**4, sigma_512_r2, s_512_r2])

# pushing the limits of 2022/931
for i in range(3,7):
    attacks.append([round(208 * p/q), round(208 * i * T/q), 3329, 2**10, 2**4, sigma, s])

for i in range(2,8):
    attacks.append([round(208 * p/q), round(208 * i * T/q), 3329, 2**10, 2**4, sigma_512, s_512])

for i in range(3,7):
    attacks.append([round(208 * 2**11/q), round(208 * i * 2**5/q), 3329, 2**11, 2**5, sigma, s])

# On Exploiting Message Leakag ... 2020/1559
attacks.append([round(211 * p/q), round(416 * T/q), 3329, 2**10, 2**4, sigma, s])
attacks.append([round(627 * p/q), round(1248 * T/q), 3329, 2**10, 2**4, sigma, s])
attacks.append([round(1252 * p/q), 0, 3329, 2**10, 2**4, sigma, s])

# # Magnifying Side-Channel Leakage ... 2022/912
# attacks.append([round(200 * p/q), round(416 * T/q), 3329, 2**10, 2**4, sigma, s])
# attacks.append([round(400 * p/q), round(416 * T/q), 3329, 2**10, 2**4, sigma, s])
# attacks.append([round(600 * p/q), round(416 * T/q), 3329, 2**10, 2**4, sigma, s])
# attacks.append([round(200 * p/q), round(416 * T/q), 3329, 2**10, 2**4, sigma, s])
# attacks.append([round(627 * p/q), round(416 * T/q), 3329, 2**10, 2**4, sigma, s])
# attacks.append([round(1252 * p/q), round(416 * T/q), 3329, 2**10, 2**4, sigma, s])


# test attacks
def test_attack(attack, s, q, p, T, L, sigma):
    du, dv, q, p, T, sigma, s = attack
    s = list(s)

    attackpossible = 1
    for si in s:
        mpoly = round(dv * q / T) - round(du * q / p) * si
        mpoly = mpoly % q

        print(mpoly, ((mpoly + q/4) % q) < q/2  )

        if (mpoly > L*sigma) and (mpoly < (q/2 - L*sigma)):
            attackpossible = 0
        if (mpoly > q/2 + L*sigma) and (mpoly < (q - L*sigma)):
            attackpossible = 0
    return attackpossible


working = 0
for attack in attacks:
    print('=========')
    working += test_attack(attack, s, q, p, T, L, sigma)
print(f"number of working equations: {working}")