from collections.abc import MutableMapping
import copy
import numpy as np

class Dist(MutableMapping):
    # Implement all the dict functionality
    def __init__(self, D, simplify_level=2**300):
        self.D = copy.deepcopy(D)
        self.simplify_level = simplify_level
        self.clean_dist()

    def __getitem__(self, key):
        return self.D[self._keytransform(key)]

    def __setitem__(self, key, value):
        self.D[self._keytransform(key)] = value

    def __delitem__(self, key):
        del self.D[self._keytransform(key)]

    def __iter__(self):
        return iter(self.D)

    def __len__(self):
        return len(self.D)

    def _keytransform(self, key):
        return key

    def __str__(self):
        return str(self.D)

    def set_simplify_level(self, simplify_level):
        self.simplify_level = simplify_level
        return self

    # cleanup functions
    def clean_dist(self):
        """ remove all items with probability below 2**-300 """
        A = self.D
        self.D = {}
        for (x, y) in A.items():
            if y > 2**(-300):
                self.D[x] = y

    def normalize(self):
        """ renormalize """
        res = self.D
        normalizer = sum(res.values())
        for i in res.keys():
            res[i] = res[i] / normalizer
        return Dist(res)

    def simplify(self, amount):
        """ approximate distribution dist with amount entries in the dictionary
        :param amount: number of entries(integer)
        """
        self.clean_dist()
        if amount >= len(self):
            return self

        res = {}
        A = self.D
        step = len(A) / amount
        x = sorted(A.keys())
        for j in range(0, amount):
            tmp = x[int(round(j * step)): int(round((j + 1) * step))]
            prob = sum([A[i] for i in tmp])
            mean = sum([A[i] * float(i) for i in tmp]) / prob
            res[mean] = res.get(mean, 0) + prob

        return Dist(res)

    def simplify_int(self):
        """ approximate distribution dist by rounding to integer values"""
        res = {}
        for i in self.keys():
            res[round(i)] = res.get(round(i), 0) + self[i]
        return Dist(res)

    # math functions
    @staticmethod
    def cast(other):
        """ internal function to homogenize inputs """
        if isinstance(other, (float, int)):
            B = {other: 1.}
        elif isinstance(other, (dict)):
            B = other
        elif isinstance(other, (Dist)):
            B = other.D
        else:
            raise Exception('wrong type')
        return B

    def __add__(self, other):
        """ add two random variables """
        C = {}
        A = self.D
        B = self.cast(other)
        for a in A:
            for b in B:
                c = a + b
                C[c] = C.get(c, 0) + A[a] * B[b]
        return Dist(C)

    def __sub__(self, other):
        """ subtract two random variables """
        C = {}
        A = self.D
        B = self.cast(other)
        for a in A:
            for b in B:
                c = a - b
                C[c] = C.get(c, 0) + A[a] * B[b]
        return Dist(C)

    def __mul__(self, other):
        """ multiply two random variables """
        C = {}
        A = self.D
        B = self.cast(other)
        for a in A:
            for b in B:
                c = a * b
                C[c] = C.get(c, 0) + A[a] * B[b]
        return Dist(C)

    def __pow__(self, i):
        """ returns distribution of n-time addition of random variables from input """
        simplify_level = self.simplify_level
        res = Dist({0: 1.0})
        i_bin = bin(i)[2:]  # binary representation of n
        for ch in i_bin:
            res = res + res
            res = res.simplify(simplify_level)
            if ch == '1':
                res = res + self
                res.simplify(simplify_level)
        return res

    def __gt__(self, thres):
        """ returns probability that random variabel exceeds thres """
        f = self.sf()

        return f(thres)

    def sf(self):
        """ compute survival function """
        A = self.D
        x = np.array(sorted(A.keys()))
        y = []
        # Summing in reverse for better numerical precision (assuming tails are decreasing)
        prev = 0.
        for j in reversed(x):
            y.append(prev)
            prev += A[j]

        y.reverse()

        return lambda inp: float(np.interp(inp, x, y, left = 0, right=1.))

    def __lt__(self, thres):
        """ returns probability that random variabel is lower than thres """
        f = self.cf()

        return f(thres)
    
    def cf(self):
        """ compute cumulative probability function """
        A = self.D
        x = np.array(sorted(A.keys()))
        y = []
        # Summing in reverse for better numerical precision (assuming tails are decreasing)
        prev = 0.
        for j in x:
            y.append(prev)
            prev += A[j]

        return lambda inp: float(np.interp(inp, x, y, left = 0, right=1.))

    def abs(self):
        """ absolute value of keys """
        A = self.D
        res = {}
        for i in A.keys():
            res[abs(i)] = res.get(abs(i), 0) + A[i]
        return res

    def norm(self, n, other = {0 : 1.}):
        """ compute approximate norm distribution, set simplify_level to determine speed / accuracy tradeoff """
        A = self.D
        B = self.cast(other)
        simplify_level = self.simplify_level

        squaredDist1 = Dist({})
        for i in A.keys():
            squaredDist1[i**2] = squaredDist1.get(i**2, 0) + A[i]

        squaredDist2 = Dist({})
        for i in B.keys():
            squaredDist2[i**2] = squaredDist2.get(i**2, 0) + B[i]
        
        squaredDist = squaredDist1 + squaredDist2
        squaredDist.set_simplify_level(simplify_level)
        squaredDist = squaredDist**n

        norm = {}
        for i in squaredDist.keys():
            norm[i**0.5] = norm.get(i**0.5, 0) + squaredDist[i]
        
        return Dist(norm)

    def max(self, accuracy = 2**-300):
        """ maximum value in distribution """
        A = self.D
        maxvalue = - 2**300
        for value, prob in A.items():
            if prob < 2**-300:
                continue
            if value > maxvalue:
                maxvalue = value 
        return maxvalue

    def min(self, accuracy = 2**-300):
        """ minimum value in distribution """
        A = self.D
        minvalue = 2**300
        for value, prob in A.items():
            if prob < 2**-300:
                continue
            if value < minvalue:
                minvalue = value 
        return minvalue
        
    def MaxOrderStatistic(self, n):
        """ return distribution of max of n samples """
        if n == 1:
            return Dist(self.D)

        A = self.D

        f = []
        F = []

        yrange = sorted(A.keys(), reverse=True)

        # generate f (probability function)
        # generate F (1 - cumulative function)
        sum = 0
        for x in yrange:
            prob = A[x]
            f.append(prob)
            F.append(sum)
            sum += prob

        f = [i / sum for i in f]
        F = [i / sum for i in F]

        fmax = {}
        for i, x in enumerate(yrange):
            fmax[x] = n * f[i] * abs(F[i] - 1)**(n - 1)

        return Dist(fmax)

    def interpolator(self):
        """ make distribution continuous by interpolation, returns function """
        xrange = sorted(list(self.keys()))
        yrange = [ self[i] for i in xrange ] 
        return lambda angle: np.interp(float(angle), xrange, yrange)


    # statistics
    def mean(self):
        A = self.D
        res = 0.
        for i in A.keys():
            res += A[i] * i
        return res

    def var(self):
        mean = self.mean()
        A = self.D
        res = 0.
        for i in A.keys():
            res += A[i] * (i - mean)**2
        return res

    def symmetry_split(self):
        """ make distribution symmetric by subtracting mean """
        mean = self.mean()
        res = self - mean
        return res, Dist({mean: 1.})
