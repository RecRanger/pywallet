import random
import binascii

import ecdsa

from pywallet.conversions import (
    bytes_to_int,
    ordsix,
)
from pywallet.addresses import public_key_to_bc_address, ASecretToSecret
from pywallet.ecdsa_constants import _Gx, _Gy, _p, _a, _b, _r

curve_secp256k1 = ecdsa.ellipticcurve.CurveFp(_p, _a, _b)
generator_secp256k1 = g = ecdsa.ellipticcurve.Point(curve_secp256k1, _Gx, _Gy, _r)
randrange = random.SystemRandom().randrange  # FIXME: this might not be secure
secp256k1 = ecdsa.curves.Curve(
    "secp256k1", curve_secp256k1, generator_secp256k1, (1, 3, 132, 0, 10)
)
ecdsa.curves.curves.append(secp256k1)


# python-ecdsa code (EC_KEY implementation)


class CurveFp(object):
    def __init__(self, p, a, b):
        self.__p = p
        self.__a = a
        self.__b = b

    def p(self):
        return self.__p

    def a(self):
        return self.__a

    def b(self):
        return self.__b

    def contains_point(self, x, y):
        return (y * y - (x * x * x + self.__a * x + self.__b)) % self.__p == 0

    def sqrt_root(self, x):
        return pow(x, (self.__p + 1) // 4, self.__p)

    def y_from_x(self, x, y_odd):
        y = self.sqrt_root((x * x * x + self.__a * x + self.__b) % self.__p)
        if (y % 2 == 1) == y_odd:
            return y
        else:
            return self.__p - y


class Point(object):
    def __init__(self, curve, x, y=None, order=None, y_odd=None):
        self.__curve = curve
        self.__x = x
        if y != None or curve == None:
            self.__y = y
        else:
            self.__y = self.__curve.y_from_x(self.__x, y_odd)
        self.__order = order
        if self.__curve:
            assert self.__curve.contains_point(self.__x, self.__y)
        if order:
            assert self * order == INFINITY

    def __add__(self, other):
        if other == INFINITY:
            return self
        if self == INFINITY:
            return other
        assert self.__curve == other.__curve
        if self.__x == other.__x:
            if (self.__y + other.__y) % self.__curve.p() == 0:
                return INFINITY
            else:
                return self.double()

        p = self.__curve.p()
        l = ((other.__y - self.__y) * inverse_mod(other.__x - self.__x, p)) % p
        x3 = (l * l - self.__x - other.__x) % p
        y3 = (l * (self.__x - x3) - self.__y) % p
        return Point(self.__curve, x3, y3)

    def __mul__(self, other):
        def leftmost_bit(x):
            assert x > 0
            result = 1
            while result <= x:
                result = 2 * result
            return result // 2

        e = other
        if self.__order:
            e = e % self.__order
        if e == 0:
            return INFINITY
        if self == INFINITY:
            return INFINITY
        assert e > 0
        e3 = 3 * e
        negative_self = Point(self.__curve, self.__x, -self.__y, self.__order)
        i = leftmost_bit(e3) // 2
        result = self
        while i > 1:
            result = result.double()
            if (e3 & i) != 0 and (e & i) == 0:
                result = result + self
            if (e3 & i) == 0 and (e & i) != 0:
                result = result + negative_self
            i = i // 2
        return result

    def __rmul__(self, other):
        return self * other

    def __str__(self):
        if self == INFINITY:
            return "infinity"
        return "(%d,%d)" % (self.__x, self.__y)

    def double(self):
        if self == INFINITY:
            return INFINITY

        p = self.__curve.p()
        a = self.__curve.a()
        l = ((3 * self.__x * self.__x + a) * inverse_mod(2 * self.__y, p)) % p
        x3 = (l * l - 2 * self.__x) % p
        y3 = (l * (self.__x - x3) - self.__y) % p
        return Point(self.__curve, x3, y3)

    def x(self):
        return self.__x

    def y(self):
        return self.__y

    def curve(self):
        return self.__curve

    def order(self):
        return self.__order


INFINITY = Point(None, None, None)
secp256k1_curve = CurveFp(_p, _a, _b)
secp256k1_generator = Point(secp256k1_curve, _Gx, _Gy, _r)


def inverse_mod(a, m):
    if a < 0 or m <= a:
        a = a % m
    c, d = a, m
    uc, vc, ud, vd = 1, 0, 0, 1
    while c != 0:
        q, c, d = divmod(d, c) + (c,)
        uc, vc, ud, vd = ud - q * uc, vd - q * vc, uc, vc
    assert d == 1
    if ud > 0:
        return ud
    else:
        return ud + m


class Signature(object):
    def __init__(self, r, s):
        self.r = r
        self.s = s


class Public_key(object):
    def __init__(self, generator, point, c=None):
        self.curve = generator.curve()
        self.generator = generator
        self.point = point
        self.compressed = c
        n = generator.order()
        if not n:
            raise RuntimeError("Generator point must have order.")
        if not n * point == INFINITY:
            raise RuntimeError("Generator point order is bad.")
        if point.x() < 0 or n <= point.x() or point.y() < 0 or n <= point.y():
            raise RuntimeError("Generator point has x or y out of range.")

    def verifies(self, hash, signature):
        G = self.generator
        n = G.order()
        r = signature.r
        s = signature.s
        if r < 1 or r > n - 1:
            return False
        if s < 1 or s > n - 1:
            return False
        c = inverse_mod(s, n)
        u1 = (hash * c) % n
        u2 = (r * c) % n
        xy = u1 * G + u2 * self.point
        v = xy.x() % n
        return v == r

    def ser(self):
        if self.compressed:
            pk = ("%02x" % (2 + (self.point.y() & 1))) + "%064x" % self.point.x()
        else:
            pk = "04%064x%064x" % (self.point.x(), self.point.y())

        return binascii.unhexlify(pk)

    def get_addr(self, v=0):
        return public_key_to_bc_address(self.ser(), v)

    @classmethod
    def from_ser(cls, g, ser):
        if len(ser) == 33:
            return cls(
                g,
                Point(g.curve(), bytes_to_int(ser[1:]), y_odd=ordsix(ser[0]) == 3),
                ordsix(ser[0]) < 4,
            )
        elif len(ser) == 65:
            return cls(
                g,
                Point(g.curve(), bytes_to_int(ser[1:33]), bytes_to_int(ser[33:])),
                ordsix(ser[0]) < 4,
            )
        raise Exception("Bad public key format: %s" % repr(ser))


class Private_key(object):
    def __init__(self, public_key, secret_multiplier):
        self.public_key = public_key
        self.secret_multiplier = secret_multiplier

    def der(self):
        hex_der_key = (
            "06052b8104000a30740201010420"
            + "%064x" % self.secret_multiplier
            + "a00706052b8104000aa14403420004"
            + "%064x" % self.public_key.point.x()
            + "%064x" % self.public_key.point.y()
        )
        return binascii.unhexlify(hex_der_key)

    def sign(self, hash, random_k):
        G = self.public_key.generator
        n = G.order()
        k = random_k % n
        p1 = k * G
        r = p1.x()
        if r == 0:
            raise RuntimeError("amazingly unlucky random number r")
        s = (inverse_mod(k, n) * (hash + (self.secret_multiplier * r) % n)) % n
        if s == 0:
            raise RuntimeError("amazingly unlucky random number s")
        return Signature(r, s)


class EC_KEY(object):
    def __init__(self, secret):
        curve = CurveFp(_p, _a, _b)
        generator = Point(curve, _Gx, _Gy, _r)
        self.pubkey = Public_key(generator, generator * secret)
        self.privkey = Private_key(self.pubkey, secret)
        self.secret = secret


# end of python-ecdsa code


def regenerate_key(sec):
    b = ASecretToSecret(sec)
    if not b:
        return False
    b = b[0:32]
    secret = int(b"0x" + binascii.hexlify(b), 16)
    return EC_KEY(secret)
