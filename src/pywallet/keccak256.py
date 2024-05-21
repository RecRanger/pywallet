import binascii
from copy import deepcopy
from functools import reduce
from math import log
from operator import xor

from pywallet.conversions import ordsix, chrsix, str_to_bytes


RoundConstants = [
    1,
    32898,
    0x800000000000808A,
    0x8000000080008000,
    32907,
    2147483649,
    0x8000000080008081,
    0x8000000000008009,
    138,
    136,
    2147516425,
    2147483658,
    2147516555,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    32778,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    2147483649,
    0x8000000080008008,
]
RotationConstants = [
    [0, 1, 62, 28, 27],
    [36, 44, 6, 55, 20],
    [3, 10, 43, 25, 39],
    [41, 45, 15, 21, 8],
    [18, 2, 61, 56, 14],
]
Masks = [(1 << i) - 1 for i in range(65)]


def bits2bytes(x):
    return (int(x) + 7) // 8


def rol(value, left, bits):
    top = value >> bits - left
    bot = (value & Masks[bits - left]) << left
    return bot | top


def ror(value, right, bits):
    top = value >> right
    bot = (value & Masks[right]) << bits - right
    return bot | top


def multirate_padding(used_bytes, align_bytes):
    padlen = align_bytes - used_bytes
    if padlen == 0:
        padlen = align_bytes
    if padlen == 1:
        return [129]
    else:
        return [1] + [0] * (padlen - 2) + [128]


def keccak_f(state: "KeccakState"):
    def round(A, RC):
        W, H = state.W, state.H
        rangeW, rangeH = state.rangeW, state.rangeH
        lanew = state.lanew
        zero = state.zero
        C = [reduce(xor, A[x]) for x in rangeW]
        D = [0] * W
        for x in rangeW:
            D[x] = C[(x - 1) % W] ^ rol(C[(x + 1) % W], 1, lanew)
            for y in rangeH:
                A[x][y] ^= D[x]
        B = zero()
        for x in rangeW:
            for y in rangeH:
                B[y % W][(2 * x + 3 * y) % H] = rol(A[x][y], RotationConstants[y][x], lanew)
        for x in rangeW:
            for y in rangeH:
                A[x][y] = B[x][y] ^ ~B[(x + 1) % W][y] & B[(x + 2) % W][y]
        A[0][0] ^= RC

    l = int(log(state.lanew, 2))
    nr = 12 + 2 * l
    for ir in range(nr):
        round(state.s, RoundConstants[ir])


class KeccakState:
    W = 5
    H = 5
    rangeW = range(W)
    rangeH = range(H)

    @staticmethod
    def zero():
        return [[0] * KeccakState.W for x in KeccakState.rangeH]

    @classmethod
    def format(cls, st):
        rows = []

        def fmt(x):
            return "%016x" % x

        for y in cls.rangeH:
            row = []
            for x in cls.rangeW:
                row.append(fmt(st[x][y]))
            rows.append(" ".join(row))
        return "\n".join(rows)

    @staticmethod
    def lane2bytes(s, w):
        o = []
        for b in range(0, w, 8):
            o.append(s >> b & 255)
        return o

    @staticmethod
    def bytes2lane(bb):
        r = 0
        for b in reversed(bb):
            r = r << 8 | b
        return r

    @staticmethod
    def bytes2str(bb):
        return str_to_bytes("").join(map(chrsix, bb))

    @staticmethod
    def str2bytes(ss):
        return map(ordsix, ss)

    def __init__(self, bitrate, b):
        self.bitrate = bitrate
        self.b = b
        assert self.bitrate % 8 == 0
        self.bitrate_bytes = bits2bytes(self.bitrate)
        assert self.b % 25 == 0
        self.lanew = self.b // 25
        self.s = KeccakState.zero()

    def __str__(self):
        return KeccakState.format(self.s)

    def absorb(self, bb):
        assert len(bb) == self.bitrate_bytes
        bb += [0] * bits2bytes(self.b - self.bitrate)
        i = 0
        for y in self.rangeH:
            for x in self.rangeW:
                self.s[x][y] ^= KeccakState.bytes2lane(bb[i : i + 8])
                i += 8

    def squeeze(self):
        return self.get_bytes()[: self.bitrate_bytes]

    def get_bytes(self):
        out = [0] * bits2bytes(self.b)
        i = 0
        for y in self.rangeH:
            for x in self.rangeW:
                v = KeccakState.lane2bytes(self.s[x][y], self.lanew)
                out[i : i + 8] = v
                i += 8
        return out

    def set_bytes(self, bb):
        i = 0
        for y in self.rangeH:
            for x in self.rangeW:
                self.s[x][y] = KeccakState.bytes2lane(bb[i : i + 8])
                i += 8


class KeccakSponge:
    def __init__(self, bitrate, width, padfn, permfn):
        self.state = KeccakState(bitrate, width)
        self.padfn = padfn
        self.permfn = permfn
        self.buffer = []

    def copy(self):
        return deepcopy(self)

    def absorb_block(self, bb):
        assert len(bb) == self.state.bitrate_bytes
        self.state.absorb(bb)
        self.permfn(self.state)

    def absorb(self, s):
        self.buffer += KeccakState.str2bytes(s)
        while len(self.buffer) >= self.state.bitrate_bytes:
            self.absorb_block(self.buffer[: self.state.bitrate_bytes])
            self.buffer = self.buffer[self.state.bitrate_bytes :]

    def absorb_final(self):
        padded = self.buffer + self.padfn(len(self.buffer), self.state.bitrate_bytes)
        self.absorb_block(padded)
        self.buffer = []

    def squeeze_once(self):
        rc = self.state.squeeze()
        self.permfn(self.state)
        return rc

    def squeeze(self, l):
        Z = self.squeeze_once()
        while len(Z) < l:
            Z += self.squeeze_once()
        return Z[:l]


class KeccakHash:
    def __init__(self, bitrate_bits, capacity_bits, output_bits):
        assert bitrate_bits + capacity_bits in (25, 50, 100, 200, 400, 800, 1600)
        self.sponge = KeccakSponge(
            bitrate_bits, bitrate_bits + capacity_bits, multirate_padding, keccak_f
        )
        assert output_bits % 8 == 0
        self.digest_size = bits2bytes(output_bits)
        self.block_size = bits2bytes(bitrate_bits)

    def __repr__(self):
        inf = (
            self.sponge.state.bitrate,
            self.sponge.state.b - self.sponge.state.bitrate,
            self.digest_size * 8,
        )
        return "<KeccakHash with r=%d, c=%d, image=%d>" % inf

    def copy(self):
        return deepcopy(self)

    def update(self, s):
        self.sponge.absorb(s)

    def digest(self):
        finalised = self.sponge.copy()
        finalised.absorb_final()
        digest = finalised.squeeze(self.digest_size)
        return KeccakState.bytes2str(digest)

    def hexdigest(self):
        return binascii.hexlify(self.digest())

    @staticmethod
    def preset(bitrate_bits, capacity_bits, output_bits):
        def create(initial_input=None):
            h = KeccakHash(bitrate_bits, capacity_bits, output_bits)
            if not (initial_input is None):
                h.update(initial_input)
            return h

        return create


Keccak256 = KeccakHash.preset(1088, 512, 256)

########################
