import math


def ordsix(x):
    if x.__class__ == int:
        return x
    return ord(x)


def chrsix(x):
    if not (x.__class__ in [int, int]):
        return x
    return bytes([x])


def str_to_bytes(k):
    if k.__class__ == str and not hasattr(k, "decode"):
        return bytes(k, "ascii")
    return k


def bytes_to_str(k):
    if k.__class__ == bytes:
        return k.decode()
    if k.__class__ == str:
        return bytes_to_str(k.encode())
    return k


def bytes_to_int(bytes):
    result = 0
    for b in bytes:
        result = result * 256 + ordsix(b)
    return result


def int_to_bytes(value, length=None):
    if not length and value == 0:
        result = [0]
    else:
        result = []
        for i in range(0, length or 1 + int(math.log(value, 2**8))):
            result.append(value >> (i * 8) & 0xFF)
        result.reverse()
    return str(bytearray(result))


def str_to_int(b):
    res = 0
    pos = 1
    for a in reversed(b):
        res += ordsix(a) * pos
        pos *= 256
    return res
