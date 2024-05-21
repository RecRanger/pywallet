import binascii
import base64

from pywallet.conversions import chrsix, ordsix, DecodeBase58Check, EncodeBase58Check
from pywallet.ecdsa import EC_KEY, i2d_ECPrivateKey, i2o_ECPublicKey
from pywallet.networks import DEFAULT_NETWORK
import hashlib


# bitcointools hashes and base58 implementation


__b58chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def Hash(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def EncodeBase58Check(secret, __b58chars=__b58chars):
    hash = Hash(secret)
    return b58encode(secret + hash[0:4], __b58chars)


def DecodeBase58Check(sec, __b58chars=__b58chars):
    vchRet = b58decode(sec, None, __b58chars)
    secret = vchRet[0:-4]
    csum = vchRet[-4:]
    hash = Hash(secret)
    cs32 = hash[0:4]
    if cs32 != csum:
        return None
    else:
        return secret


def hash_160(public_key):
    md = hashlib.new("ripemd160")
    md.update(hashlib.sha256(public_key).digest())
    return md.digest()


def public_key_to_bc_address(public_key, v=None, network=DEFAULT_NETWORK):
    if v == None:
        v = network.p2pkh_prefix
    h160 = hash_160(public_key)
    return hash_160_to_bc_address(h160, v)


def hash_160_to_bc_address(h160, v=None, network=DEFAULT_NETWORK):
    if v == None:
        v = network.p2pkh_prefix
    vh160 = chrsix(v) + h160
    h = Hash(vh160)
    addr = vh160 + h[0:4]
    return b58encode(addr)


def bc_address_to_hash_160(addr):
    bytes = b58decode(addr, 25)
    return bytes[1:21]


def b58encode(v, __b58chars=__b58chars):
    """encode v, which is a string of bytes, to base58."""
    __b58base = len(__b58chars)

    int_value = 0
    for i, c in enumerate(v[::-1]):
        int_value += (256**i) * ordsix(c)

    result = ""
    while int_value >= __b58base:
        div, mod = divmod(int_value, __b58base)
        result = __b58chars[mod] + result
        int_value = div
    result = __b58chars[int_value] + result

    # Bitcoin does a little leading-zero-compression:
    # leading 0-bytes in the input become leading-1s
    nPad = 0
    for c in v:
        if chrsix(c) == b"\0":
            nPad += 1
        else:
            break

    return (__b58chars[0] * nPad) + result


def b58decode(v, length, __b58chars=__b58chars):
    """decode v into a string of len bytes"""
    __b58base = len(__b58chars)
    int_value = 0
    for i, c in enumerate(v[::-1]):
        int_value += __b58chars.find(c) * (__b58base**i)

    result = b""
    while int_value >= 256:
        div, mod = divmod(int_value, 256)
        result = chrsix(mod) + result
        int_value = div
    result = chrsix(int_value) + result

    nPad = 0
    for c in v:
        if c == __b58chars[0]:
            nPad += 1
        else:
            break

    result = chrsix(0) * nPad + result
    if not (length is None) and len(result) != length:
        return None

    return result


# end of bitcointools base58 implementation


# address-handling code


def PrivKeyToSecret(privkey):
    if len(privkey) == 279:
        return privkey[9 : 9 + 32]
    else:
        return privkey[8 : 8 + 32]


def SecretToASecret(secret, compressed=False, network=DEFAULT_NETWORK):
    prefix = chrsix(network.wif_prefix)
    vchIn = prefix + secret
    if compressed:
        vchIn += b"\01"
    return EncodeBase58Check(vchIn)


def ASecretToSecret(sec, network=DEFAULT_NETWORK):
    vch = DecodeBase58Check(sec)
    if not vch:
        return False
    if ordsix(vch[0]) != network.wif_prefix:
        print("Warning: adress prefix seems bad (%d vs %d)" % (ordsix(vch[0]), network.wif_prefix))
    return vch[1:]


def regenerate_key(sec):
    b = ASecretToSecret(sec)
    if not b:
        return False
    b = b[0:32]
    secret = int(b"0x" + binascii.hexlify(b), 16)
    return EC_KEY(secret)


def GetPubKey(pkey, compressed=False):
    return i2o_ECPublicKey(pkey, compressed)


def GetPrivKey(pkey, compressed=False):
    return i2d_ECPrivateKey(pkey, compressed)


def GetSecret(pkey):
    return binascii.unhexlify("%064x" % pkey.secret)


def is_compressed(sec):
    b = ASecretToSecret(sec)
    return len(b) == 33


BECH32_ALPH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BASE32_ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def bech32_polymod(values):
    GEN = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def bech32_hrp_expand(s):
    return [ordsix(x) >> 5 for x in s] + [0] + [ordsix(x) & 31 for x in s]


def bech32_verify_checksum(hrp, data):
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1


def bech32_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def witprog_to_bech32_addr(witprog, network, witv=0):
    x = base64.b32encode(witprog).decode()
    x = x.replace("=", "")
    data = [witv] + list(map(lambda y: BASE32_ALPH.index(y), x))
    combined = data + bech32_create_checksum(network.segwit_hrp, data)
    addr = network.segwit_hrp + "1" + "".join([BECH32_ALPH[d] for d in combined])
    return addr


def p2sh_script_to_addr(script):
    version = 5
    return hash_160_to_bc_address(hash_160(script), version)
