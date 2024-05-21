import binascii


from pywallet.ecdsa import _Gx, _Gy, _p, _r

# secp256k1
# pywallet openssl private key implementation


def i2d_ECPrivateKey(pkey, compressed=False):  # , crypted=True):
    part3 = "a081a53081a2020101302c06072a8648ce3d0101022100"  # for uncompressed keys
    if compressed:
        if True:  # not crypted:  ## Bitcoin accepts both part3's for crypted wallets...
            part3 = "a08185308182020101302c06072a8648ce3d0101022100"  # for compressed keys
        key = (
            "3081d30201010420"
            + "%064x" % pkey.secret
            + part3
            + "%064x" % _p
            + "3006040100040107042102"
            + "%064x" % _Gx
            + "022100"
            + "%064x" % _r
            + "020101a124032200"
        )
    else:
        key = (
            "308201130201010420"
            + "%064x" % pkey.secret
            + part3
            + "%064x" % _p
            + "3006040100040107044104"
            + "%064x" % _Gx
            + "%064x" % _Gy
            + "022100"
            + "%064x" % _r
            + "020101a144034200"
        )

    return binascii.unhexlify(key) + i2o_ECPublicKey(pkey, compressed)


def i2o_ECPublicKey(pkey, compressed=False):
    # public keys are 65 bytes int (520 bits)
    # 0x04 + 32-byte X-coordinate + 32-byte Y-coordinate
    # 0x00 = point at infinity, 0x02 and 0x03 = compressed, 0x04 = uncompressed
    # compressed keys: <sign> <x> where <sign> is 0x02 if y is even and 0x03 if y is odd
    if compressed:
        if pkey.pubkey.point.y() & 1:
            key = "03" + "%064x" % pkey.pubkey.point.x()
        else:
            key = "02" + "%064x" % pkey.pubkey.point.x()
    else:
        key = "04" + "%064x" % pkey.pubkey.point.x() + "%064x" % pkey.pubkey.point.y()

    return binascii.unhexlify(key)
