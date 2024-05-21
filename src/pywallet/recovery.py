import binascii
import json
import os
import sys
import time
import logging
import re
import urllib
import hashlib
from datetime import datetime

from pywallet.wallet_crypter import crypter
from pywallet.addresses import Hash
from pywallet.ecdsa import EC_KEY
from pywallet.addresses import GetPubKey
from pywallet.env_info import ts

ko = 1e3
kio = 1024
Mo = 1e6
Mio = 1024**2
Go = 1e9
Gio = 1024**3
To = 1e12
Tio = 1024**4

prekeys = [
    binascii.unhexlify("308201130201010420"),
    binascii.unhexlify("308201120201010420"),
]
postkeys = [binascii.unhexlify("a081a530"), binascii.unhexlify("81a530")]


def multiextract(s, ll):
    r = []
    cursor = 0
    for length in ll:
        r.append(s[cursor : cursor + length])
        cursor += length
    if s[cursor:] != b"":
        r.append(s[cursor:])
    return r


class RecovCkey(object):
    def __init__(self, epk, pk):
        self.encrypted_pk = epk
        self.public_key = pk
        self.mkey = None
        self.privkey = None


class RecovMkey(object):
    def __init__(self, ekey, salt, nditer, ndmethod, nid):
        self.encrypted_key = ekey
        self.salt = salt
        self.iterations = nditer
        self.method = ndmethod
        self.id = nid
        # print((ekey, salt, nditer, ndmethod, nid))


def readpartfile(fd, offset, length):  # make everything 512*n because of windows...
    rest = offset % 512
    new_offset = offset - rest
    big_length = 512 * (int((length + rest - 1) // 512) + 1)
    os.lseek(fd, new_offset, os.SEEK_SET)
    d = os.read(fd, big_length)
    return d[rest : rest + length]


def recov_ckey(fd, offset):
    d = readpartfile(fd, offset - 49, 122)
    me = multiextract(d, [1, 48, 4, 4, 1])

    checks = []
    checks.append([0, "30"])
    checks.append([3, "636b6579"])
    if sum(
        map(lambda x: int(me[x[0]] != binascii.unhexlify(x[1])), checks)
    ):  # number of false statements
        return None

    return me


def recov_mkey(fd, offset):
    d = readpartfile(fd, offset - 72, 84)
    me = multiextract(d, [4, 48, 1, 8, 4, 4, 1, 2, 8, 4])

    checks = []
    checks.append([0, "43000130"])
    checks.append([2, "08"])
    checks.append([6, "00"])
    checks.append([8, "090001046d6b6579"])
    if sum(
        map(lambda x: int(me[x[0]] != binascii.unhexlify(x[1])), checks)
    ):  # number of false statements
        return None

    return me


def drop_first(e):
    if hasattr(e, "next"):
        e.next()
    else:
        e = e[1:]
    for i in e:
        yield i


def recov_uckey(fd, offset):
    dd = readpartfile(fd, offset, 223)
    r = []
    for beg in map(binascii.unhexlify, ["3081d30201010420", "308201130201010420"]):
        for chunk in drop_first(dd.split(beg)):
            r.append(chunk[:32])
    return r and (None, None, None, None, r[0])


def recov_uckeyOLD(fd, offset):
    checks = []

    d = readpartfile(fd, offset - 217, 223)
    if d[-7] == "\x26":
        me = multiextract(d, [2, 1, 4, 1, 32, 141, 33, 2, 1, 6])

        checks.append([0, "3081"])
        checks.append([2, "02010104"])
    elif d[-7] == "\x46":
        d = readpartfile(fd, offset - 282, 286)

        me = multiextract(d, [2, 1, 4, 1, 32, 173, 65, 1, 2, 5])

        checks.append([0, "8201"])
        checks.append([2, "02010104"])
        checks.append([-1, "460001036b"])
    else:
        return None

    if sum(
        map(lambda x: int(me[x[0]] != binascii.unhexlify(x[1])), checks)
    ):  # number of false statements
        return None

    return me


def search_patterns_on_disk(device, size, inc, patternlist):  # inc must be higher than 1k
    try:
        otype = os.O_RDONLY | os.O_BINARY
    except:
        otype = os.O_RDONLY
    try:
        fd = os.open(device, otype)
    except Exception as e:
        print("Can't open %s, check the path or try as root" % device)
        print("  Error: " + str(e.args))
        exit(0)

    i = 0
    data = b""

    tzero = time.time()
    sizetokeep = 0
    BlocksToInspect = dict(map(lambda x: [x, []], patternlist))
    lendataloaded = None
    writeProgressEvery = 100 * Mo
    while i < int(size) and (lendataloaded != 0 or lendataloaded == None):
        if int(i // writeProgressEvery) != int((i + inc) // writeProgressEvery):
            print("%.2f Go read" % (i // 1e9))
        try:
            datakept = data[-sizetokeep:]
            data = datakept + os.read(fd, inc)
            lendataloaded = len(data) - len(datakept)  # should be inc
            for text in patternlist:
                if text in data:
                    BlocksToInspect[text].append([i - len(datakept), data, len(datakept)])
                    pass
            sizetokeep = 20  # 20 because all the patterns have a len<20. Could be higher.
            i += lendataloaded
        except Exception as exc:
            if lendataloaded % 512 > 0:
                raise Exception("SPOD error 1: %d, %d" % (lendataloaded, i - len(datakept)))
            os.lseek(fd, lendataloaded, os.SEEK_CUR)
            print(str(exc))
            i += lendataloaded
            continue
    os.close(fd)

    AllOffsets = dict(map(lambda x: [repr(x), []], patternlist))
    for text, blocks in BlocksToInspect.items():
        for offset, data, ldk in blocks:  # ldk = len(datakept)
            offsetslist = [offset + m.start() for m in re.finditer(text, data)]
            AllOffsets[repr(text)].extend(offsetslist)

    AllOffsets["PRFdevice"] = device
    AllOffsets["PRFdt"] = time.time() - tzero
    AllOffsets["PRFsize"] = i
    return AllOffsets


def check_postkeys(key, postkeys):
    for i in postkeys:
        if key[: len(i)] == i:
            return True
    return False


def one_element_in(a, string):
    for i in a:
        if i in string:
            return True
    return False


def first_read(device, size, prekeys, inc=10000):
    t0 = ts() - 1
    try:
        fd = os.open(device, os.O_RDONLY)
    except:
        print("Can't open %s, check the path or try as root" % device)
        exit(0)
    prekey = prekeys[0]
    data = b""
    i = 0
    data = os.read(fd, i)
    before_contained_key = False
    contains_key = False
    ranges = []

    while i < int(size):
        if i % (10 * Mio) > 0 and i % (10 * Mio) <= inc:
            print("\n%.2f/%.2f Go" % (i // 1e9, size // 1e9))
            t = ts()
            speed = i // (t - t0)
            ETAts = size // speed + t0
            d = datetime.fromtimestamp(ETAts)
            print(d.strftime("   ETA: %H:%M:%S"))

        try:
            data = os.read(fd, inc)
        except Exception as exc:
            os.lseek(fd, inc, os.SEEK_CUR)
            print(str(exc))
            i += inc
            continue

        contains_key = one_element_in(prekeys, data)

        if not before_contained_key and contains_key:
            ranges.append(i)

        if before_contained_key and not contains_key:
            ranges.append(i)

        before_contained_key = contains_key

        i += inc

    os.close(fd)
    return ranges


def shrink_intervals(device, ranges, prekeys, inc=1000):
    prekey = prekeys[0]
    nranges = []
    fd = os.open(device, os.O_RDONLY)
    for j in range(len(ranges) // 2):
        before_contained_key = False
        contains_key = False
        bi = ranges[2 * j]
        bf = ranges[2 * j + 1]

        mini_blocks = []
        k = bi
        while k <= bf + len(prekey) + 1:
            mini_blocks.append(k)
            k += inc
            mini_blocks.append(k)

        for k in range(len(mini_blocks) // 2):
            mini_blocks[2 * k] -= len(prekey) + 1
            mini_blocks[2 * k + 1] += len(prekey) + 1

            bi = mini_blocks[2 * k]
            bf = mini_blocks[2 * k + 1]

            os.lseek(fd, bi, 0)

            data = os.read(fd, bf - bi + 1)
            contains_key = one_element_in(prekeys, data)

            if not before_contained_key and contains_key:
                nranges.append(bi)

            if before_contained_key and not contains_key:
                nranges.append(bi + len(prekey) + 1 + len(prekey) + 1)

            before_contained_key = contains_key

    os.close(fd)

    return nranges


def find_offsets(device, ranges, prekeys):
    prekey = prekeys[0]
    list_offsets = []
    to_read = 0
    fd = os.open(device, os.O_RDONLY)
    for i in range(len(ranges) // 2):
        bi = ranges[2 * i] - len(prekey) - 1
        os.lseek(fd, bi, 0)
        bf = ranges[2 * i + 1] + len(prekey) + 1
        to_read += bf - bi + 1
        buf = b""
        for j in range(len(prekey)):
            buf += b"\x00"
        curs = bi

        while curs <= bf:
            data = os.read(fd, 1)
            buf = buf[1:] + data
            if buf in prekeys:
                list_offsets.append(curs)
            curs += 1

    os.close(fd)

    return [to_read, list_offsets]


def read_keys(device, list_offsets):
    found_hexkeys = []
    fd = os.open(device, os.O_RDONLY)
    for offset in list_offsets:
        os.lseek(fd, offset + 1, 0)
        data = os.read(fd, 40)
        hexkey = binascii.hexlify(data[1:33])
        after_key = binascii.hexlify(data[33:39])
        if hexkey not in found_hexkeys and check_postkeys(binascii.unhexlify(after_key), postkeys):
            found_hexkeys.append(hexkey)

    os.close(fd)

    return found_hexkeys


def read_device_size(size):
    n, prefix, bi = re.match(r"(\d+)(|k|M|G|T|P)(i?)[oB]?$", size).groups()
    r = int(int(n) * pow(1000 + int(bool(bi)) * 24, "zkMGTP".index(prefix or "z")))
    return r


def md5_2(a):
    return hashlib.md5(a).digest()


def md5_file(nf):
    with open(nf, "rb") as f:
        return md5_2(f.read())


def md5_onlinefile(add):
    page = urllib.urlopen(add).read()
    return md5_2(page)


def recov(device, passes, size=102400, inc=10240, outputdir="."):
    if inc % 512 > 0:
        inc -= inc % 512  # inc must be 512*n on Windows... Don't ask me why...

    nameToDBName = {
        "mkey": b"\x09\x00\x01\x04mkey",
        "ckey": b"\x27\x00\x01\x04ckey",
        "key": b"\x00\x01\x03key",
    }

    if not device.startswith("PartialRecoveryFile:"):
        r = search_patterns_on_disk(device, size, inc, nameToDBName.values())
        f = open(outputdir + "/pywallet_partial_recovery_%d.json" % ts(), "w")
        f.write(json.dumps(r))
        f.close()
        print("\nRead %.1f Go in %.1f minutes\n" % (r["PRFsize"] // 1e9, r["PRFdt"] // 60.0))
    else:
        prf = device[20:]
        f = open(prf, "r")
        content = f.read()
        f.close()
        r = json.loads(content)
        device = r["PRFdevice"]
        print("\nLoaded %.1f Go from %s\n" % (r["PRFsize"] // 1e9, device))

    try:
        otype = os.O_RDONLY | os.O_BINARY
    except:
        otype = os.O_RDONLY
    fd = os.open(device, otype)

    mkeys = []
    crypters = []
    for offset in r[repr(nameToDBName["mkey"])]:
        s = recov_mkey(fd, offset)
        if s == None:
            continue
        if s[-1] == b"":
            s = s[:-1]
        newmkey = RecovMkey(
            s[1],
            s[3],
            int(binascii.hexlify(s[5][::-1]), 16),
            int(binascii.hexlify(s[4][::-1]), 16),
            int(binascii.hexlify(s[-1][::-1]), 16),
        )
        mkeys.append([offset, newmkey])

    print("Found %d possible wallets" % len(mkeys))

    ckeys = []
    for offset in r[repr(nameToDBName["ckey"])]:
        s = recov_ckey(fd, offset)
        if s == None:
            continue
        newckey = RecovCkey(s[1], s[5][: int(binascii.hexlify(s[4]), 16)])
        ckeys.append([offset, newckey])
    print("Found %d possible encrypted keys" % len(ckeys))

    uckeys = []
    for offset in r[repr(nameToDBName["key"])]:
        s = recov_uckey(fd, offset)
        if s:
            uckeys.append(s[4])
    uckeys = list(set(uckeys))
    print("Found %d possible unencrypted keys" % len(uckeys))

    os.close(fd)

    list_of_possible_keys_per_master_key = dict(map(lambda x: [x[1], []], mkeys))
    for cko, ck in ckeys:
        tl = map(lambda x: [abs(x[0] - cko)] + x, mkeys)
        tl = sorted(tl, key=lambda x: x[0])
        list_of_possible_keys_per_master_key[tl[0][2]].append(ck)

    cpt = 0
    mki = 1
    tzero = time.time()
    if len(passes) == 0:
        if len(ckeys) > 0:
            print("Can't decrypt them as you didn't provide any passphrase.")
    else:
        for mko, mk in mkeys:
            list_of_possible_keys = list_of_possible_keys_per_master_key[mk]
            sys.stdout.write("\nPossible wallet #" + str(mki))
            sys.stdout.flush()
            for ppi, pp in enumerate(passes):
                sys.stdout.write("\n    with passphrase #" + str(ppi + 1) + "  ")
                sys.stdout.flush()
                failures_in_a_row = 0
                # 				print("SKFP params:", pp, mk.salt, mk.iterations, mk.method)
                res = crypter.SetKeyFromPassphrase(pp, mk.salt, mk.iterations, mk.method)
                if res == 0:
                    print("Unsupported derivation method")
                    sys.exit(1)
                masterkey = crypter.Decrypt(mk.encrypted_key)
                crypter.SetKey(masterkey)
                for ck in list_of_possible_keys:
                    if cpt % 10 == 9 and failures_in_a_row == 0:
                        sys.stdout.write(".")
                        sys.stdout.flush()
                    if failures_in_a_row > 5:
                        break
                    crypter.SetIV(Hash(ck.public_key))
                    secret = crypter.Decrypt(ck.encrypted_pk)
                    compressed = ck.public_key[0] != "\04"

                    pkey = EC_KEY(int(b"0x" + binascii.hexlify(secret), 16))
                    if ck.public_key != GetPubKey(pkey, compressed):
                        failures_in_a_row += 1
                    else:
                        failures_in_a_row = 0
                        ck.mkey = mk
                        ck.privkey = secret
                    cpt += 1
            mki += 1
        print("\n")
        tone = time.time()
        try:
            calcspeed = 1.0 * cpt // (tone - tzero) * 60  # calc/min
        except:
            calcspeed = 1.0
        if calcspeed == 0:
            calcspeed = 1.0

        ckeys_not_decrypted = list(filter(lambda x: x[1].privkey == None, ckeys))
        refused_to_test_all_pps = True
        if len(ckeys_not_decrypted) == 0:
            print("All the found encrypted private keys have been decrypted.")
            return map(lambda x: x[1].privkey, ckeys)
        else:
            print("Private keys not decrypted: %d" % len(ckeys_not_decrypted))
            print(
                "Trying all the remaining possibilities (%d) might take up to %d minutes."
                % (
                    len(ckeys_not_decrypted) * len(passes) * len(mkeys),
                    int(len(ckeys_not_decrypted) * len(passes) * len(mkeys) // calcspeed),
                )
            )
            cont = input("Do you want to test them? (y/n): ")
            while len(cont) == 0:
                cont = input("Do you want to test them? (y/n): ")
                if cont[0] == "y":
                    refused_to_test_all_pps = False
                    cpt = 0
                    for dist, mko, mk in tl:
                        for ppi, pp in enumerate(passes):
                            res = crypter.SetKeyFromPassphrase(
                                pp, mk.salt, mk.iterations, mk.method
                            )
                            if res == 0:
                                logging.error("Unsupported derivation method")
                                sys.exit(1)
                            masterkey = crypter.Decrypt(mk.encrypted_key)
                            crypter.SetKey(masterkey)
                            for cko, ck in ckeys_not_decrypted:
                                tl = map(lambda x: [abs(x[0] - cko)] + x, mkeys)
                                tl = sorted(tl, key=lambda x: x[0])
                                if mk == tl[0][2]:
                                    continue  # because already tested
                                crypter.SetIV(Hash(ck.public_key))
                                secret = crypter.Decrypt(ck.encrypted_pk)
                                compressed = ck.public_key[0] != "\04"

                                pkey = EC_KEY(int(b"0x" + binascii.hexlify(secret), 16))
                                if ck.public_key == GetPubKey(pkey, compressed):
                                    ck.mkey = mk
                                    ck.privkey = secret
                                cpt += 1

        print("")
        ckeys_not_decrypted = filter(lambda x: x[1].privkey == None, ckeys)
        if len(ckeys_not_decrypted) == 0:
            print("All the found encrypted private keys have been finally decrypted.")
        elif not refused_to_test_all_pps:
            print("Private keys not decrypted: %d" % len(ckeys_not_decrypted))
            print("Try another password, check the size of your partition or seek help")

    uncrypted_ckeys = filter(lambda x: x != None, map(lambda x: x[1].privkey, ckeys))
    uckeys.extend(uncrypted_ckeys)

    return uckeys
