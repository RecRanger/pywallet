import traceback
import socket
import _thread as thread
import os
import mmap
import random
import struct
import logging
import sys
import binascii

import binascii
import json
import sys
import time
import warnings
import logging
import collections
import random
import os


import ecdsa
from ecdsa import der
from bsddb3.db import (
    DBEnv,
    DB,
    DB_CREATE,
    DB_INIT_LOCK,
    DB_INIT_LOG,
    DB_INIT_MPOOL,
    DB_INIT_TXN,
    DB_THREAD,
    DB_RECOVER,
    DB_RDONLY,
    DB_BTREE,
    DBError,
)


from pywallet.addresses import (
    public_key_to_bc_address,
    Hash,
    p2sh_script_to_addr,
    witprog_to_bech32_addr,
    bc_address_to_hash_160,
    hash_160,
    ASecretToSecret,
    SecretToASecret,
    PrivKeyToSecret,
    GetPrivKey,
    GetPubKey,
    GetSecret,
    is_compressed,
)
from pywallet.conversions import (
    str_to_int,
    bytes_to_str,
    ordsix,
    str_to_bytes,
    chrsix,
)
from pywallet.ecdsa_constants import _r
from pywallet.ecdsa import EC_KEY, regenerate_key, secp256k1
from pywallet.types import Bdict
from pywallet.networks import find_network, network_bitcoin, DEFAULT_NETWORK, Network
from pywallet.web_api import balance, balance_site
from pywallet.env_info import ts
from pywallet.bip39 import Xpriv
from pywallet.wallet_crypter import crypter

# bitcointools wallet.dat handling code


def create_env(db_dir):
    db_env = DBEnv(0)
    r = db_env.open(
        db_dir,
        (
            DB_CREATE
            | DB_INIT_LOCK
            | DB_INIT_LOG
            | DB_INIT_MPOOL
            | DB_INIT_TXN
            | DB_THREAD
            | DB_RECOVER
        ),
    )
    return db_env


def parse_CAddress(vds):
    d = Bdict({"ip": "0.0.0.0", "port": 0, "nTime": 0})
    try:
        d["nVersion"] = vds.read_int32()
        d["nTime"] = vds.read_uint32()
        d["nServices"] = vds.read_uint64()
        d["pchReserved"] = vds.read_bytes(12)
        d["ip"] = socket.inet_ntoa(vds.read_bytes(4))
        d["port"] = vds.read_uint16()
    except:
        pass
    return d


def deserialize_CAddress(d):
    return d["ip"] + ":" + str(d["port"])


def parse_BlockLocator(vds):
    d = Bdict({"hashes": []})
    nHashes = vds.read_compact_size()
    for i in range(nHashes):
        d["hashes"].append(vds.read_bytes(32))
        return d


def deserialize_BlockLocator(d):
    result = "Block Locator top: " + binascii.hexlify(d["hashes"][0][::-1])
    return result


def parse_setting(setting, vds):
    if setting[0] == "f":  # flag (boolean) settings
        return str(vds.read_boolean())
    elif setting[0:4] == "addr":  # CAddress
        d = parse_CAddress(vds)
        return deserialize_CAddress(d)
    elif setting == "nTransactionFee":
        return vds.read_int64()
    elif setting == "nLimitProcessors":
        return vds.read_int32()
    return "unknown setting"


class SerializationError(Exception):
    """Thrown when there's a problem deserializing or serializing"""


def overlapped_read(f, sz, overlap, maxlen=None):
    buffer = b""
    stop = False
    total_read = 0
    while not stop and (not maxlen or maxlen > total_read):
        new_content = os.read(f, sz)
        if not new_content:
            break
        total_read += len(new_content)
        buffer = buffer[-overlap:] + new_content
        yield buffer


class KEY:
    def __init__(self):
        self.prikey = None
        self.pubkey = None

    def generate(self, secret=None):
        if secret:
            exp = int(b"0x" + binascii.hexlify(secret), 16)
            self.prikey = ecdsa.SigningKey.from_secret_exponent(exp, curve=secp256k1)
        else:
            self.prikey = ecdsa.SigningKey.generate(curve=secp256k1)
        self.pubkey = self.prikey.get_verifying_key()
        return self.prikey.to_der()

    def set_privkey(self, key):
        if len(key) == 279:
            seq1, rest = der.remove_sequence(key)
            integer, rest = der.remove_integer(seq1)
            octet_str, rest = der.remove_octet_string(rest)
            (
                tag1,
                cons1,
                rest,
            ) = der.remove_constructed(rest)
            (
                tag2,
                cons2,
                rest,
            ) = der.remove_constructed(rest)
            point_str, rest = der.remove_bitstring(cons2)
            self.prikey = ecdsa.SigningKey.from_string(octet_str, curve=secp256k1)
        else:
            self.prikey = ecdsa.SigningKey.from_der(key)

    def set_pubkey(self, key):
        key = key[1:]
        self.pubkey = ecdsa.VerifyingKey.from_string(key, curve=secp256k1)

    def get_privkey(self):
        _p = self.prikey.curve.curve.p()
        _r = self.prikey.curve.generator.order()
        _Gx = self.prikey.curve.generator.x()
        _Gy = self.prikey.curve.generator.y()
        encoded_oid2 = der.encode_oid(*(1, 2, 840, 10045, 1, 1))
        encoded_gxgy = binascii.unhexlify("04" + ("%64x" % _Gx) + ("%64x" % _Gy))
        param_sequence = der.encode_sequence(
            ecdsa.der.encode_integer(1),
            der.encode_sequence(
                encoded_oid2,
                der.encode_integer(_p),
            ),
            der.encode_sequence(
                der.encode_octet_string("\x00"),
                der.encode_octet_string("\x07"),
            ),
            der.encode_octet_string(encoded_gxgy),
            der.encode_integer(_r),
            der.encode_integer(1),
        )
        encoded_vk = "\x00\x04" + self.pubkey.to_string()
        return der.encode_sequence(
            der.encode_integer(1),
            der.encode_octet_string(self.prikey.to_string()),
            der.encode_constructed(0, param_sequence),
            der.encode_constructed(1, der.encode_bitstring(encoded_vk)),
        )

    def get_pubkey(self):
        return "\x04" + self.pubkey.to_string()

    def sign(self, hash):
        sig = self.prikey.sign_digest(hash, sigencode=ecdsa.util.sigencode_der)
        return binascii.hexlify(sig)

    def verify(self, hash, sig):
        return self.pubkey.verify_digest(sig, hash, sigdecode=ecdsa.util.sigdecode_der)


def message_to_hash(msg, msgIsHex=False):
    str = ""
    # 	str += '04%064x%064x'%(pubkey.point.x(), pubkey.point.y())
    # 	str += "Padding text - "
    str += msg
    if msgIsHex:
        str = binascii.unhexlify(str)
    hash = Hash(str)
    return hash


def sign_message(secret, msg, msgIsHex=False):
    k = KEY()
    k.generate(secret)
    return k.sign(message_to_hash(msg, msgIsHex))


def verify_message_signature(pubkey, sign, msg, msgIsHex=False):
    k = KEY()
    k.set_pubkey(binascii.unhexlify(pubkey))
    return k.verify(message_to_hash(msg, msgIsHex), binascii.unhexlify(sign))


class BCDataStream(object):
    def __init__(self):
        self.input = None
        self.read_cursor = 0

    def clear(self):
        self.input = None
        self.read_cursor = 0

    def write(self, bytes):  # Initialize with string of bytes
        if self.input is None:
            self.input = bytes
        else:
            self.input += bytes

    def map_file(self, file, start):  # Initialize with bytes from file
        self.input = mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ)
        self.read_cursor = start

    def seek_file(self, position):
        self.read_cursor = position

    def close_file(self):
        self.input.close()

    def read_string(self):
        # Strings are encoded depending on length:
        # 0 to 252 :	1-byte-length followed by bytes (if any)
        # 253 to 65,535 : byte'253' 2-byte-length followed by bytes
        # 65,536 to 4,294,967,295 : byte '254' 4-byte-length followed by bytes
        # ... and the Bitcoin client is coded to understand:
        # greater than 4,294,967,295 : byte '255' 8-byte-length followed by bytes of string
        # ... but I don't think it actually handles any strings that big.
        if self.input is None:
            raise SerializationError("call write(bytes) before trying to deserialize")

        try:
            length = self.read_compact_size()
        except IndexError:
            raise SerializationError("attempt to read past end of buffer")

        return self.read_bytes(length)

    def write_string(self, string):
        # Length-encoded as with read-string
        self.write_compact_size(len(string))
        self.write(string)

    def read_bytes(self, length):
        try:
            result = self.input[self.read_cursor : self.read_cursor + length]
            self.read_cursor += length
            return result
        except IndexError:
            raise SerializationError("attempt to read past end of buffer")

        return b""

    def read_boolean(self):
        return self.read_bytes(1)[0] != chrsix(0)

    def read_int16(self):
        return self._read_num("<h")

    def read_uint16(self):
        return self._read_num("<H")

    def read_int32(self):
        return self._read_num("<i")

    def read_uint32(self):
        return self._read_num("<I")

    def read_int64(self):
        return self._read_num("<q")

    def read_uint64(self):
        return self._read_num("<Q")

    def write_boolean(self, val):
        return self.write(chrsix(int(val)))

    def write_int16(self, val):
        return self._write_num("<h", val)

    def write_uint16(self, val):
        return self._write_num("<H", val)

    def write_int32(self, val):
        return self._write_num("<i", val)

    def write_uint32(self, val):
        return self._write_num("<I", val)

    def write_int64(self, val):
        return self._write_num("<q", val)

    def write_uint64(self, val):
        return self._write_num("<Q", val)

    def read_compact_size(self):
        size = ordsix(self.input[self.read_cursor])
        self.read_cursor += 1
        if size == 253:
            size = self._read_num("<H")
        elif size == 254:
            size = self._read_num("<I")
        elif size == 255:
            size = self._read_num("<Q")
        return size

    def write_compact_size(self, size):
        if size < 0:
            raise SerializationError("attempt to write size < 0")
        elif size < 253:
            self.write(chrsix(size))
        elif size < 2**16:
            self.write("\xfd")
            self._write_num("<H", size)
        elif size < 2**32:
            self.write("\xfe")
            self._write_num("<I", size)
        elif size < 2**64:
            self.write("\xff")
            self._write_num("<Q", size)

    def _read_num(self, format):
        (i,) = struct.unpack_from(format, self.input, self.read_cursor)
        self.read_cursor += struct.calcsize(format)
        return i

    def _write_num(self, format, num):
        s = struct.pack(format, num)
        self.write(s)


def open_wallet(db_env, walletfile, writable=False):
    db = DB(db_env)
    if writable:
        DB_TYPEOPEN = DB_CREATE
    else:
        DB_TYPEOPEN = DB_RDONLY
    flags = DB_THREAD | DB_TYPEOPEN
    try:
        r = db.open(walletfile, "main", DB_BTREE, flags)
    except DBError as e:
        print(e)
        r = True

    if not (r is None):
        logging.error(
            "Couldn't open wallet.dat/main. Try quitting Bitcoin and running this again."
        )
        sys.exit(1)

    return db


def parse_wallet(db, item_callback):
    kds = BCDataStream()
    vds = BCDataStream()

    def parse_TxIn(vds):
        d = Bdict({})
        d["prevout_hash"] = binascii.hexlify(vds.read_bytes(32))
        d["prevout_n"] = vds.read_uint32()
        d["scriptSig"] = binascii.hexlify(vds.read_bytes(vds.read_compact_size()))
        d["sequence"] = vds.read_uint32()
        return d

    def parse_TxOut(vds):
        d = Bdict({})
        d["value"] = vds.read_int64() // 1e8
        d["scriptPubKey"] = binascii.hexlify(vds.read_bytes(vds.read_compact_size()))
        return d

    for key, value in db.items():
        d = Bdict({})

        kds.clear()
        kds.write(key)
        vds.clear()
        vds.write(value)

        type = kds.read_string()

        d["__key__"] = key
        d["__value__"] = value
        d["__type__"] = type

        try:
            if type == b"tx":
                d["tx_id"] = binascii.hexlify(kds.read_bytes(32)[::-1])
                start = vds.read_cursor
                d["version"] = vds.read_int32()
                n_vin = vds.read_compact_size()
                d["txIn"] = []
                for i in range(n_vin):
                    d["txIn"].append(parse_TxIn(vds))
                n_vout = vds.read_compact_size()
                d["txOut"] = []
                for i in range(n_vout):
                    d["txOut"].append(parse_TxOut(vds))
                d["lockTime"] = vds.read_uint32()
                d["tx"] = binascii.hexlify(vds.input[start : vds.read_cursor])
                d["txv"] = binascii.hexlify(value)
                d["txk"] = binascii.hexlify(key)
            elif type == b"name":
                d["hash"] = kds.read_string()
                d["name"] = vds.read_string()
            elif type == b"version":
                d["version"] = vds.read_uint32()
            elif type == b"minversion":
                d["minversion"] = vds.read_uint32()
            elif type == b"setting":
                d["setting"] = kds.read_string()
                d["value"] = parse_setting(d["setting"], vds)
            elif type == b"key":
                d["public_key"] = kds.read_bytes(kds.read_compact_size())
                d["private_key"] = vds.read_bytes(vds.read_compact_size())
            elif type == b"wkey":
                d["public_key"] = kds.read_bytes(kds.read_compact_size())
                d["private_key"] = vds.read_bytes(vds.read_compact_size())
                d["created"] = vds.read_int64()
                d["expires"] = vds.read_int64()
                d["comment"] = vds.read_string()
            elif type == b"defaultkey":
                d["key"] = vds.read_bytes(vds.read_compact_size())
            elif type == b"pool":
                d["n"] = kds.read_int64()
                d["nVersion"] = vds.read_int32()
                d["nTime"] = vds.read_int64()
                d["public_key"] = vds.read_bytes(vds.read_compact_size())
            elif type == b"acc":
                d["account"] = kds.read_string()
                d["nVersion"] = vds.read_int32()
                d["public_key"] = vds.read_bytes(vds.read_compact_size())
            elif type == b"acentry":
                d["account"] = kds.read_string()
                d["n"] = kds.read_uint64()
                d["nVersion"] = vds.read_int32()
                d["nCreditDebit"] = vds.read_int64()
                d["nTime"] = vds.read_int64()
                d["otherAccount"] = vds.read_string()
                d["comment"] = vds.read_string()
            # elif type == b"bestblock":
            # 	d['nVersion'] = vds.read_int32()
            # 	d.update(parse_BlockLocator(vds))
            elif type == b"ckey":
                d["public_key"] = kds.read_bytes(kds.read_compact_size())
                d["encrypted_private_key"] = vds.read_bytes(vds.read_compact_size())
            elif type == b"mkey":
                d["nID"] = kds.read_uint32()
                d["encrypted_key"] = vds.read_string()
                d["salt"] = vds.read_string()
                d["nDerivationMethod"] = vds.read_uint32()
                d["nDerivationIterations"] = vds.read_uint32()
                d["otherParams"] = vds.read_string()

            item_callback(type, d)

        except Exception as e:
            traceback.print_exc()
            print("ERROR parsing wallet.dat, type %s" % type)
            print("key data: %s" % key)
            print("key data in hex: %s" % binascii.hexlify(key))
            print("value data in hex: %s" % binascii.hexlify(value))
            sys.exit(1)


def delete_from_wallet(db_env, walletfile, typedel, kd):
    db = open_wallet(db_env, walletfile, True)
    kds = BCDataStream()
    vds = BCDataStream()

    deleted_items = 0

    if not isinstance(kd, list):
        kd = [kd]

    if typedel == "tx" and kd != ["all"]:
        for keydel in kd:
            db.delete("\x02\x74\x78" + binascii.unhexlify(keydel)[::-1])
            deleted_items += 1

    else:
        for i, keydel in enumerate(kd):
            for key, value in db.items():
                kds.clear()
                kds.write(key)
                vds.clear()
                vds.write(value)
                type = kds.read_string()

                if typedel == "tx" and type == b"tx":
                    db.delete(key)
                    deleted_items += 1
                elif typedel == "key":
                    if type == b"key" or type == b"ckey":
                        if keydel == public_key_to_bc_address(
                            kds.read_bytes(kds.read_compact_size())
                        ):
                            db.delete(key)
                            deleted_items += 1
                    elif type == b"pool":
                        vds.read_int32()
                        vds.read_int64()
                        if keydel == public_key_to_bc_address(
                            vds.read_bytes(vds.read_compact_size())
                        ):
                            db.delete(key)
                            deleted_items += 1
                    elif type == b"name":
                        if keydel == kds.read_string():
                            db.delete(key)
                            deleted_items += 1

    db.close()
    return deleted_items


def merge_keys_lists(la, lb):
    lr = Bdict({})
    llr = []
    for k in la:
        lr[k[0]] = k[1]

    for k in lb:
        if k[0] in lr.keys():
            lr[k[0]] = lr[k[0]] + " / " + k[1]
        else:
            lr[k[0]] = k[1]

    for k, j in lr.items():
        llr.append([k, j])

    return llr


def merge_wallets(wadir, wa, wbdir, wb, wrdir, wr, passphrase_a, passphrase_b, passphrase_r):
    global passphrase
    passphrase_LAST = passphrase

    # Read Wallet 1
    passphrase = passphrase_a
    dba_env = create_env(wadir)
    crypted_a = read_wallet(json_db, dba_env, wa, True, True, "", None)["crypted"]

    list_keys_a = []
    for i in json_db["keys"]:
        try:
            label = i["label"]
        except:
            label = "#Reserve"
        try:
            list_keys_a.append([i["secret"], label])
        except:
            pass

    if len(list_keys_a) == 0:
        return [False, "Something went wrong with the first wallet."]

    # Read Wallet 2
    passphrase = passphrase_b
    dbb_env = create_env(wbdir)
    crypted_b = read_wallet(json_db, dbb_env, wb, True, True, "", None)["crypted"]

    list_keys_b = []
    for i in json_db["keys"]:
        try:
            label = i["label"]
        except:
            label = "#Reserve"
        try:
            list_keys_b.append([i["secret"], label])
        except:
            pass
    if len(list_keys_b) == 0:
        return [False, "Something went wrong with the second wallet."]

    m = merge_keys_lists(list_keys_a, list_keys_b)

    # Create new wallet
    dbr_env = create_env(wrdir)
    create_new_wallet(dbr_env, wr, 80100)

    dbr = open_wallet(dbr_env, wr, True)
    update_wallet(dbr, "minversion", {"minversion": 60000})

    if len(passphrase_r) > 0:
        NPP_salt = os.urandom(8)
        NPP_rounds = int(50000 + random.random() * 20000)
        NPP_method = 0
        NPP_MK = os.urandom(32)

        crypter.SetKeyFromPassphrase(passphrase_r, NPP_salt, NPP_rounds, NPP_method)
        NPP_EMK = crypter.Encrypt(NPP_MK)

        update_wallet(
            dbr,
            "mkey",
            {
                "encrypted_key": NPP_EMK,
                "nDerivationIterations": NPP_rounds,
                "nDerivationMethod": NPP_method,
                "nID": 1,
                "otherParams": b"",
                "salt": NPP_salt,
            },
        )

    dbr.close()

    t = "\n".join(map(lambda x: ";".join(x), m))
    passphrase = passphrase_r

    global global_merging_message

    global_merging_message = ["Merging...", "Merging..."]
    thread.start_new_thread(
        import_csv_keys,
        (
            "\x00" + t,
            wrdir,
            wr,
        ),
    )
    t = ""

    passphrase = passphrase_LAST

    return [True]


def update_wallet(db, types, datas, paramsAreLists=False):
    """Write a single item to the wallet.
    db must be open with writable=True.
    type and data are the type code and data dictionary as parse_wallet would
    give to item_callback.
    data's __key__, __value__ and __type__ are ignored; only the primary data
    fields are used.
    """

    if not paramsAreLists:
        types = [types]
        datas = [datas]

    if len(types) != len(datas):
        raise Exception("UpdateWallet: sizes are different")

    for it, type in enumerate(types):
        type = str_to_bytes(type)
        data = datas[it]

        d = data
        kds = BCDataStream()
        vds = BCDataStream()

        # Write the type code to the key
        kds.write_string(type)
        vds.write(b"")  # Ensure there is something

        try:
            if type == b"tx":
                # 			raise NotImplementedError("Writing items of type 'tx'")
                kds.write(binascii.unhexlify(d["txi"][6:]))
                vds.write(binascii.unhexlify(d["txv"]))
            elif type == b"name":
                kds.write_string(d["hash"])
                vds.write_string(d["name"])
            elif type == b"version":
                vds.write_uint32(d["version"])
            elif type == b"minversion":
                vds.write_uint32(d["minversion"])
            elif type == b"setting":
                raise NotImplementedError("Writing items of type 'setting'")
                kds.write_string(d["setting"])
                # d['value'] = parse_setting(d['setting'], vds)
            elif type == b"key":
                kds.write_string(d["public_key"])
                vds.write_string(d["private_key"])
            elif type == b"wkey":
                kds.write_string(d["public_key"])
                vds.write_string(d["private_key"])
                vds.write_int64(d["created"])
                vds.write_int64(d["expires"])
                vds.write_string(d["comment"])
            elif type == b"defaultkey":
                vds.write_string(d["key"])
            elif type == b"pool":
                kds.write_int64(d["n"])
                vds.write_int32(d["nVersion"])
                vds.write_int64(d["nTime"])
                vds.write_string(d["public_key"])
            elif type == b"acc":
                kds.write_string(d["account"])
                vds.write_int32(d["nVersion"])
                vds.write_string(d["public_key"])
            elif type == b"acentry":
                kds.write_string(d["account"])
                kds.write_uint64(d["n"])
                vds.write_int32(d["nVersion"])
                vds.write_int64(d["nCreditDebit"])
                vds.write_int64(d["nTime"])
                vds.write_string(d["otherAccount"])
                vds.write_string(d["comment"])
            # elif type == b"bestblock":
            # 	vds.write_int32(d['nVersion'])
            # 	vds.write_compact_size(len(d['hashes']))
            # 	for h in d['hashes']:
            # 		vds.write(h)
            elif type == b"ckey":
                kds.write_string(d["public_key"])
                vds.write_string(d["encrypted_private_key"])
            elif type == b"mkey":
                kds.write_uint32(d["nID"])
                vds.write_string(d["encrypted_key"])
                vds.write_string(d["salt"])
                vds.write_uint32(d["nDerivationMethod"])
                vds.write_uint32(d["nDerivationIterations"])
                vds.write_string(d["otherParams"])

            else:
                print("Unknown key type: %s" % type)

            # Write the key/value pair to the database
            db.put(kds.input, vds.input)

        except Exception as e:
            print("ERROR writing to wallet.dat, type %s" % type)
            print("data dictionary: %r" % data)
            traceback.print_exc()


def create_new_wallet(db_env, walletfile, version):
    db_out = DB(db_env)

    try:
        r = db_out.open(walletfile, "main", DB_BTREE, DB_CREATE)
    except DBError:
        r = True

    if not (r is None):
        logging.error("Couldn't open %s." % walletfile)
        sys.exit(1)

    db_out.put(
        binascii.unhexlify("0776657273696f6e"),
        binascii.unhexlify("%08x" % version)[::-1],
    )

    db_out.close()


def rewrite_wallet(db_env, walletfile, destFileName, pre_put_callback=None):
    db = open_wallet(db_env, walletfile)

    db_out = DB(db_env)
    try:
        r = db_out.open(destFileName, "main", DB_BTREE, DB_CREATE)
    except DBError:
        r = True

    if not (r is None):
        logging.error("Couldn't open %s." % destFileName)
        sys.exit(1)

    def item_callback(type, d):
        if pre_put_callback is None or pre_put_callback(type, d):
            db_out.put(d["__key__"], d["__value__"])

    parse_wallet(db, item_callback)
    db_out.close()
    db.close()


# end of bitcointools wallet.dat handling code

# wallet.dat reader / writer

addr_to_keys = {}


KeyInfo = collections.namedtuple(
    "KeyInfo",
    "secret private_key public_key uncompressed_public_key addr wif compressed",
)


def read_wallet(
    json_db,
    db_env,
    walletfile,
    print_wallet,
    print_wallet_transactions,
    transaction_filter,
    include_balance,
    FillPool=False,
):
    global passphrase, addr_to_keys
    crypted = False

    private_keys = []
    private_hex_keys = []

    db = open_wallet(db_env, walletfile, writable=FillPool)

    json_db["keys"] = []
    json_db["pool"] = []
    json_db["tx"] = []
    json_db["names"] = Bdict({})
    json_db["ckey"] = []
    json_db["mkey"] = Bdict({})

    def item_callback(type, d):
        if type == b"tx":
            json_db["tx"].append(
                {
                    "tx_id": d["tx_id"],
                    "txin": d["txIn"],
                    "txout": d["txOut"],
                    "tx_v": d["txv"],
                    "tx_k": d["txk"],
                }
            )

        elif type == b"name":
            json_db["names"][d["hash"]] = d["name"]

        elif type == b"version":
            json_db["version"] = d["version"]

        elif type == b"minversion":
            json_db["minversion"] = d["minversion"]

        elif type == b"setting":
            if not json_db.has_key("settings"):
                json_db["settings"] = Bdict({})
            json_db["settings"][d["setting"]] = d["value"]

        elif type == b"defaultkey":
            json_db["defaultkey"] = public_key_to_bc_address(d["key"])

        elif type == b"key":
            addr = public_key_to_bc_address(d["public_key"])
            compressed = d["public_key"][0] != "\04"
            sec = SecretToASecret(PrivKeyToSecret(d["private_key"]), compressed)
            hexsec = binascii.hexlify(ASecretToSecret(sec)[:32])
            private_keys.append(sec)
            addr_to_keys[addr] = [hexsec, binascii.hexlify(d["public_key"])]
            json_db["keys"].append(
                {
                    "addr": addr,
                    "sec": sec,
                    "hexsec": hexsec,
                    "secret": hexsec,
                    "pubkey": binascii.hexlify(d["public_key"]),
                    "compressed": compressed,
                    "private": binascii.hexlify(d["private_key"]),
                }
            )

        elif type == b"wkey":
            if not json_db.has_key("wkey"):
                json_db["wkey"] = []
            json_db["wkey"]["created"] = d["created"]

        elif type == b"pool":
            """d['n'] = kds.read_int64()
            d['nVersion'] = vds.read_int32()
            d['nTime'] = vds.read_int64()
            d['public_key'] = vds.read_bytes(vds.read_compact_size())"""
            try:
                json_db["pool"].append(
                    {
                        "n": d["n"],
                        "addr": public_key_to_bc_address(d["public_key"]),
                        "addr2": public_key_to_bc_address(binascii.unhexlify(d["public_key"])),
                        "addr3": public_key_to_bc_address(binascii.hexlify(d["public_key"])),
                        "nTime": d["nTime"],
                        "nVersion": d["nVersion"],
                        "public_key_hex": d["public_key"],
                    }
                )
            except:
                json_db["pool"].append(
                    {
                        "n": d["n"],
                        "addr": public_key_to_bc_address(d["public_key"]),
                        "nTime": d["nTime"],
                        "nVersion": d["nVersion"],
                        "public_key_hex": binascii.hexlify(d["public_key"]),
                    }
                )

        elif type == b"acc":
            json_db["acc"] = d["account"]
            # print("Account %s (current key: %s)"%(d['account'], public_key_to_bc_address(d['public_key'])))

        elif type == b"acentry":
            json_db["acentry"] = (
                d["account"],
                d["nCreditDebit"],
                d["otherAccount"],
                time.ctime(d["nTime"]),
                d["n"],
                d["comment"],
            )

        # elif type == b"bestblock":
        # 	json_db['bestblock'] = binascii.hexlify(d['hashes'][0][::-1])

        elif type == b"ckey":
            crypted = True
            compressed = d["public_key"][0] != "\04"
            json_db["keys"].append(
                {
                    "pubkey": binascii.hexlify(d["public_key"]),
                    "addr": public_key_to_bc_address(d["public_key"]),
                    "encrypted_privkey": binascii.hexlify(d["encrypted_private_key"]),
                    "compressed": compressed,
                }
            )

        elif type == b"mkey":
            json_db["mkey"]["nID"] = d["nID"]
            json_db["mkey"]["encrypted_key"] = binascii.hexlify(d["encrypted_key"])
            json_db["mkey"]["salt"] = binascii.hexlify(d["salt"])
            json_db["mkey"]["nDerivationMethod"] = d["nDerivationMethod"]
            json_db["mkey"]["nDerivationIterations"] = d["nDerivationIterations"]
            json_db["mkey"]["otherParams"] = d["otherParams"]

            if passphrase:
                res = crypter.SetKeyFromPassphrase(
                    passphrase,
                    d["salt"],
                    d["nDerivationIterations"],
                    d["nDerivationMethod"],
                )
                if res == 0:
                    logging.error("Unsupported derivation method")
                    sys.exit(1)
                masterkey = crypter.Decrypt(d["encrypted_key"])
                crypter.SetKey(masterkey)

        else:
            json_db[type] = "unsupported"
            if type not in b"keymeta".split():
                print("Wallet data not recognized: %s" % str(d))

    list_of_reserve_not_in_pool = []
    parse_wallet(db, item_callback)

    nkeys = len(json_db["keys"])
    i = 0
    for k in json_db["keys"]:
        i += 1
        addr = k["addr"]
        if include_balance:
            # 			print("%3d/%d  %s  %s" % (i, nkeys, k["addr"], k["balance"]))
            k["balance"] = balance(balance_site, k["addr"])
        # 			print("  %s" % (i, nkeys, k["addr"], k["balance"]))

        if addr in json_db["names"].keys():
            k["label"] = json_db["names"][addr]
            k["reserve"] = 0
        else:
            k["reserve"] = 1
            list_of_reserve_not_in_pool.append(k["pubkey"])

    def rnip_callback(a):
        list_of_reserve_not_in_pool.remove(a["public_key_hex"])

    if FillPool:
        map(rnip_callback, json_db["pool"])

        cpt = 1
        for p in list_of_reserve_not_in_pool:
            update_wallet(
                db,
                "pool",
                {
                    "public_key": binascii.unhexlify(p),
                    "n": cpt,
                    "nTime": ts(),
                    "nVersion": 80100,
                },
            )
            cpt += 1

    db.close()

    crypted = "salt" in json_db["mkey"]

    if not crypted:
        print("The wallet is not encrypted")

    if crypted and not passphrase:
        print("The wallet is encrypted but no passphrase is used")

    if crypted and passphrase:
        check = True
        ppcorrect = True
        for k in json_db["keys"]:
            if "encrypted_privkey" in k:
                ckey = binascii.unhexlify(k["encrypted_privkey"])
                public_key = binascii.unhexlify(k["pubkey"])
                crypter.SetIV(Hash(public_key))
                secret = crypter.Decrypt(ckey)
                compressed = public_key[0] != "\04"

                if check:
                    check = False
                    pkey = EC_KEY(int(b"0x" + binascii.hexlify(secret), 16))
                    if public_key != GetPubKey(pkey, compressed):
                        print("The wallet is encrypted and the passphrase is incorrect")
                        ppcorrect = False
                        break

                sec = SecretToASecret(secret, compressed)
                k["sec"] = sec
                k["hexsec"] = binascii.hexlify(secret[:32])
                k["secret"] = binascii.hexlify(secret)
                k["compressed"] = compressed
                addr_to_keys[k["addr"]] = [sec, k["pubkey"]]
                # 			del(k['ckey'])
                # 			del(k['secret'])
                # 			del(k['pubkey'])
                private_keys.append(sec)
        if ppcorrect:
            print("The wallet is encrypted and the passphrase is correct")

    for k in json_db["keys"]:
        if k["compressed"] and "secret" in k:
            k["secret"] += b"01"

    # 	del(json_db['pool'])
    # 	del(json_db['names'])

    return {"crypted": crypted}


def parse_private_key(sec, force_compressed=None):
    def as_compressed(x):
        return x if force_compressed is None else force_compressed

    try:
        pkey = regenerate_key(sec)
        compressed = as_compressed(is_compressed(sec))
    except:
        pkey = None
        try:
            binascii.unhexlify(sec)
        except:
            pass
    if not pkey:
        if len(sec) == 64:
            pkey = EC_KEY(str_to_int(binascii.unhexlify(sec)))
            compressed = as_compressed(False)
        elif len(sec) == 66:
            pkey = EC_KEY(str_to_int(binascii.unhexlify(sec[:-2])))
            compressed = as_compressed(True)
        else:
            warnings.warn(
                "Hexadecimal private keys must be 64 or 66 characters int (specified one is "
                + str(len(sec))
                + " characters int)"
            )
            if len(sec) < 64:
                compressed = as_compressed(False)
                warnings.warn(
                    "Padding with zeroes, %scompressed" % ("un" if not compressed else "")
                )
                try:
                    pkey = EC_KEY(str_to_int(binascii.unhexlify("0" * (64 - len(sec)) + sec)))
                except Exception as e:
                    warnings.warn(e)
                    raise Exception("Failed padding with zeroes")
            elif len(sec) > 66:
                compressed = as_compressed(False)
                warnings.warn(
                    "Keeping first 64 characters, %scompressed" % ("un" if not compressed else "")
                )
                pkey = EC_KEY(str_to_int(binascii.unhexlify(sec[:64])))
            else:
                raise Exception("Error")
    return (pkey, compressed)


def pubkey_info(pubkey, network):
    addr = public_key_to_bc_address(pubkey, network.p2pkh_prefix)
    p2wpkh = p2sh_script_to_addr(b"\x00\x14" + hash_160(pubkey))
    witaddr = witprog_to_bech32_addr(hash_160(pubkey), network)
    h160 = bc_address_to_hash_160(addr)
    return addr, p2wpkh, witaddr, h160


def keyinfo(sec, network=None, print_info=False, force_compressed=None):
    if not (network is None) and network.__class__ != Network:
        network = find_network(network) or network
    if sec.__class__ == Xpriv:
        assert sec.ktype == 0
        return keyinfo(binascii.hexlify(sec.key), network, print_info, force_compressed)
    network = network or network_bitcoin
    (pkey, compressed) = parse_private_key(sec, force_compressed)
    if not pkey:
        return False

    secret = GetSecret(pkey)
    private_key = GetPrivKey(pkey, compressed)
    uncompressed_ser_public_key = GetPubKey(pkey, False)
    ser_public_key = GetPubKey(pkey, compressed)
    addr, p2wpkh, witaddr, h160 = pubkey_info(ser_public_key, network)
    wif = SecretToASecret(secret, compressed) if network.wif_prefix else None

    if print_info:
        print("Network: %s" % network.name)
        print("Compressed: %s" % str(compressed))
        if network.p2pkh_prefix != None:
            print("P2PKH Address:       %s" % (addr))
        if compressed:
            if network.p2sh_prefix != None:
                print("P2SH-P2WPKH Address: %s" % (p2wpkh))
            else:
                print("P2SH unavailable:    unknown network P2SH prefix")
        if compressed:
            if network.segwit_hrp != None:
                print("P2WPKH Address:      %s" % (witaddr))
            else:
                print("P2WPKH unavailable:  unknown network SegWit HRP")
        if network.wif_prefix != None:
            print("Privkey:             %s" % wif)
        else:
            print("Privkey unavailable: unknown network WIF prefix")
        print("Hexprivkey:          %s" % bytes_to_str(binascii.hexlify(secret)))
        if compressed:
            warnings.warn(
                "    For compressed keys, the hexadecimal private key sometimes contains an extra '01' at the end"
            )
        print("Hash160:             %s" % bytes_to_str(binascii.hexlify(h160)))
        print("Pubkey:              %s" % bytes_to_str(binascii.hexlify(ser_public_key)))
        if int(binascii.hexlify(secret), 16) > _r:
            warnings.warn(
                "/!\\ Beware, 0x%s is equivalent to 0x%.33x"
                % (binascii.hexlify(secret), int(binascii.hexlify(secret), 16) - _r)
            )

    r = KeyInfo(
        secret,
        private_key,
        ser_public_key,
        uncompressed_ser_public_key,
        addr,
        wif,
        compressed,
    )
    if network:
        ki = network.keyinfo(r, print_info=print_info)
        if ki:
            addr = ki.addr
        r = KeyInfo(
            secret,
            private_key,
            ser_public_key,
            uncompressed_ser_public_key,
            addr,
            wif,
            compressed,
        )
    return r


def importprivkey(db, sec, label, reserve, verbose=True, network=DEFAULT_NETWORK):
    k = keyinfo(sec, network, verbose)
    secret = k.secret
    private_key = k.private_key
    public_key = k.public_key
    addr = k.addr

    global crypter, passphrase, json_db
    crypted = False
    if "mkey" in json_db.keys() and "salt" in json_db["mkey"]:
        crypted = True
    if crypted:
        if passphrase:
            cry_master = binascii.unhexlify(json_db["mkey"]["encrypted_key"])
            cry_salt = binascii.unhexlify(json_db["mkey"]["salt"])
            cry_rounds = json_db["mkey"]["nDerivationIterations"]
            cry_method = json_db["mkey"]["nDerivationMethod"]

            crypter.SetKeyFromPassphrase(passphrase, cry_salt, cry_rounds, cry_method)
            # 			if verbose:
            # 				print("Import with", passphrase, "", binascii.hexlify(cry_master), "", binascii.hexlify(cry_salt))
            masterkey = crypter.Decrypt(cry_master)
            crypter.SetKey(masterkey)
            crypter.SetIV(Hash(public_key))
            e = crypter.Encrypt(secret)
            ck_epk = e

            update_wallet(db, "ckey", {"public_key": public_key, "encrypted_private_key": ck_epk})
    else:
        update_wallet(db, "key", {"public_key": public_key, "private_key": private_key})

    if not reserve:
        update_wallet(db, "name", {"hash": addr, "name": label})

    return True


def read_jsonfile(filename):
    filin = open(filename, "r")
    txdump = filin.read()
    filin.close()
    return json.loads(txdump)


def write_jsonfile(filename, array):
    filout = open(filename, "w")
    filout.write(json.dumps(array, sort_keys=True, indent=0))
    filout.close()


def export_all_keys(db, ks, filename):
    txt = ";".join(ks) + "\n"
    for i in db["keys"]:
        try:
            j = i.copy()
            if "label" not in j:
                j["label"] = "#Reserve"
            t = ";".join([str(j[k]) for k in ks])
            txt += t + "\n"
        except:
            return False

    try:
        myFile = open(filename, "w")
        myFile.write(txt)
        myFile.close()
        return True
    except:
        return False


def import_csv_keys(filename, wdir, wname, nbremax=9999999):
    global global_merging_message
    if filename[0] == "\x00":  # yeah, dirty workaround
        content = filename[1:]
    else:
        filen = open(filename, "r")
        content = filen.read()
        filen.close()

    db_env = create_env(wdir)
    read_wallet(json_db, db_env, wname, True, True, "", None)
    db = open_wallet(db_env, wname, writable=True)

    content = content.split("\n")
    content = content[: min(nbremax, len(content))]
    for i in range(len(content)):
        c = content[i]
        global_merging_message = [
            "Merging: " + str(round(100.0 * (i + 1) // len(content), 1)) + "%" for j in range(2)
        ]
        if ";" in c and len(c) > 0 and c[0] != "#":
            cs = c.split(";")
            sec, label = cs[0:2]
            reserve = False
            if label == "#Reserve":
                reserve = True
            importprivkey(db, sec, label, reserve, verbose=False)

    global_merging_message = ["Merging done.", ""]

    db.close()

    read_wallet(json_db, db_env, wname, True, True, "", None, True)  # Fill the pool if empty

    return True


def random_string(l, alph="0123456789abcdef"):
    r = ""
    la = len(alph)
    for i in range(l):
        r += alph[int(la * (random.random()))]
    return r


def clone_wallet(parentPath, clonePath):
    types, datas = [], []
    parentdir, parentname = os.path.split(parentPath)
    wdir, wname = os.path.split(clonePath)

    db_env = create_env(parentdir)
    read_wallet(json_db, db_env, parentname, True, True, "", False)

    types.append("version")
    datas.append({"version": json_db["version"]})
    types.append("defaultkey")
    datas.append({"key": json_db["defaultkey"]})
    for k in json_db["keys"]:
        types.append("ckey")
        datas.append(
            {
                "public_key": binascii.unhexlify(k["pubkey"]),
                "encrypted_private_key": binascii.unhexlify(random_string(96)),
            }
        )
    for k in json_db["pool"]:
        types.append("pool")
        datas.append(
            {
                "n": k["n"],
                "nVersion": k["nVersion"],
                "nTime": k["nTime"],
                "public_key": binascii.unhexlify(k["public_key_hex"]),
            }
        )
    for addr, label in json_db["names"].items():
        types.append("name")
        datas.append({"hash": addr, "name": "Watch:" + label})

    db_env = create_env(wdir)
    create_new_wallet(db_env, wname, 60000)

    db = open_wallet(db_env, wname, True)
    NPP_salt = binascii.unhexlify(random_string(16))
    NPP_rounds = int(50000 + random.random() * 20000)
    NPP_method = 0
    NPP_MK = binascii.unhexlify(random_string(64))
    crypter.SetKeyFromPassphrase(random_string(64), NPP_salt, NPP_rounds, NPP_method)
    NPP_EMK = crypter.Encrypt(NPP_MK)
    update_wallet(
        db,
        "mkey",
        {
            "encrypted_key": NPP_EMK,
            "nDerivationIterations": NPP_rounds,
            "nDerivationMethod": NPP_method,
            "nID": 1,
            "otherParams": b"",
            "salt": NPP_salt,
        },
    )
    db.close()

    read_wallet(json_db, db_env, wname, True, True, "", False)

    db = open_wallet(db_env, wname, writable=True)
    update_wallet(db, types, datas, True)
    db.close()
    print("Wallet successfully cloned to:\n   %s" % clonePath)
