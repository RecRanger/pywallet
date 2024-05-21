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

import ecdsa
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

from pywallet.addresses import public_key_to_bc_address, Hash
from pywallet.ecdsa import secp256k1, der
from pywallet.types import Bdict
from pywallet.conversions import (
    ordsix,
    str_to_bytes,
    chrsix,
)
from pywallet.wallet_dat_reader import read_wallet, import_csv_keys
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
