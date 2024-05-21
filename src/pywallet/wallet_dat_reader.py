import binascii
import json
import sys
import time
import warnings
import logging
import collections
import random
import os


from pywallet.addresses import (
    ASecretToSecret,
    SecretToASecret,
    PrivKeyToSecret,
    GetPrivKey,
    GetPubKey,
    GetSecret,
    regenerate_key,
    is_compressed,
)
from pywallet.addresses import (
    public_key_to_bc_address,
    Hash,
    b58encode,
    b58decode,
    p2sh_script_to_addr,
    witprog_to_bech32_addr,
    bc_address_to_hash_160,
    hash_160,
)
from pywallet.conversions import (
    str_to_int,
    bytes_to_str,
)
from pywallet.ecdsa import EC_KEY, _r
from pywallet.types import Bdict
from pywallet.wallet_dat_handler import (
    create_env,
    open_wallet,
    parse_wallet,
    update_wallet,
    create_new_wallet,
)
from pywallet.networks import find_network, network_bitcoin, DEFAULT_NETWORK, Network
from pywallet.web_api import balance, balance_site
from pywallet.env_info import ts
from pywallet.bip39 import Xpriv

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
