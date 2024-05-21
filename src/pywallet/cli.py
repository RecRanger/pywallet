import json
import os
from optparse import OptionParser
import getpass
import binascii
import random

from pywallet.bip39 import dump_bip32_privkeys
from pywallet.types import Bdict
from pywallet.wallet_crypter import crypter
from pywallet.recovery import (
    recov,
    ts,
    read_device_size,
)
from pywallet.web_api import balance_site, balance
from pywallet.wallet_dat_handler import (
    create_env,
    create_new_wallet,
    open_wallet,
    update_wallet,
    delete_from_wallet,
    BCDataStream,
    clone_wallet,
    read_wallet,
    keyinfo,
    importprivkey,
)
from pywallet.networks import (
    network_bitcoin,
    network_bitcoin_testnet3,
    network_ethereum,
    find_network,
    Network,
)
from pywallet.extras import whitepaper


def plural(a):
    if a >= 2:
        return "s"
    return ""


def main():
    parser = OptionParser(usage="%prog [options]", version="%prog 1.1")

    parser.add_option(
        "--dump_bip32",
        nargs=2,
        help="dump the keys from a xpriv and a path, usage: --dump_bip32 xprv9s21ZrQH143K m/0H/1-2/2H/2-4",
    )

    parser.add_option("--bip32_format", help="format of dumped bip32 keys")

    parser.add_option(
        "--passphrase", dest="passphrase", help="passphrase for the encrypted wallet"
    )

    parser.add_option("--find_address", help="find info about an address")

    parser.add_option(
        "-d",
        "--dumpwallet",
        dest="dump",
        action="store_true",
        help="dump wallet in json format",
    )

    parser.add_option(
        "--dumpformat", default="all", help="choose what to extract in a wallet dump"
    )

    parser.add_option(
        "--dumpwithbalance",
        dest="dumpbalance",
        action="store_true",
        help="includes balance of each address in the json dump, takes about 2 minutes per 100 addresses",
    )

    parser.add_option("--importprivkey", dest="key", help="import private key from vanitygen")

    parser.add_option(
        "--importhex", dest="keyishex", action="store_true", help="DEPRECATED, useless"
    )

    parser.add_option(
        "--datadir",
        dest="datadir",
        help="REMOVED OPTION: put full path in the --wallet option",
    )

    parser.add_option(
        "-w",
        "--wallet",
        dest="walletfile",
        help="wallet filename (defaults to wallet.dat)",
        default="",
    )

    parser.add_option(
        "--label",
        dest="label",
        help="label shown in the adress book (defaults to '')",
        default="",
    )

    parser.add_option(
        "--testnet",
        dest="testnet",
        action="store_true",
        help="use testnet subdirectory and address type",
    )

    parser.add_option(
        "--namecoin",
        dest="namecoin",
        action="store_true",
        help="use namecoin address type",
    )

    parser.add_option(
        "--eth", dest="ethereum", action="store_true", help="use ethereum address type"
    )

    parser.add_option(
        "--otherversion",
        dest="otherversion",
        help="use other network address type, either P2PKH prefix only (e.g. 111) or full network info as 'name,p2pkh,p2sh,wif,segwithrp' (e.g. btc,0,0,0x80,bc)",
    )

    parser.add_option(
        "--info",
        dest="keyinfo",
        action="store_true",
        help="display pubkey, privkey (both depending on the network) and hexkey",
    )

    parser.add_option(
        "--reserve",
        dest="reserve",
        action="store_true",
        help="import as a reserve key, i.e. it won't show in the adress book",
    )

    parser.add_option(
        "--multidelete",
        dest="multidelete",
        help="deletes data in your wallet, according to the file provided",
    )

    parser.add_option("--balance", dest="key_balance", help="prints balance of KEY_BALANCE")

    parser.add_option(
        "--recover",
        dest="recover",
        action="store_true",
        help="recover your deleted keys, use with recov_size and recov_device",
    )

    parser.add_option(
        "--recov_device",
        dest="recov_device",
        help="device to read (e.g. /dev/sda1 or E: or a file)",
    )

    parser.add_option(
        "--recov_size",
        dest="recov_size",
        help="number of bytes to read (e.g. 20Mo or 50Gio)",
    )

    parser.add_option(
        "--recov_outputdir",
        dest="recov_outputdir",
        help="output directory where the recovered wallet will be put",
    )

    parser.add_option(
        "--clone_watchonly_from",
        dest="clone_watchonly_from",
        help="path of the original wallet",
    )

    parser.add_option(
        "--clone_watchonly_to",
        dest="clone_watchonly_to",
        help="path of the resulting watch-only wallet",
    )

    parser.add_option(
        "--dont_check_walletversion",
        dest="dcv",
        action="store_true",
        help="don't check if wallet version > %d before running (WARNING: this may break your wallet, be sure you know what you do)"
        % max_version,
    )

    parser.add_option(
        "--random_key",
        action="store_true",
        help="print info of a randomly generated private key",
    )

    parser.add_option(
        "--whitepaper",
        action="store_true",
        help="write the Bitcoin whitepaper using bitcoin-cli or blockchain.info",
    )

    parser.add_option(
        "--minimal_encrypted_copy",
        action="store_true",
        help="write a copy of an encrypted wallet with only an empty address, *should* be safe to share when needing help bruteforcing the password",
    )

    parser.add_option("--tests", action="store_true", help="run tests")

    # 	parser.add_option("--forcerun", dest="forcerun",
    # 		action="store_true",
    # 		help="run even if pywallet detects bitcoin is running")

    (options, args) = parser.parse_args()

    # 	a=Popen("ps xa | grep ' bitcoin'", shell=True, bufsize=-1, stdout=PIPE).stdout
    # 	aread=a.read()
    # 	nl = aread.count("\n")
    # 	a.close()
    # 	if nl > 2:
    # 		print('Bitcoin seems to be running: \n"%s"'%(aread))
    # 		if options.forcerun is None:
    # 			exit(0)

    # if options.tests:
    #     unittest.main(argv=sys.argv[:1] + ["TestPywallet"])
    #     exit()

    if options.dump_bip32:
        print(
            'Warning: single quotes (\') may be parsed by your terminal, please use "H" for hardened keys'
        )
        dump_bip32_privkeys(*options.dump_bip32, format=options.bip32_format)
        exit()

    if options.whitepaper:
        whitepaper()
        exit()

    if options.passphrase:
        passphrase = options.passphrase

    if not (options.clone_watchonly_from is None) and options.clone_watchonly_to:
        clone_wallet(options.clone_watchonly_from, options.clone_watchonly_to)
        exit(0)

    if options.recover:
        if (
            options.recov_size is None
            or options.recov_device is None
            or options.recov_outputdir is None
        ):
            print(
                "You must provide the device, the number of bytes to read and the output directory"
            )
            exit(0)
        device = options.recov_device
        if len(device) in [2, 3] and device[1] == ":":
            device = "\\\\.\\" + device
        size = read_device_size(options.recov_size)

        passphraseRecov = None
        while not passphraseRecov:
            passphraseRecov = getpass.getpass(
                "Enter the passphrase for the wallet that will contain all the recovered keys%s: "
                % ("" if passphraseRecov is None else " (can't be empty)")
            )
        passphrase = passphraseRecov

        passes = []
        p = " "
        print("\nEnter the possible passphrases used in your deleted wallets.")
        print("Don't forget that more passphrases = more time to test the possibilities.")
        print("Write one passphrase per line and end with an empty line.")
        while p != "":
            p = getpass.getpass("Possible passphrase: ")
            if p != "":
                passes.append(p)

        print("\nStarting recovery.")
        recoveredKeys = recov(device, passes, size, 10240, options.recov_outputdir)
        recoveredKeys = list(set(recoveredKeys))
        # 		print(recoveredKeys[0:5])

        db_env = create_env(options.recov_outputdir)
        recov_wallet_name = "recovered_wallet_%s.dat" % ts()

        create_new_wallet(db_env, recov_wallet_name, 32500)

        if (
            passphraseRecov
            != "I don't want to put a password on the recovered wallet and I know what can be the consequences."
        ):
            db = open_wallet(db_env, recov_wallet_name, True)

            NPP_salt = os.urandom(8)
            NPP_rounds = int(50000 + random.random() * 20000)
            NPP_method = 0
            NPP_MK = os.urandom(32)
            crypter.SetKeyFromPassphrase(passphraseRecov, NPP_salt, NPP_rounds, NPP_method)
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

        read_wallet(json_db, db_env, recov_wallet_name, True, True, "", False)

        db = open_wallet(db_env, recov_wallet_name, True)

        print("\n\nImporting:")
        for i, sec in enumerate(recoveredKeys):
            sec = binascii.hexlify(sec)
            print("Importing key %4d/%d" % (i + 1, len(recoveredKeys)))
            importprivkey(db, sec, "recovered: %s" % sec, None, False)
            importprivkey(db, sec + "01", "recovered: %s" % sec, None, False)
        db.close()

        print(
            "\n\nThe new wallet %s/%s contains the %d recovered key%s"
            % (
                options.recov_outputdir,
                recov_wallet_name,
                len(recoveredKeys),
                plural(len(recoveredKeys)),
            )
        )

        exit(0)

    if not (options.dcv is None):
        max_version = 10**9

    if not (options.datadir is None):
        print("Depreacation")
        print(
            "  The --datadir option has been deprecated, now the full path of the wallet file should go to --wallet"
        )
        print(
            "  If you're not sure what to do, concatenating the old --datadir content, then a directory separator, then the old --wallet should do the trick"
        )
        print(
            "  If not, ask for help in the Pywallet thread: https://bitcointalk.org/index.php?topic=34028"
        )

    db_dir = ""
    if options.walletfile:
        if options.datadir:
            options.walletfile = options.datadir + os.path.sep + options.walletfile
        if not os.path.isfile(options.walletfile):
            print(
                "ERROR: wallet file %s can't be found" % repr(os.path.realpath(options.walletfile))
            )
            exit()
        db_dir, wallet_name = os.path.split(os.path.realpath(options.walletfile))

    if not (options.key_balance is None):
        print(balance(balance_site, options.key_balance))
        exit(0)

    network = network_bitcoin
    if not (options.otherversion is None):
        try:
            network = find_network(options.otherversion)
            if not network:
                network = Network("Unknown network", int(options.otherversion), None, None, None)
                print("Some network info is missing: please use the complete network format")
        except:
            network_info = options.otherversion.split(",")
            parse_int = lambda x: int(x, 16) if x.startswith("0x") else int(x)
            network = Network(
                network_info[0],
                parse_int(network_info[1]),
                parse_int(network_info[2]),
                parse_int(network_info[3]),
                network_info[4],
            )
    if options.namecoin:
        network = Network("Namecoin", 52, 13, 180, "nc")
    elif options.testnet:
        db_dir += "/testnet3"
        network = network_bitcoin_testnet3
    elif options.ethereum:
        network = network_ethereum

    if not (options.keyinfo is None) or options.random_key:
        if not options.keyinfo:
            options.key = binascii.hexlify(os.urandom(32))
        keyinfo(options.key, network, True, False)
        print("")
        keyinfo(options.key, network, True, True)
        exit(0)

    if not db_dir:
        print("A mandatory option is missing\n")
        parser.print_help()
        exit()
    db_env = create_env(db_dir)

    if not (options.multidelete is None):
        filename = options.multidelete
        filin = open(filename, "r")
        content = filin.read().split("\n")
        filin.close()
        typedel = content[0]
        kd = filter(bool, content[1:])
        try:
            r = delete_from_wallet(db_env, wallet_name, typedel, kd)
            print("%d element%s deleted" % (r, "s" * (int(r > 1))))
        except:
            print("Error: do not try to delete a non-existing transaction.")
            exit(1)
        exit(0)

    if options.minimal_encrypted_copy:
        db = open_wallet(db_env, wallet_name)
        minimal_wallet = wallet_name + ".minimal_for_decrypting.dat"
        assert not os.path.exists(
            os.path.join(db_dir, minimal_wallet)
        ), "There is already a minimal encrypted copy at %s/%s, exiting" % (
            db_dir,
            minimal_wallet,
        )
        kds = BCDataStream()
        vds = BCDataStream()
        encrypted_keys = []
        mkey = None
        for key, value in db.items():
            d = Bdict({})
            kds.clear()
            kds.write(key)
            vds.clear()
            vds.write(value)
            typ = kds.read_string()
            if typ == b"mkey":
                mkey = (key, value)
            if typ != b"ckey":
                continue
            d["public_key"] = kds.read_bytes(kds.read_compact_size())
            d["__key__"] = key
            d["__value__"] = value
            encrypted_keys.append(d)
        db.close()
        print(
            """
	Before creating a safe partial wallet you need to check the balance of the following addresses.
	You may check the balance on your wallet or using an online block explorer.
	Just hit Enter if the address is empty and write 'no' if not empty.

			"""
        )
        for pbk in encrypted_keys[::-1]:
            p2pkh, p2wpkh, witaddr, _ = pubkey_info(pbk["public_key"], network)
            for addr in [p2pkh, p2wpkh, witaddr]:
                has_balance = input(addr + ": ") != ""
                if has_balance:
                    print("")
                    break
            if not has_balance:
                if (
                    input(
                        "\nAre you REALLY sure the 3 addresses above have an empty balance? (type 'YES') "
                    )
                    == "YES"
                ):
                    output_db = open_wallet(db_env, minimal_wallet, True)
                    output_db.put(*mkey)
                    output_db.put(pbk["__key__"], pbk["__value__"])
                    output_db.close()
                    print("\nMinimal wallet written at %s" % minimal_wallet)
                    exit()
                else:
                    print(
                        "\nYou need to input zero character only when the balance is empty, exiting"
                    )
                    exit()
        print(
            "\nError: all your addresses seem to be used, pywallet can't create a safe minimal wallet to share"
        )
        exit()

    read_wallet(json_db, db_env, wallet_name, True, True, "", not (options.dumpbalance is None))

    if json_db.get("minversion", 99999999) > max_version:
        print("Version mismatch (must be <= %d)" % max_version)
        # exit(1)

    if options.find_address:
        addr_data = filter(
            lambda x: x["addr"] == options.find_address,
            json_db["keys"] + json_db["pool"],
        )
        print(json.dumps(list(addr_data), sort_keys=True, indent=4))
        exit()

    if options.dump:
        if options.dumpformat == "addr":
            addrs = list(map(lambda x: x["addr"], json_db["keys"] + json_db["pool"]))
            json_db = addrs
        wallet = json.dumps(json_db, sort_keys=True, indent=4)
        print(wallet)
        exit()
    elif options.key:
        if json_db["version"] > max_version:
            print("Version mismatch (must be <= %d)" % max_version)
        elif options.key in private_keys or options.key in private_hex_keys:
            print("Already exists")
        else:
            db = open_wallet(db_env, wallet_name, writable=True)

            if importprivkey(db, options.key, options.label, options.reserve):
                print("Imported successfully")
            else:
                print("Bad private key")

            db.close()
        exit()


if __name__ == "__main__":
    main()
