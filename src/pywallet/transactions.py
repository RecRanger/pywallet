import json
import urllib
import binascii

# Imports from this project
from pywallet.addresses import Hash
from pywallet.types import Bdict
from pywallet.wallet_dat_handler import sign_message, verify_message_signature


OP_DUP = 118
OP_HASH160 = 169
OP_EQUALVERIFY = 136
OP_CHECKSIG = 172

XOP_DUP = "%02x" % OP_DUP
XOP_HASH160 = "%02x" % OP_HASH160
XOP_EQUALVERIFY = "%02x" % OP_EQUALVERIFY
XOP_CHECKSIG = "%02x" % OP_CHECKSIG


def ct(
    l_prevh,
    l_prevn,
    l_prevsig,
    l_prevpubkey,
    l_value_out,
    l_pubkey_out,
    is_msg_to_sign=-1,
    oldScriptPubkey="",
):
    scriptSig = True
    if is_msg_to_sign != -1:
        scriptSig = False
        index = is_msg_to_sign

    ret = ""
    ret += inverse_str("%08x" % 1)
    nvin = len(l_prevh)
    ret += "%02x" % nvin

    for i in range(nvin):
        txin_ret = ""
        txin_ret2 = ""

        txin_ret += inverse_str(l_prevh[i])
        txin_ret += inverse_str("%08x" % l_prevn[i])

        if scriptSig:
            txin_ret2 += "%02x" % (1 + len(l_prevsig[i]) // 2)
            txin_ret2 += l_prevsig[i]
            txin_ret2 += "01"
            txin_ret2 += "%02x" % (len(l_prevpubkey[i]) // 2)
            txin_ret2 += l_prevpubkey[i]

            txin_ret += "%02x" % (len(txin_ret2) // 2)
            txin_ret += txin_ret2

        elif index == i:
            txin_ret += "%02x" % (len(oldScriptPubkey) // 2)
            txin_ret += oldScriptPubkey
        else:
            txin_ret += "00"

        ret += txin_ret
        ret += "ffffffff"

    nvout = len(l_value_out)
    ret += "%02x" % nvout
    for i in range(nvout):
        txout_ret = ""

        txout_ret += inverse_str("%016x" % (l_value_out[i]))
        txout_ret += "%02x" % (len(l_pubkey_out[i]) // 2 + 5)
        txout_ret += "%02x" % OP_DUP
        txout_ret += "%02x" % OP_HASH160
        txout_ret += "%02x" % (len(l_pubkey_out[i]) // 2)
        txout_ret += l_pubkey_out[i]
        txout_ret += "%02x" % OP_EQUALVERIFY
        txout_ret += "%02x" % OP_CHECKSIG
        ret += txout_ret

    ret += "00000000"
    if not scriptSig:
        ret += "01000000"
    return ret


def create_transaction(
    secret_key,
    hashes_txin,
    indexes_txin,
    pubkey_txin,
    prevScriptPubKey,
    amounts_txout,
    scriptPubkey,
):
    li1 = len(secret_key)
    li2 = len(hashes_txin)
    li3 = len(indexes_txin)
    li4 = len(pubkey_txin)
    li5 = len(prevScriptPubKey)

    if li1 != li2 or li2 != li3 or li3 != li4 or li4 != li5:
        print("Error in the number of tx inputs")
        exit(0)

    lo1 = len(amounts_txout)
    lo2 = len(scriptPubkey)

    if lo1 != lo2:
        print("Error in the number of tx outputs")
        exit(0)

    sig_txin = []
    i = 0
    for cpt in hashes_txin:
        sig_txin.append(
            sign_message(
                binascii.unhexlify(secret_key[i]),
                ct(
                    hashes_txin,
                    indexes_txin,
                    sig_txin,
                    pubkey_txin,
                    amounts_txout,
                    scriptPubkey,
                    i,
                    prevScriptPubKey[i],
                ),
                True,
            )
            + "01"
        )
        i += 1

    tx = ct(hashes_txin, indexes_txin, sig_txin, pubkey_txin, amounts_txout, scriptPubkey)
    hashtx = binascii.hexlify(Hash(binascii.unhexlify(tx)))

    for i in range(len(sig_txin)):
        try:
            verify_message_signature(
                pubkey_txin[i],
                sig_txin[i][:-2],
                ct(
                    hashes_txin,
                    indexes_txin,
                    sig_txin,
                    pubkey_txin,
                    amounts_txout,
                    scriptPubkey,
                    i,
                    prevScriptPubKey[i],
                ),
                True,
            )
            print("sig %2d: verif ok" % i)
        except:
            print("sig %2d: verif error" % i)
            exit(0)

    # 	tx += end_of_wallettx([], int(time.time()))
    # 	return [inverse_str(hashtx), "027478" + hashtx, tx]
    return [inverse_str(hashtx), "", tx]


def inverse_str(string):
    ret = ""
    for i in range(len(string) // 2):
        ret += string[len(string) - 2 - 2 * i]
        ret += string[len(string) - 2 - 2 * i + 1]
    return ret


def read_table(table, beg, end):
    rows = table.split(beg)
    for i in range(len(rows)):
        rows[i] = rows[i].split(end)[0]
    return rows


def read_blockexplorer_table(table):
    cell = []
    rows = read_table(table, "<tr>", "</tr>")
    for i in range(len(rows)):
        cell.append(read_table(rows[i], "<td>", "</td>"))
        del cell[i][0]
    del cell[0]
    del cell[0]
    return cell


txin_amounts = Bdict({})


def bc_address_to_available_tx(address, testnet=False):
    TN = ""
    if testnet:
        TN = "testnet"

    blockexplorer_url = "http://blockexplorer.com/" + TN + "/address/"
    ret = ""
    txin = []
    txin_no = Bdict({})
    global txin_amounts
    txout = []
    balance = 0
    txin_is_used = Bdict({})

    page = urllib.urlopen("%s/%s" % (blockexplorer_url, address))
    try:
        table = page.read().split('<table class="txtable">')[1]
        table = table.split("</table>")[0]
    except:
        return {address: []}

    cell = read_blockexplorer_table(table)

    for i in range(len(cell)):
        txhash = read_table(cell[i][0], "/tx/", "#")[1]
        post_hash = read_table(cell[i][0], "#", '">')[1]
        io = post_hash[0]
        no_tx = post_hash[1:]
        if io in "i":
            txout.append([txhash, post_hash])
        else:
            txin.append(txhash + no_tx)
            txin_no[txhash + no_tx] = post_hash[1:]
            txin_is_used[txhash + no_tx] = 0

        # hashblock = read_table(cell[i][1], '/block/', '">')[1]
        # blocknumber = read_table(cell[i][1], 'Block ', '</a>')[1]

        txin_amounts[txhash + no_tx] = round(float(cell[i][2]), 8)

        # 		if cell[i][3][:4] in 'Sent' and io in 'o':
        # 			print(cell[i][3][:4])
        # 			print(io)
        # 			return 'error'
        # 		if cell[i][3][:4] in 'Rece' and io in 'i':
        # 			print(cell[i][3][:4])
        # 			print(io)
        # 			return 'error'

        balance = round(float(cell[i][5]), 8)

    for tx in txout:
        pagetx = urllib.urlopen("http://blockexplorer.com/" + TN + "/tx/" + tx[0])
        table_in = (
            pagetx.read()
            .split('<a name="outputs">Outputs</a>')[0]
            .split('<table class="txtable">')[1]
            .split("</table>")[0]
        )

        cell = read_blockexplorer_table(table_in)
        for i in range(len(cell)):
            txhash = read_table(cell[i][0], "/tx/", "#")[1]
            no_tx = read_table(cell[i][0], "#", '">')[1][1:]

            if txhash + no_tx in txin:
                txin_is_used[txhash + no_tx] = 1

    ret = []
    for tx in txin:
        if not txin_is_used[tx]:
            ret.append([tx, txin_amounts[tx], txin_no[tx]])

    return {address: ret}


empty_txin = Bdict(
    {"hash": "", "index": "", "sig": "##", "pubkey": "", "oldscript": "", "addr": ""}
)
empty_txout = Bdict({"amount": "", "script": ""})


class tx:
    ins = []
    outs = []
    tosign = False

    def hashtypeone(self, index, script):
        global empty_txin
        for i in range(len(self.ins)):
            self.ins[i] = empty_txin
        self.ins[index]["pubkey"] = ""
        self.ins[index]["oldscript"] = s
        self.tosign = True

    def copy(self):
        r = tx()
        r.ins = self.ins[:]
        r.outs = self.outs[:]
        return r

    def sign(self, n=-1):
        if n == -1:
            for i in range(len(self.ins)):
                self.sign(i)
                return "done"

        global json_db
        txcopy = self.copy()
        txcopy.hashtypeone(i, self.ins[n]["oldscript"])

        sec = ""
        for k in json_db["keys"]:
            if k["addr"] == self.ins[n]["addr"] and "hexsec" in k:
                sec = k["hexsec"]
        if sec == "":
            print("priv key not found (addr:" + self.ins[n]["addr"] + ")")
            return ""

        self.ins[n]["sig"] = sign_message(binascii.unhexlify(sec), txcopy.get_tx(), True)

    def ser(self):
        r = Bdict({})
        r["ins"] = self.ins
        r["outs"] = self.outs
        r["tosign"] = self.tosign
        return json.dumps(r)

    def unser(self, r):
        s = json.loads(r)
        self.ins = s["ins"]
        self.outs = s["outs"]
        self.tosign = s["tosign"]

    def get_tx(self):
        r = ""
        ret += inverse_str("%08x" % 1)
        ret += "%02x" % len(self.ins)

        for i in range(len(self.ins)):
            txin = self.ins[i]
            ret += inverse_str(txin["hash"])
            ret += inverse_str("%08x" % txin["index"])

            if txin["pubkey"] != "":
                tmp += "%02x" % (1 + len(txin["sig"]) // 2)
                tmp += txin["sig"]
                tmp += "01"
                tmp += "%02x" % (len(txin["pubkey"]) // 2)
                tmp += txin["pubkey"]

                ret += "%02x" % (len(tmp) / 2)
                ret += tmp

            elif txin["oldscript"] != "":
                ret += "%02x" % (len(txin["oldscript"]) // 2)
                ret += txin["oldscript"]

            else:
                ret += "00"

            ret += "ffffffff"

        ret += "%02x" % len(self.outs)

        for i in range(len(self.outs)):
            txout = self.outs[i]
            ret += inverse_str("%016x" % (txout["amount"]))

            if txout["script"][:2] == "s:":  # script
                script = txout["script"][:2]
                ret += "%02x" % (len(script) // 2)
                ret += script
            else:  # address
                ret += "%02x" % (len(txout["script"]) // 2 + 5)
                ret += "%02x" % OP_DUP
                ret += "%02x" % OP_HASH160
                ret += "%02x" % (len(txout["script"]) // 2)
                ret += txout["script"]
                ret += "%02x" % OP_EQUALVERIFY
                ret += "%02x" % OP_CHECKSIG

        ret += "00000000"
        if not self.tosign:
            ret += "01000000"
        return ret
