from collections import namedtuple

# from types import MethodType
import binascii

from pywallet.conversions import bytes_to_str
from pywallet.keccak256 import Keccak256

# from pywallet.addresses import public_key_to_bc_address

aversions = {}
for i in range(256):
    aversions[i] = "version %d" % i
aversions[0] = "Bitcoin"
aversions[48] = "Litecoin"
aversions[52] = "Namecoin"
aversions[111] = "Testnet"


def eip55(hex_addr):
    if hex_addr[:2] == "0x":
        hex_addr = hex_addr[2:]
    hex_addr = hex_addr.lower()
    checksummed_buffer = ""
    hashed_address = bytes_to_str(binascii.hexlify(Keccak256(hex_addr).digest()))
    for nibble_index, character in enumerate(hex_addr):
        if character in "0123456789":
            checksummed_buffer += character
        elif character in "abcdef":
            hashed_address_nibble = int(hashed_address[nibble_index], 16)
            if hashed_address_nibble > 7:
                checksummed_buffer += character.upper()
            else:
                checksummed_buffer += character
        else:
            raise ValueError(
                "Unrecognized hex character {} at position {}".format(character, nibble_index)
            )
    return "0x" + checksummed_buffer


class Network(namedtuple("Network", "name p2pkh_prefix p2sh_prefix wif_prefix segwit_hrp")):
    instances = []

    def __init__(self, *a, **kw):
        self.__class__.instances.append(self)
        super(Network, self).__init__()

    def keyinfo(self, *a, **kw):
        pass


# def ethereum_keyinfo(self, keyinfo, print_info=True):
#     ethpubkey = keyinfo.uncompressed_public_key[1:]
#     eth_hash = binascii.hexlify(Keccak256(ethpubkey).digest())[-40:]
#     eth_addr = "0x" + bytes_to_str(eth_hash)
#     if print_info and not keyinfo.compressed:
#         print("Ethereum address:    %s" % eip55(eth_addr))
#         print("Ethereum B58address: %s" % public_key_to_bc_address(eth_hash, 33))
#     return namedtuple("SubKeyInfo", "addr")(eth_addr)


def find_network(name):
    for n in Network.instances:
        if n.name.lower() == name.lower():
            return n
    return None


network_bitcoin = Network("Bitcoin", 0, 5, 0x80, "bc")
network_bitcoin_testnet3 = Network("Bitcoin-Testnet3", 0x6F, 0xC4, 0xEF, "tb")
# network_ethereum = Network("Ethereum", 0, 5, 0x80, "eth")
# network_ethereum.keyinfo = MethodType(ethereum_keyinfo, network_ethereum)

DEFAULT_NETWORK = network_bitcoin
