import unittest
import warnings
import binascii

from pywallet.networks import network_bitcoin
from pywallet.bip39 import Xpriv, keyinfo


class TestPywallet(unittest.TestCase):
    def setUp(self):
        super(TestPywallet, self).setUp()
        warnings.simplefilter("ignore")

    def test_btc_privkey_1(self):
        key = keyinfo("1", network=network_bitcoin, force_compressed=False)
        self.assertEqual(key.addr, "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm")
        self.assertEqual(key.wif, "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf")
        self.assertEqual(key.secret, b"\x00" * 31 + b"\x01")
        self.assertFalse(key.compressed)

    def test_btc_privkey_1_from_wif(self):
        key = keyinfo(
            "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf",
            network=network_bitcoin,
            force_compressed=False,
        )
        self.assertEqual(key.addr, "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm")

    def test_bad_privkey_format(self):
        with self.assertRaises(Exception):
            keyinfo("g", network=network_bitcoin)

    def test_btc_bip32_test_vectors(self):
        self.assertEqual(
            Xpriv.from_seed(binascii.unhexlify("000102030405060708090a0b0c0d0e0f"))
            .ckd_xpriv(0x80000000, 1, -2, 2, 1000000000)
            .xpub(),
            "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
        )
        self.assertEqual(
            Xpriv.from_seed(
                binascii.unhexlify(
                    "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
                )
            )
            .ckd_xpriv(0, -2147483647, 1, -2147483646, 2)
            .xpub(),
            "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
        )
        self.assertEqual(
            Xpriv.from_seed(
                binascii.unhexlify(
                    "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be"
                )
            )
            .ckd_xpriv(0x80000000)
            .xpub(),
            "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y",
        )

    def test_btc_bip32_2(self):
        xpriv = "xprv9s21ZrQH143K2gCVXRarFj5npbgjtJ7MuNb15AoRYJ92ZMA1hcnoqpxJKfcsiMHP6cNmDKHCTphsC6uzzyzr2MwjXbDxg6U9ivvEupavYUb"
        paths = "m/7-8'/3/99'/38-39"
        keys = Xpriv.b58decode(xpriv).multi_ckd_xpriv(paths)
        for k, privkey in zip(
            keys,
            [
                "5ca736abd3b19632d11366c4dd79c227236500879980c6a1fc4e7c1e33933350",
                "8c793bce5319bf04349b5e4d21d091a98c1a1ad632bffc0425a5f4802c999a76",
                "692f2ddb1d5c7213d194643984642df6e9a5c8cd14a1a6b4054571955fcab05f",
                "8739db9026ceb50d7774ef145bd27e899228700f1096072fe9d26f8387378314",
            ],
        ):
            self.assertEqual(k.key, binascii.unhexlify(privkey))

    def test_btc_bip39_test_vectors(self):
        self.assertEqual(
            Xpriv.from_mnemomic(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                "TREZOR",
            ).b58encode(),
            "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF",
        )
        self.assertEqual(
            Xpriv.from_mnemomic(
                "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
                "TREZOR",
            ).b58encode(),
            "xprv9s21ZrQH143K39rnQJknpH1WEPFJrzmAqqasiDcVrNuk926oizzJDDQkdiTvNPr2FYDYzWgiMiC63YmfPAa2oPyNB23r2g7d1yiK6WpqaQS",
        )

    def test_btc_key_recovery(self):
        pass
