import ctypes
import ctypes.util
import hashlib
import ssl

from Crypto.Cipher import AES  # pycryptodome

from pywallet.conversions import str_to_bytes, ordsix, chrsix
from pywallet.aes import append_PKCS7_padding, AESModeOfOperation

###################################
# pywallet crypter implementation #
###################################


class Crypter_pycrypto(object):
    def SetKeyFromPassphrase(self, vKeyData, vSalt, nDerivIterations, nDerivationMethod):
        if nDerivationMethod != 0:
            return 0
        data = str_to_bytes(vKeyData) + vSalt
        for i in range(nDerivIterations):
            data = hashlib.sha512(data).digest()
        self.SetKey(data[0:32])
        self.SetIV(data[32 : 32 + 16])
        return len(data)

    def SetKey(self, key):
        self.chKey = key

    def SetIV(self, iv):
        self.chIV = iv[0:16]

    def Encrypt(self, data):
        return AES.new(self.chKey, AES.MODE_CBC, self.chIV).encrypt(append_PKCS7_padding(data))

    def Decrypt(self, data):
        return AES.new(self.chKey, AES.MODE_CBC, self.chIV).decrypt(data)[0:32]


class Crypter_ssl(object):
    def __init__(self):
        self.chKey = ctypes.create_string_buffer(32)
        self.chIV = ctypes.create_string_buffer(16)

    def SetKeyFromPassphrase(self, vKeyData, vSalt, nDerivIterations, nDerivationMethod):
        if nDerivationMethod != 0:
            return 0
        strKeyData = ctypes.create_string_buffer(vKeyData)
        chSalt = ctypes.create_string_buffer(vSalt)
        return ssl.EVP_BytesToKey(
            ssl.EVP_aes_256_cbc(),
            ssl.EVP_sha512(),
            chSalt,
            strKeyData,
            len(vKeyData),
            nDerivIterations,
            ctypes.byref(self.chKey),
            ctypes.byref(self.chIV),
        )

    def SetKey(self, key):
        self.chKey = ctypes.create_string_buffer(key)

    def SetIV(self, iv):
        self.chIV = ctypes.create_string_buffer(iv)

    def Encrypt(self, data):
        buf = ctypes.create_string_buffer(len(data) + 16)
        written = ctypes.c_int(0)
        final = ctypes.c_int(0)
        ctx = ssl.EVP_CIPHER_CTX_new()
        ssl.EVP_CIPHER_CTX_init(ctx)
        ssl.EVP_EncryptInit_ex(ctx, ssl.EVP_aes_256_cbc(), None, self.chKey, self.chIV)
        ssl.EVP_EncryptUpdate(ctx, buf, ctypes.byref(written), data, len(data))
        output = buf.raw[: written.value]
        ssl.EVP_EncryptFinal_ex(ctx, buf, ctypes.byref(final))
        output += buf.raw[: final.value]
        return output

    def Decrypt(self, data):
        buf = ctypes.create_string_buffer(len(data) + 16)
        written = ctypes.c_int(0)
        final = ctypes.c_int(0)
        ctx = ssl.EVP_CIPHER_CTX_new()
        ssl.EVP_CIPHER_CTX_init(ctx)
        ssl.EVP_DecryptInit_ex(ctx, ssl.EVP_aes_256_cbc(), None, self.chKey, self.chIV)
        ssl.EVP_DecryptUpdate(ctx, buf, ctypes.byref(written), data, len(data))
        output = buf.raw[: written.value]
        ssl.EVP_DecryptFinal_ex(ctx, buf, ctypes.byref(final))
        output += buf.raw[: final.value]
        return output


class Crypter_pure(object):
    def __init__(self):
        self.m = AESModeOfOperation()
        self.cbc = self.m.modeOfOperation["CBC"]
        self.sz = self.m.aes.keySize["SIZE_256"]

    def SetKeyFromPassphrase(self, vKeyData, vSalt, nDerivIterations, nDerivationMethod):
        if nDerivationMethod != 0:
            return 0
        data = str_to_bytes(vKeyData) + vSalt
        for i in range(nDerivIterations):
            data = hashlib.sha512(data).digest()
        self.SetKey(data[0:32])
        self.SetIV(data[32 : 32 + 16])
        return len(data)

    def SetKey(self, key):
        self.chKey = [ordsix(i) for i in key]

    def SetIV(self, iv):
        self.chIV = [ordsix(i) for i in iv]

    def Encrypt(self, data):
        mode, size, cypher = self.m.encrypt(
            append_PKCS7_padding(data), self.cbc, self.chKey, self.sz, self.chIV
        )
        return b"".join(map(chrsix, cypher))

    def Decrypt(self, data):
        chData = [ordsix(i) for i in data]
        return self.m.decrypt(chData, self.sz, self.cbc, self.chKey, self.sz, self.chIV)


# for now, force use of pycrypto
crypter = Crypter_pycrypto()

# crypter = None
# if crypter is None:
#     try:

#         crypter = Crypter_pycrypto()
#     except:
#         try:
#             import ctypes
#             import ctypes.util

#             ssl = ctypes.cdll.LoadLibrary(ctypes.util.find_library("ssl") or "libeay32")
#             crypter = Crypter_ssl()
#         except:
#             crypter = Crypter_pure()
#             logging.warning("pycrypto or libssl not found, decryption may be slow")


##########################################
# end of pywallet crypter implementation #
##########################################
