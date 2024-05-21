import subprocess
import binascii
import os
import hashlib
import urllib


def whitepaper():
    try:
        rawtx = subprocess.check_output(
            [
                "bitcoin-cli",
                "getrawtransaction",
                "54e48e5f5c656b26c3bca14a8c95aa583d07ebe84dde3b7dd4a78f4e4186e713",
            ]
        )
    except:
        rawtx = urllib.urlopen(
            "https://blockchain.info/tx/54e48e5f5c656b26c3bca14a8c95aa583d07ebe84dde3b7dd4a78f4e4186e713?format=hex"
        ).read()
    outputs = rawtx.split("0100000000000000")
    pdf = b""
    for output in outputs[1:-2]:
        i = 6
        pdf += binascii.unhexlify(output[i : i + 130])
        i += 132
        pdf += binascii.unhexlify(output[i : i + 130])
        i += 132
        pdf += binascii.unhexlify(output[i : i + 130])
    pdf += binascii.unhexlify(outputs[-2][6:-4])
    content = pdf[8:-8]
    assert (
        hashlib.sha256(content).hexdigest()
        == "b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553"
    )
    filename = "bitcoin_whitepaper"
    while os.path.exists(filename + ".pdf"):
        filename += "_"
    with open(filename + ".pdf", "wb") as f:
        f.write(content)
    print("Wrote the Bitcoin whitepaper to %s.pdf" % filename)
