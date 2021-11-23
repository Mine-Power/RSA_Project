from Crypto.PublicKey import RSA
from Crypto.Random import random
from Crypto.Util.number import bytes_to_long, long_to_bytes


def removePadding(paddedMsgBytes: bytes):
    idSecondZero = paddedMsgBytes.index(b"\00", 1)
    if paddedMsgBytes[0:2] != b"\x00\x02":
        raise Exception("The padded message bytes are not valid!")
    else:
        return paddedMsgBytes[idSecondZero+1:]


class PKCS1:
    def __init__(self, rsaKey: RSA.RsaKey) -> None:
        self.rsaKey = rsaKey

    def new(key: RSA.RsaKey):
        return PKCS1(key)

    def encode(self, msgBytes: bytes):
        rsaKey = self.rsaKey
        msgLength = len(msgBytes)
        totalBytes = rsaKey.size_in_bytes()
        if msgLength > totalBytes - 11:
            raise Exception("The message is too large for encoding!")
        padLength = totalBytes - msgLength - 3
        padding = bytes(random.sample(range(1, 256), padLength))
        paddedMsgBytes = b"\x00\x02" + padding + b"\x00" + msgBytes
        return paddedMsgBytes

    def decode(self, paddedMsgBytes):
        return removePadding(paddedMsgBytes)

    def encrypt(self, paddedMsgBytes: bytes):
        rsaKey = self.rsaKey
        n = rsaKey.n
        e = rsaKey.e
        totalBytes = rsaKey.size_in_bytes()
        paddedMsgInt = bytes_to_long(paddedMsgBytes)
        cipherInt = pow(paddedMsgInt, e, n)
        return long_to_bytes(cipherInt, totalBytes)

    def decrypt(self, cipherBytes: bytes):
        rsaKey = self.rsaKey
        d = rsaKey.d
        n = rsaKey.n
        cipherInt = bytes_to_long(cipherBytes)
        paddedMsgInt = pow(cipherInt, d, n)
        return long_to_bytes(paddedMsgInt, rsaKey.size_in_bytes())
