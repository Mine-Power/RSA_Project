from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.Random import random
from Crypto.Util.number import bytes_to_long, long_to_bytes
from utils import inversePrimeMod


def removePadding(paddedMsgBytes: bytes):
    idSecondZero = paddedMsgBytes.index(b"\00", 1)
    if paddedMsgBytes[0:2] != b"\x00\x02":
        raise Exception("The padded message bytes are not valid!")
    else:
        return paddedMsgBytes[idSecondZero + 1 :]


class PKCS1:
    def __init__(self, rsaKey: rsa.RSAPrivateKey) -> None:
        self.rsaKey = rsaKey
        self.n = rsaKey.public_key().public_numbers().n
        self.p = rsaKey.private_numbers().p
        self.q = rsaKey.private_numbers().q
        self.e = rsaKey.public_key().public_numbers().e
        self.d = rsaKey.private_numbers().d
        self.u = inversePrimeMod(self.p, self.q)

    def new(key: rsa.RSAPrivateKey):
        return PKCS1(key)

    def encode(self, msgBytes: bytes):
        rsaKey = self.rsaKey
        msgLength = len(msgBytes)
        totalBytes = rsaKey.key_size // 8
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
        totalBytes = rsaKey.key_size // 8
        paddedMsgInt = bytes_to_long(paddedMsgBytes)
        cipherInt = pow(paddedMsgInt, self.e, self.n)
        return long_to_bytes(cipherInt, totalBytes)

    def decrypt(self, cipherBytes: bytes):
        rsaKey = self.rsaKey
        cipherInt = bytes_to_long(cipherBytes)

        dp = self.d % (self.p - 1)
        dq = self.d % (self.q - 1)
        m1 = pow(cipherInt, dp, self.p)
        m2 = pow(cipherInt, dq, self.q)
        h = ((m2 - m1) * self.u) % self.q
        paddedMsgInt = h * self.p + m1
        return long_to_bytes(paddedMsgInt, rsaKey.key_size // 8)
