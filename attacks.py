from typing import List
import utils
from utils import Interval
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.Util.number import bytes_to_long, long_to_bytes

from PKCS1 import PKCS1

# Use only one cipher

class RSA_Attack():
    noOfBits = 512
    B = int(pow(2, noOfBits - 8 * 2))
    mLowThresh = 2 * B
    mHighThresh = 3 * B - 1
    queries = 0
    sIndex = 2

    def __init__(self):
        self.rsa_key = rsa.generate_private_key(
            public_exponent = 65537,
            key_size = self.noOfBits,
        )
        self.cipher = PKCS1.new(self.rsa_key)
        self.n = self.rsa_key.public_key().public_numbers().n
        self.e = self.rsa_key.public_key().public_numbers().e


    def canDecryptWithS(self, cipherInt: int, s: int):
        self.queries += 1
        if self.queries % 500 == 0:
            print("Oracle query {q}; \nTesting s{i}, value is: {s}".format(q = self.queries, i=self.sIndex, s = s))
        newCipherInt: int = cipherInt * pow(s, self.e, self.n) % self.n
        try:
            cipherBytes = long_to_bytes(newCipherInt)
            paddedMessBytes = self.cipher.decrypt(cipherBytes)
            self.cipher.decode(paddedMessBytes)
            return True
        except Exception:
            return False


    def searchSmallestS(self, cipherTextInt: int, lowerBound: int):
        s = lowerBound
        while True:
            if self.canDecryptWithS(cipherTextInt, s):
                return s
            s += 1


    def searchSOneInterval(self, interval: Interval, cipherTextInt: int, prevS: int):
        high = interval.high
        low = interval.low
        curR = utils.ceil(2 * (high * prevS - self.mLowThresh), self.n)
        prevHighS = -1

        while True:
            lowS = utils.ceil(self.mLowThresh + curR * self.n, high)
            highS = utils.ceil(self.mHighThresh + 1 + curR * self.n, low)
            if (prevHighS > lowS):
              lowS = prevHighS + 1
            for s in range(lowS, highS):
                if self.canDecryptWithS(cipherTextInt, s):
                    return s
            curR += 1
            prevHighS = highS


    def searchS(self, intervals: List[Interval], cipherTextInt: int, prevS: int):
        if len(intervals) > 1:
            return self.searchSmallestS(cipherTextInt, prevS + 1)
        elif len(intervals) == 1:
            return self.searchSOneInterval(intervals[0], cipherTextInt, prevS)
        else:
            return None


    def narrowIntervals(self, prevIntervals: List[Interval], s: int):
        retIntervals: List[Interval] = []
        for prevInterval in prevIntervals:
            lowR = utils.ceil(prevInterval.low * s - self.mHighThresh, self.n)
            highR = utils.floor(prevInterval.high * s - self.mLowThresh, self.n)
            for r in range(lowR, highR + 1):
                lowM = utils.ceil(self.mLowThresh + r * self.n,  s)
                highM = utils.floor(self.mHighThresh + r * self.n, s)
                maxLowM = max(prevInterval.low, lowM)
                minHighM = min(prevInterval.high, highM)
                retIntervals.append(Interval(maxLowM, minHighM))
        return utils.mergeIntervals(retIntervals)


    def checkIntervals(self, intervals: List[Interval]) -> bool:
        if len(intervals) == 1:
            if intervals[0].low == intervals[0].high:
                return True
        return False


    def handleMessageInt(self, initpaddedMsgBytes: bytes, messageInt: int):
        messageBytes: bytes = long_to_bytes(messageInt, self.noOfBits // 8)
        decodeMesBytes = self.cipher.decode(messageBytes)
        print("Find messageBytes", messageBytes.hex(":"))
        print("Init message Bytes", initpaddedMsgBytes.hex(":"))
        print("Found message", decodeMesBytes.decode())


    def perform_attack(self):
        message = utils.getInputMessage()
        messageBytes = message.encode()
        paddedMsgBytes = self.cipher.encode(messageBytes)

        cipherTextBytes = self.cipher.encrypt(paddedMsgBytes)
        cipherTextInt = bytes_to_long(cipherTextBytes)

        intervals: List[Interval] = [Interval(self.mLowThresh, self.mHighThresh)]

        s = self.searchSmallestS(cipherTextInt, utils.ceil(self.n, self.mHighThresh + 1))

        while True:
            s = self.searchS(intervals, cipherTextInt, s)
            if s is None:
                print("Error encountered while searching for S!")
                break
            intervals = self.narrowIntervals(intervals, s)
            if self.checkIntervals(intervals):
                self.handleMessageInt(paddedMsgBytes, intervals[0].low)
                break
            self.sIndex += 1
