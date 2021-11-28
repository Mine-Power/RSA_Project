import multiprocessing
from typing import List
import utils
from utils import Interval
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.Util.number import bytes_to_long, long_to_bytes
from multiprocessing import Pool
from PKCS1 import PKCS1
import time

queries = 0
curQuerysDiv = 0
sIndex = 1
useCipherInt = None


class AttackObj:
    def __init__(self, noOfBits: int):
        self.noOfBits = 512
        self.B = int(pow(2, noOfBits - 8 * 2))
        self.mLowThresh = 2 * self.B
        self.mHighThresh = 3 * self.B - 1
        self.rsa_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=noOfBits,
        )
        self.cipher = PKCS1.new(self.rsa_key)
        self.n = self.rsa_key.public_key().public_numbers().n
        self.e = self.rsa_key.public_key().public_numbers().e
        self.cpuNum = multiprocessing.cpu_count() // 2
        self.parrallelBatchSize = 128
        self.oneIntervalBatchSize = 128


attackObj = AttackObj(512)


def init(noOfBits: int):
    global attackObj
    attackObj = AttackObj(noOfBits)


def canDecryptWithSOneParams(s: int):
    newCipherInt: int = useCipherInt * pow(s, attackObj.e, attackObj.n) % attackObj.n
    try:
        cipherBytes = long_to_bytes(newCipherInt)
        paddedMessBytes = attackObj.cipher.decrypt(cipherBytes)
        attackObj.cipher.decode(paddedMessBytes)
        return True
    except Exception:
        return False


def searchSmallestS(cipherTextInt: int, lowerBound: int):
    global queries
    global useCipherInt
    parrallelBatchSize = attackObj.parrallelBatchSize
    useCipherInt = cipherTextInt
    s = lowerBound
    index = 0
    pool = Pool(attackObj.cpuNum)
    while True:
        argArr = [
            s + (i + parrallelBatchSize * index) for i in range(0, parrallelBatchSize)
        ]
        checkArr = pool.map(canDecryptWithSOneParams, argArr)
        for i in range(0, parrallelBatchSize):
            if checkArr[i] == True:
                queries += i + 1
                return s + (i + parrallelBatchSize * index)
        queries += parrallelBatchSize
        index += 1


def searchSOneInterval(interval: Interval, cipherTextInt: int, prevS: int):
    global queries
    high = interval.high
    low = interval.low
    curR = utils.ceil(2 * (high * prevS - attackObj.mLowThresh), attackObj.n)
    prevHighS = -1
    global useCipherInt
    useCipherInt = cipherTextInt
    while True:
        lowS = utils.ceil(attackObj.mLowThresh + curR * attackObj.n, high)
        highS = utils.ceil(attackObj.mHighThresh + 1 + curR * attackObj.n, low)
        if prevHighS > lowS:
            lowS = prevHighS + 1
        pool = Pool(attackObj.cpuNum)
        parrallelBatchSize = attackObj.oneIntervalBatchSize
        for baseS in range(lowS, highS, parrallelBatchSize):
            argArr = [baseS + (i) for i in range(0, parrallelBatchSize)]
            if baseS + parrallelBatchSize > highS:
                argArr = [baseS + (i) for i in range(0, highS - baseS)]
            checkArr = pool.map(canDecryptWithSOneParams, argArr)
            for i in range(0, len(argArr)):
                if checkArr[i] == True:
                    queries += i + 1
                    return baseS + i
            queries += parrallelBatchSize
        curR += 1
        prevHighS = highS


def searchS(intervals: List[Interval], cipherTextInt: int, prevS: int):
    if len(intervals) > 1:
        return searchSmallestS(cipherTextInt, prevS + 1)
    elif len(intervals) == 1:
        return searchSOneInterval(intervals[0], cipherTextInt, prevS)
    else:
        return None


def narrowIntervals(prevIntervals: List[Interval], s: int):
    retIntervals: List[Interval] = []
    for prevInterval in prevIntervals:
        lowR = utils.ceil(prevInterval.low * s - attackObj.mHighThresh, attackObj.n)
        highR = utils.floor(prevInterval.high * s - attackObj.mLowThresh, attackObj.n)
        for r in range(lowR, highR + 1):
            lowM = utils.ceil(attackObj.mLowThresh + r * attackObj.n, s)
            highM = utils.floor(attackObj.mHighThresh + r * attackObj.n, s)
            maxLowM = max(prevInterval.low, lowM)
            minHighM = min(prevInterval.high, highM)
            retIntervals.append(Interval(maxLowM, minHighM))
    if len(retIntervals) == 0:
        print("check prev interval cause 0", prevIntervals)
    return utils.mergeIntervals(retIntervals)


def checkIntervals(intervals: List[Interval]) -> bool:
    if len(intervals) == 1:
        if intervals[0].low == intervals[0].high:
            return True
    return False


def handleMessageInt(initpaddedMsgBytes: bytes, messageInt: int):
    messageBytes: bytes = long_to_bytes(messageInt, attackObj.noOfBits // 8)
    decodeMesBytes = attackObj.cipher.decode(messageBytes)
    print("Find messageBytes", messageBytes.hex(":"))
    print("Init message Bytes", initpaddedMsgBytes.hex(":"))
    try:
        print("Found message", decodeMesBytes.decode())
    except Exception:
        print("Exception when decode")


def attack(messageBytes: bytes):
    startTime = time.time()
    global queries
    global sIndex
    queries = 0
    sIndex = 1
    paddedMsgBytes = attackObj.cipher.encode(messageBytes)

    cipherTextBytes = attackObj.cipher.encrypt(paddedMsgBytes)
    cipherTextInt = bytes_to_long(cipherTextBytes)

    intervals: List[Interval] = [Interval(attackObj.mLowThresh, attackObj.mHighThresh)]

    s = searchSmallestS(
        cipherTextInt, utils.ceil(attackObj.n, attackObj.mHighThresh + 1)
    )
    print("Found s{i}, s is {s}, \ntotal queries {q}".format(i=sIndex, s=s, q=queries))
    sIndex += 1
    while True:
        s = searchS(intervals, cipherTextInt, s)
        if s is None:
            print("Error encountered while searching for S!")
            break
        else:
            print(
                "Found s{i}, s is {s}, \ntotal queries {q}".format(
                    i=sIndex, s=s, q=queries
                )
            )
        intervals = narrowIntervals(intervals, s)
        if checkIntervals(intervals):
            handleMessageInt(paddedMsgBytes, intervals[0].low)
            break
        sIndex += 1
    endTime = time.time()
    return [queries, endTime - startTime]


def perform_attack():
    message = utils.getInputMessage()
    return attack(message.encode())
