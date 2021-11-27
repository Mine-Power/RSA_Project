import multiprocessing
from typing import List
import utils
from utils import Interval
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.Util.number import bytes_to_long, long_to_bytes
from multiprocessing import Pool
from PKCS1 import PKCS1

# Use only one cipher


noOfBits = 512
B = int(pow(2, noOfBits - 8 * 2))
mLowThresh = 2 * B
mHighThresh = 3 * B - 1
queries = 0
curQuerysDiv = 0
sIndex = 2
printOracleQuery = True
useCipherInt = None

rsa_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=noOfBits,
)
cipher = PKCS1.new(rsa_key)
n = rsa_key.public_key().public_numbers().n
e = rsa_key.public_key().public_numbers().e
printOracleQuery = printOracleQuery

cpuNum = multiprocessing.cpu_count() // 2
print("check cpu", cpuNum)

parrallelBatchSize = 128


def canDecryptWithSOneParams(s: int):
    newCipherInt: int = useCipherInt * pow(s, e, n) % n
    try:
        cipherBytes = long_to_bytes(newCipherInt)
        paddedMessBytes = cipher.decrypt(cipherBytes)
        cipher.decode(paddedMessBytes)
        return True
    except Exception:
        return False


def searchSmallestS(cipherTextInt: int, lowerBound: int):
    global queries
    global useCipherInt
    useCipherInt = cipherTextInt
    s = lowerBound
    index = 0
    pool = Pool(cpuNum)
    while True:
        argArr = [
            s + (i + parrallelBatchSize * index) for i in range(0, parrallelBatchSize)
        ]
        checkArr = pool.map(canDecryptWithSOneParams, argArr)
        for i in range(0, parrallelBatchSize):
            if checkArr[i] == True:
                queries += i
                return s + (i + parrallelBatchSize * index)
        queries += parrallelBatchSize
        index += 1


def searchSOneInterval(interval: Interval, cipherTextInt: int, prevS: int):
    global queries
    high = interval.high
    low = interval.low
    curR = utils.ceil(2 * (high * prevS - mLowThresh), n)
    prevHighS = -1
    global useCipherInt
    useCipherInt = cipherTextInt
    while True:
        lowS = utils.ceil(mLowThresh + curR * n, high)
        highS = utils.ceil(mHighThresh + 1 + curR * n, low)
        if prevHighS > lowS:
            lowS = prevHighS + 1
        pool = Pool(cpuNum)
        for baseS in range(lowS, highS, parrallelBatchSize):
            argArr = [baseS + (i) for i in range(0, parrallelBatchSize)]
            if baseS + parrallelBatchSize > highS:
                argArr = [baseS + (i) for i in range(0, highS - baseS)]
            checkArr = pool.map(canDecryptWithSOneParams, argArr)
            for i in range(0, len(argArr)):
                if checkArr[i] == True:
                    queries += i
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
        lowR = utils.ceil(prevInterval.low * s - mHighThresh, n)
        highR = utils.floor(prevInterval.high * s - mLowThresh, n)
        for r in range(lowR, highR + 1):
            lowM = utils.ceil(mLowThresh + r * n, s)
            highM = utils.floor(mHighThresh + r * n, s)
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
    messageBytes: bytes = long_to_bytes(messageInt, noOfBits // 8)
    decodeMesBytes = cipher.decode(messageBytes)
    print("Find messageBytes", messageBytes.hex(":"))
    print("Init message Bytes", initpaddedMsgBytes.hex(":"))
    try:
        print("Found message", decodeMesBytes.decode())
    except Exception:
        print("Exception when decode")


def attack(messageBytes: bytes):
    global queries
    global sIndex
    queries = 0
    sIndex = 2
    paddedMsgBytes = cipher.encode(messageBytes)

    cipherTextBytes = cipher.encrypt(paddedMsgBytes)
    cipherTextInt = bytes_to_long(cipherTextBytes)

    intervals: List[Interval] = [Interval(mLowThresh, mHighThresh)]

    s = searchSmallestS(cipherTextInt, utils.ceil(n, mHighThresh + 1))

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
    return queries


def perform_attack():
    message = utils.getInputMessage()
    attack(message.encode())
