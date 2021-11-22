from typing import List
import utils;
from utils import Interval
from Cryptodome.PublicKey import RSA
from Cryptodome.Util.number import bytes_to_long, long_to_bytes

from PKCS1 import PKCS1;

# use only one cipher
noOfBits = 1024
rsa_key = RSA.generate(noOfBits)
cipher = PKCS1.new(rsa_key)
B = int(pow(2, noOfBits-8*2))
mLowThresh = 2*B
mHighThresh = 3*B - 1
n = rsa_key.n
e = rsa_key.e
queries = 0

def canDecryptWithS(cipherInt: int, s: int):
  global queries
  queries += 1
  if (queries % 500 ==0):
    print("Oracle query {q}; \n s is {s}".format(q=queries, s=s))
  newCipherInt: int = cipherInt*pow(s, e, n) % n
  try:
    cipherBytes = long_to_bytes(newCipherInt)
    paddedMessBytes = cipher.decrypt(cipherBytes)
    cipher.decode(paddedMessBytes)
    return True
  except Exception:
    return False

def searchSmallestS(cipherTextInt: int, lowerBound: int):
  s = lowerBound
  while True:
    if canDecryptWithS(cipherTextInt, s):
      return s
    s += 1

def searchSOneInterval(interval: Interval, cipherTextInt: int, prevS: int):
  high = interval.high
  low = interval.low
  curR = utils.ceil(2 * (high * prevS - mLowThresh), n)

  while True:
    lowS = utils.ceil( (mLowThresh + curR*n), high)
    highS = utils.ceil( (3*B + curR*n ), low)
    for s in range(lowS, highS):
      if canDecryptWithS(cipherTextInt, s):
        return s
    curR += 1

def searchS(intervals: List[Interval],  cipherTextInt: int, prevS: int):
  if len(intervals) > 1:
    return searchSmallestS(cipherTextInt, prevS + 1)
  elif len(intervals) == 1:
    return searchSOneInterval(intervals[0], cipherTextInt, prevS)
  else:
    return None

def narrowIntervals(prevIntervals: List[Interval], s: int):
  retIntervals: List[Interval] = []
  for prevInterval in prevIntervals:
    lowR = utils.ceil((prevInterval.low * s - mHighThresh), n)
    highR = utils.floor((prevInterval.high * s - mLowThresh), n)
    for r in range(lowR, highR + 1):
      lowM = utils.ceil( (mLowThresh + r*n),  s)
      highM = utils.floor( (mHighThresh + r*n), s)
      maxLowM = max(prevInterval.low, lowM)
      minHighM = min(prevInterval.high, highM)
      retIntervals.append(Interval(maxLowM, minHighM))
  return utils.mergeIntervals(retIntervals)

def checkIntervals(intervals: List[Interval]) -> bool:
  if (len(intervals) == 1):
    if (intervals[0].low == intervals[0].high):
      return True
  return False

def handleMessageInt(initpaddedMsgBytes: bytes, messageInt: int):
  messageBytes: bytes = long_to_bytes(messageInt, noOfBits//8)
  decodeMesBytes =  cipher.decode(messageBytes)
  print("Find messageBytes", messageBytes.hex(':'))
  print("Init message Bytes", initpaddedMsgBytes.hex(':'))
  print("Found message", decodeMesBytes.decode())

def attack():
  message = utils.getInputMessage()
  messageBytes = message.encode()
  paddedMsgBytes = cipher.encode(messageBytes)

  cipherTextBytes = cipher.encrypt(paddedMsgBytes)
  cipherTextInt = bytes_to_long(cipherTextBytes)

  intervals: List[Interval] = [Interval(mLowThresh, mHighThresh)]

  s = searchSmallestS(cipherTextInt, utils.ceil(n, 3*B ))
  sIndex = 2

  while True:
    s = searchS(intervals, cipherTextInt, s)
    if (s is None):
      print("Search S error")
      break
    else:
      print("\ns{i}: {s}".format(i=sIndex, s=s))
    intervals = narrowIntervals(intervals, s)
    if (checkIntervals(intervals)):
      handleMessageInt(paddedMsgBytes, intervals[0].low)
      break
    sIndex+=1





