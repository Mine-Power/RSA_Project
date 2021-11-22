from typing import List

# math.ceil and math.floor don't work for large integers
def floor(a, b):
    return a // b

def ceil(a, b):
    return a // b + (a % b > 0)


def getInputMessage():
  return (input("Input your message: "))

def convertBytesToInt(bytesInput: bytes):
  return int.from_bytes(bytesInput)

class Interval:
  def __init__(self, low, high):
    if (low <= high):
      self.low = low
      self.high = high
    else:
      print("Low higher than high: [{l} - {h}]".format(l=low, h=high))
      raise ValueError("Low should cannot be higher then hihg")
  def __repr__(self):
    return "[{l} - {h}]".format(l=self.low, h=self.high)
  def __str__(self) -> str:
    return "[{l} - {h}]".format(l=self.low, h=self.high)

def mergeIntervals(intervals: List[Interval]) -> List[Interval]:
  intervals.sort(key=lambda x: x.low)
  merged: List[Interval] = []
  for interval in intervals:
      # if the list of merged intervals is empty or if the current
      # interval does not overlap with the previous, simply append it.
      if not merged or merged[-1].high < interval.low:
          merged.append(interval)
      else:
      # otherwise, there is overlap, so we merge the current and previous
      # intervals.
        newHigh = max(merged[-1].high, interval.high)
        merged[-1] = Interval(merged[-1].low, newHigh)

  return merged