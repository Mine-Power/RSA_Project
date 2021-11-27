from Crypto.Random import random
from attacksParallel import attack
import time
import math
import seaborn as sns
import numpy as np
import matplotlib.pyplot as plt


class AttackStatistics:
    def calBins(self, npArray):
        q25, q75 = np.percentile(npArray, [25, 75])
        bin_width = 2 * (q75 - q25) * len(npArray) ** (-1 / 3)
        bins = round((npArray.max() - npArray.min()) / bin_width)
        print("Freedman–Diaconis number of bins:", bins)
        return bins

    def oracleQueryStatistic(self, iteration: int, noOfBits):
        if noOfBits % 8 != 0:
            print("The number of bits must be divisible by 8")
            return
        queriesCount = []
        timeCount = []
        noOfBytes = noOfBits // 8
        messLength = random.randint(1, noOfBytes - 11)
        randomMesBytes = bytes(random.sample(range(1, 256), messLength))
        for i in range(0, iteration):
            messLength = random.randint(1, noOfBytes - 11)
            randomMesBytes = bytes(random.sample(range(1, 256), messLength))
            print("Starting {i} attack".format(i=i + 1))
            start = time.time()
            queriesCount.append(attack(randomMesBytes))
            end = time.time()
            atkTime = end - start
            timeCount.append(atkTime)
            print(
                "check cur count: {c}, elapsed time{t}".format(
                    c=queriesCount, t=atkTime
                )
            )
        logQueries = np.array(
            [math.log2(queriesCount[i]) for i in range(0, len(queriesCount))]
        )
        bins = self.calBins(logQueries)
        sns.displot(logQueries, bins=bins, kde=True)
        plt.show()
