from Crypto.Random import random
from attacksParallel import attack, init
from attacks import RSA_Attack
import math
import seaborn as sns
import numpy as np
import matplotlib.pyplot as plt


class AttackStatistics:
    def calBins(self, npArray):
        q25, q75 = np.percentile(npArray, [25, 75])
        bin_width = 2 * (q75 - q25) * len(npArray) ** (-1 / 3)
        if bin_width == 0:
            return 1
        bins = round((npArray.max() - npArray.min()) / bin_width)
        return bins

    def oracleQueryStatistic(self, iteration: int, noOfBits: int, isParallel: bool):
        if noOfBits % 8 != 0:
            print("The number of bits must be divisible by 8")
            return
        queriesCount = []
        timeCount = []
        noOfBytes = noOfBits // 8
        messLength = random.randint(1, noOfBytes - 11)
        randomMesBytes = bytes(random.sample(range(1, 256), messLength))
        if (isParallel):
            init(noOfBits)
            attackFunction = attack
        else:
            attackNormal = RSA_Attack(noOfBits, True)
            attackFunction = attackNormal.attack
        init(noOfBits)
        for i in range(0, iteration):
            messLength = random.randint(1, noOfBytes - 11)
            randomMesBytes = bytes(random.sample(range(1, 256), messLength))
            print("Starting #{i} attack".format(i=i + 1))
            [count, atkTime] = attackFunction(randomMesBytes)
            queriesCount.append(count)
            timeCount.append(atkTime)
            print(
                "The attacks end with: {c} queries, elapsed time: {t}".format(
                    c=count, t=atkTime
                )
            )
        logQueries = np.array(
            [math.log2(queriesCount[i]) for i in range(0, len(queriesCount))]
        )
        bins = self.calBins(logQueries)
        sns.displot(logQueries, bins=bins, kde=True).set(title="Queries Count log2")
        plt.show()
