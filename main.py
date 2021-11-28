import attacks
from attackStatistics import AttackStatistics
import attacksParallel
import time


def main():
    print(
        "Enter your options to\
        \n1 Perform an normal attack\
        \n2 Perform a parallel attack\
        \n3 Generate statistic information by performing multiple attacks\
    "
    )
    userOptions = int(input("Please enter your option: \n"))
    noOfBits = int(
        input(
            "Please enter the number of bits for n (512 or 1024 or 2048): \n"
        )
    )
    try:
        if userOptions == 1:
            rsa_attack = attacks.RSA_Attack(noOfBits, True)
            time = rsa_attack.perform_attack()[1]
            print("Attack time: {t}".format(t=time))
        elif userOptions == 2:
            attacksParallel.init(noOfBits)
            time = attacksParallel.perform_attack()[1]
            print("Attack time: {t}".format(t=time))
        elif userOptions == 3:
            noOfIterations = int(
                input("Please enter the number of iterations you want to run: \n")
            )
            atkStat = AttackStatistics()
            atkStat.oracleQueryStatistic(noOfIterations, noOfBits)
        else:
            print("Unexpected input")
    except Exception:
        print("There is an exception")


if __name__ == "__main__":
    main()
