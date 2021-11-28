import attacks
from attackStatistics import AttackStatistics
import attacksParallel
import time


def main():
    print(
        "Enter your options to\
        \n1 For perform an normal attacks\
        \n2 Perform a parallel attacks\
        \n3 Generate statistic information by performing multiple attakcs\
    "
    )
    userOptions = int(input("Please enter your options: \n"))
    noOfBits = int(
        input(
            "Please enter the number of bits for modulus n (512 or 1024 or 2048): \n"
        )
    )
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
        isParrallel = input("Do you want to use parrallel attack (Y/N): \n")
        atkStat = AttackStatistics()
        if (isParrallel == "Y"):
            atkStat.oracleQueryStatistic(noOfIterations, noOfBits, True)
        else:
            atkStat.oracleQueryStatistic(noOfIterations, noOfBits, False)
    else:
        print("Unexpected input")


if __name__ == "__main__":
    main()
