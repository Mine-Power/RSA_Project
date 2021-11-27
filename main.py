import attacks
from attackStatistics import AttackStatistics
import attacksParallel

def main():
    # rsa_attack = attacks.RSA_Attack(512, True)
    # rsa_attack.perform_attack()
    attacksParallel.perform_attack()
    # atkStat = AttackStatistics()
    # atkStat.oracleQueryStatistic(50, 512)

if __name__ == "__main__":
    main()