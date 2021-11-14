import RSA_Functions as rsa
import math

def main():
    n, phi_n = rsa.input_n()
    e = rsa.input_e(phi_n)
    d = rsa.find_mul_inverse(e, phi_n)
    message = int(input("Input message number: "))
    cipher = (message**e) % n
    print("Cipher text is: " + str(cipher))
    decrypt = (cipher**d) % n
    print("Decrypted message is: " + str(decrypt))


if __name__ == "__main__":
    main()