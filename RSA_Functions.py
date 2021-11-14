"""
    This function returns GCD(a, b), x, y such that ax + by = GCD
"""
def extended_euclidean_algorithm(a, b):
    prev_r, cur_r = a, b
    prev_s, cur_s = 1, 0
    prev_t, cur_t = 0, 1
    if a < b:
        prev_r, cur_r = b, a
        prev_s, cur_s = 0, 1
        prev_t, cur_t = 1, 0

    while cur_r != 0:
        q = prev_r // cur_r
        prev_r, cur_r = cur_r, prev_r - q * cur_r
        prev_s, cur_s = cur_s, prev_s - q * cur_s
        prev_t, cur_t = cur_t, prev_t - q * cur_t

        # print(q, prev_r, cur_r, prev_s, cur_s, prev_t, cur_t)
        # input()
    
    return prev_r, prev_s, prev_t

"""
    Given a and m, this function finds b such that ab % m = 1
"""
def find_mul_inverse(a, m):
    gcd, x, y = extended_euclidean_algorithm(a, m)
    if gcd != 1:
        raise ValueError("{} has no multiplicative inverse module {}".format(a, m))
    else:
        return x % m

"""
    Ask for input p and q, then compute n and phi(n)
"""
def input_n():
    p = int(input("Input p here: "))
    q = int(input("Input q here: "))

    n = p * q
    phi_n = (p - 1) * (q - 1) / extended_euclidean_algorithm(p-1, q-1)[0]

    return n, phi_n

"""
    Ask for input exponent e, check if GCD(e, phi_n) == 1, if yes - reinput e.
"""
def input_e(phi_n):
    e = int(input("Input e here: "))

    while extended_euclidean_algorithm(e, phi_n)[0] != 1:
        e = input("e and n are not coprimes. Please reinput e: ")

    return e
