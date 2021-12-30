import hashlib, sys
import random
import math

# primary number generator

def nextPrime(p):
    while p % 4 != 3:
        p = p + 1
    return nextPrime_3(p)


def nextPrime_3(p):
    m_ = 3 * 5 * 7 * 11 * 13 * 17 * 19 * 23 * 29
    while math.gcd(p, m_) != 1:
        p = p + 4
    if (pow(2, p - 1, p) != 1):
        return nextPrime_3(p + 4)
    if (pow(3, p - 1, p) != 1):
        return nextPrime_3(p + 4)
    if (pow(5, p - 1, p) != 1):
        return nextPrime_3(p + 4)
    if (pow(17, p - 1, p) != 1):
        return nextPrime_3(p + 4)
    return p


# A collision-resistant hash function
# x: bytes
# return: int
def h(x):
    hx = hashlib.sha256(x).digest()
    idx = len(hx) // 2
    hl = hashlib.sha256(hx[:idx]).digest()
    hr = hashlib.sha256(hx[idx:]).digest()
    return int.from_bytes(hl + hr, 'little')


# m: bytes
def root(m, p, q):
    i = 0
    nrabin = p*q
    while True:
        x = h(m) % nrabin
        sig = pow(p, q - 2, q) * p * pow(x, (q + 1) // 4, q)
        sig = (pow(q, p - 2, p) * q * pow(x, (p + 1) // 4, p) + sig) % (nrabin)
        if (sig * sig) % nrabin == x and i != 0:
            break

        # padding
        m = m + bytes.fromhex("00")
        i = i + 1
    return sig, i


# Calculate h(mU) % n
# n: public key of the sender
def hF(m, paddingnum, nrabin):
    return h(m + bytes.fromhex("00") * paddingnum) % nrabin


# get message and private key and return signature and padding num (generated)
# Calculate signature by padding and return the signature and the generated padding num
def sF(hexmsg, p, q):
    return root(bytes.fromhex(hexmsg), p, q)


# Verify signature of encrypted message with the sender public key -return true if H(m,U,n) == s*s % n  , else false
def vF(hexmsg, paddingnum, s, nrabin):
    return hF(bytes.fromhex(hexmsg), paddingnum, nrabin) == (s * s) % nrabin


# Generate 2 large prime number that both of them equals 3 mod 4. return also the mul between those two number
def generate_keys_for_rabin():
    arg = '{}{}'.format((random.randint(a=0, b=9)), random.randint(a=0, b=9))
    p = nextPrime(h(bytes.fromhex(arg)) % (2 ** 501 + 1))
    q = nextPrime(h(bytes.fromhex(arg + '00')) % (2 ** 501 + 1))
    return p, q, p * q


# get message and private key and return signature and padding num (generated)
def sing_msg(msg, p, q):
    sig, padding_num = sF(msg, p, q)
    return hex(sig), padding_num


# Verify signature of encrypted message with the sender public key
def verify(to_ver, sig, padding_num, nrabin):
    res = vF(to_ver, int(padding_num), int(sig, 16), nrabin)
    print("Result of Rabin signatures verification: " + str(res))
    return res