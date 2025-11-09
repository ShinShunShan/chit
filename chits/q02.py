"""Q2: Toy RSA timing experiment WITHOUT external libraries.

This is a simplified, educational RSA timing demo that uses only the Python
standard library. It implements a tiny RSA key generation (Miller-Rabin
primality test + random prime search), textbook RSA encrypt/decrypt (m^e mod n),
and measures timings. THIS IS INSECURE: it is for learning only.

We avoid OAEP and PyCryptodome here to keep the script self-contained.
Outputs CSV rows: key_bits,message_bits,keygen_s,encrypt_s,decrypt_s,ok
"""

import time
import secrets
import random
from typing import Tuple


def is_probable_prime(n: int, k: int = 8) -> bool:
    """Miller-Rabin primality test (probabilistic).
    k is the number of rounds; larger -> more confidence."""
    if n < 2:
        return False
    # small primes quick check
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    # write n-1 as d*2^s
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    def try_composite(a: int) -> bool:
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            return False
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                return False
        return True  # composite

    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        if try_composite(a):
            return False
    return True


def generate_prime(bits: int) -> int:
    """Generate a probable prime of the given bit length."""
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate


def egcd(a: int, b: int) -> Tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("No modular inverse")
    return x % m


def generate_rsa(bits: int = 512) -> Tuple[int, int, int]:
    """Generate a tiny RSA keypair (n,e,d). Bits is total key size (educational)."""
    e = 65537
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    while q == p:
        q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    if phi % e == 0:
        return generate_rsa(bits)
    d = modinv(e, phi)
    return n, e, d


def rsa_encrypt_int(m: int, e: int, n: int) -> int:
    return pow(m, e, n)


def rsa_decrypt_int(c: int, d: int, n: int) -> int:
    return pow(c, d, n)


def time_keygen(bits: int) -> float:
    t0 = time.perf_counter()
    generate_rsa(bits)
    t1 = time.perf_counter()
    return t1 - t0


def run():
    print("key_bits,message_bits,keygen_s,encrypt_s,decrypt_s,ok")
    for kb in [512, 768]:
        kg = time_keygen(kb)
        n, e, d = generate_rsa(kb)
        for mb in [32, 64, 128, 256]:
            mlen = (mb + 7) // 8
            while True:
                msg_bytes = secrets.token_bytes(mlen)
                m_int = int.from_bytes(msg_bytes, 'big')
                if m_int < n:
                    break

            t0 = time.perf_counter()
            c_int = rsa_encrypt_int(m_int, e, n)
            t1 = time.perf_counter()
            enc_t = t1 - t0

            t0 = time.perf_counter()
            p_int = rsa_decrypt_int(c_int, d, n)
            t1 = time.perf_counter()
            dec_t = t1 - t0

            ok = (p_int == m_int)
            print(f"{kb},{mb},{kg:.6f},{enc_t:.6f},{dec_t:.6f},{ok}")


if __name__ == '__main__':
    run()
