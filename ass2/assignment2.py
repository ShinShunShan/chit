import time
def power(base, expo, m):
    """Compute (base^expo) % m"""
    return pow(base, expo, m)

def mod_inverse(e, phi):
    """Compute modular inverse of e under modulo phi"""
    return pow(e, -1, phi)

def generate_keys(p, q):
    """Generate RSA keys"""
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 2
    while e < phi:
        if gcd(e, phi) == 1:
            break
        e += 1

    d = mod_inverse(e, phi)
    return e, d, n

def gcd(a, b):
    """Greatest Common Divisor"""
    while b:
        a, b = b, a % b
    return a

def encrypt(m, e, n):
    """Encrypt message m using (e, n)"""
    return power(m, e, n)

def decrypt(c, d, n):
    """Decrypt ciphertext c using (d, n)"""
    return power(c, d, n)


def main():
    # Manual inputs
    p = int(input("Enter prime number p: "))
    q = int(input("Enter prime number q: "))
    M = int(input("Enter message (integer): "))

    # Key generation timing
    t_key_start = time.time_ns()
    e, d, n = generate_keys(p, q)
    t_key_end = time.time_ns()
    key_gen_time = t_key_end - t_key_start

    # Encryption timing
    t_enc_start = time.time_ns()
    C = encrypt(M, e, n)
    t_enc_end = time.time_ns()
    enc_time = t_enc_end - t_enc_start

    # Decryption timing
    t_dec_start = time.time_ns()
    D = decrypt(C, d, n)
    t_dec_end = time.time_ns()
    dec_time = t_dec_end - t_dec_start

    # Print results
    print(f"Total key generation time: {key_gen_time} ns ({key_gen_time / 1e6:.6f} ms)")
    print(f"Encryption time: {enc_time} ns ({enc_time / 1e6:.6f} ms)")
    print(f"Decryption time: {dec_time} ns ({dec_time / 1e6:.6f} ms)\n")

    print(f"Public Key (e, n): ({e}, {n})")
    print(f"Private Key (d, n): ({d}, {n})")
    print(f"Original Message: {M}")
    print(f"Encrypted Message: {C}")
    print(f"Decrypted Message: {D}")


if __name__ == "__main__":
    main()

