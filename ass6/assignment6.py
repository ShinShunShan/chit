def gcd(a: int, b: int) -> int:
    while b != 0:
        a, b = b, a % b
    return a


def mod_inverse(e: int, phi: int) -> int:
    for i in range(1, phi):
        if (e * i) % phi == 1:
            return i
    return 0


def mod_exp(base: int, exp: int, mod: int) -> int:
    result = 1
    base %= mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        exp //= 2
        base = (base * base) % mod
    return result


def simple_hash(msg: str) -> int:
    h = 0
    for c in msg:
        h = (h + ord(c)) % 100
    return h


def main() -> None:
    p = int(input("Enter two prime numbers p and q (>5): ").strip())
    q = int(input().strip())

    n = p * q
    phi = (p - 1) * (q - 1)
    print(f"Computed n = {n}, phi = {phi}")

    while True:
        e = int(input("Enter public exponent e (1 < e < phi, gcd(e, phi)=1): "))
        if 1 < e < phi and gcd(e, phi) == 1:
            break
        print("Invalid e! Try again.")

    d = mod_inverse(e, phi)
    print(f"Private exponent (d) = {d}")

    message = input("\nEnter message: ")
    hash_value = simple_hash(message)
    print(f"\nMessage Hash Value: {hash_value}")

    signature = mod_exp(hash_value, d, n)
    print(f"Digital Signature (Sender X): {signature}")

    print("\nApplying key to each character")
    print("Signed values: ", end="")
    signed_chars = []
    for ch in message:
        sc = mod_exp(ord(ch), d, n)  
        signed_chars.append(sc)
        print(f"{sc} ", end="")
    print()

    print("\nRecovering original characters using the key...")
    print("Recovered Message: ", end="")
    recovered = []
    for sc in signed_chars:
        recovered.append(chr(mod_exp(sc, e, n)))  
    dec_msg = ''.join(recovered)
    print(dec_msg)

    print("\nVerifying Digital Signature...")
    verify_hash = mod_exp(signature, e, n)
    receiver_hash = simple_hash(dec_msg)
    print(f"Decrypted Signature (Hash from sender): {verify_hash}")
    print(f"Receiver's Computed Hash: {receiver_hash}")

    if verify_hash == receiver_hash:
        print("\n Signature Verified! Message is Authentic, Intact, and Sender cannot deny it.")
    else:
        print("\n Verification Failed! Message altered or sender not authentic.")


if __name__ == "__main__":
    main()
