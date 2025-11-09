"""Diffie–Hellman key exchange with a Man-in-the-Middle (MITM) demo.

Concepts shown:
1. Honest DH: Alice and Bob each select a private exponent and exchange public values.
2. MITM: Mallory intercepts and substitutes public values so Alice and Bob never share a key.

Security lesson:
- DH without authentication (signatures, certificates, PAKE) is vulnerable to MITM.
- Each side believes they have a shared secret, but Mallory has two: one with Alice, one with Bob.

Usage:
    python diffie_hellman_mitm_demo.py

NOTE: Tiny prime used for clarity; real implementations use large safe primes or elliptic curves.
"""
import random

# For demo: use tiny prime and generator (in real life, huge safe primes)
P = 23  # prime
G = 5   # generator


def modexp(base: int, exp: int, mod: int) -> int:
    """Modular exponentiation: (base ** exp) % mod.
    Python's built-in pow with 3 args uses fast exponentiation."""
    return pow(base, exp, mod)


def honest_dh():
    """Perform an honest DH exchange and print matching shared keys."""
    print("Honest DH (no MITM):")
    a = random.randint(2, P - 2)  # Alice's private exponent
    b = random.randint(2, P - 2)  # Bob's private exponent
    A = modexp(G, a, P)           # Alice's public value g^a mod p
    B = modexp(G, b, P)           # Bob's public value g^b mod p
    s_alice = modexp(B, a, P)     # (g^b)^a = g^(ab) mod p
    s_bob = modexp(A, b, P)       # (g^a)^b = g^(ab) mod p
    print(f"  Alice private a={a}, public A={A}")
    print(f"  Bob   private b={b}, public B={B}")
    print(f"  Shared key (Alice) = {s_alice}")
    print(f"  Shared key (Bob)   = {s_bob}")
    print()


def mitm_dh():
    """Simulate a MITM where Mallory derives two keys and can read traffic."""
    print("MITM DH:")
    a = random.randint(2, P - 2)   # Alice's private
    b = random.randint(2, P - 2)   # Bob's private
    m1 = random.randint(2, P - 2)  # Mallory's secret with Alice
    m2 = random.randint(2, P - 2)  # Mallory's secret with Bob

    A = modexp(G, a, P)            # Alice's public
    B = modexp(G, b, P)            # Bob's public
    M1 = modexp(G, m1, P)          # Mallory's replacement to Bob
    M2 = modexp(G, m2, P)          # Mallory's replacement to Alice

    # Keys established (incorrectly from Alice & Bob perspective):
    s_alice = modexp(M2, a, P)              # Alice thinks this is shared with Bob (actually with Mallory)
    s_mallory_with_alice = modexp(A, m2, P) # Mallory's key with Alice
    s_bob = modexp(M1, b, P)                # Bob thinks this is shared with Alice (actually with Mallory)
    s_mallory_with_bob = modexp(B, m1, P)   # Mallory's key with Bob

    print(f"  Alice sends A={A}; Mallory replaces with M1={M1} to Bob")
    print(f"  Bob sends B={B};   Mallory replaces with M2={M2} to Alice")
    print(f"  Alice's key (with Mallory)        = {s_alice}")
    print(f"  Mallory's key with Alice          = {s_mallory_with_alice}")
    print(f"  Bob's key (with Mallory)          = {s_bob}")
    print(f"  Mallory's key with Bob            = {s_mallory_with_bob}")
    print("  Result: Alice and Bob do NOT share a key; Mallory can decrypt and modify transit messages.")


def main():
    honest_dh()
    mitm_dh()


if __name__ == "__main__":
    main()
