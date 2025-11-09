"""Q6: Diffie–Hellman with a Man-in-the-Middle (MITM) demo.

What you see:
- Honest DH yields the same shared key on both sides (g^(ab) mod p).
- MITM swaps public values and ends with two different keys, one per victim.

Usage:
    python q06.py
"""
import random

# For demo: use tiny prime and generator (in real life, huge safe primes)
P = 23  # prime
G = 5   # generator


def modexp(base, exp, mod):
    """Fast modular exponentiation using Python's built-in pow."""
    return pow(base, exp, mod)


def honest_dh():
    """Run an honest DH exchange and print matching keys."""
    print("Honest DH (no MITM):")
    a = random.randint(2, P-2)
    b = random.randint(2, P-2)
    A = modexp(G, a, P)
    B = modexp(G, b, P)
    s_alice = modexp(B, a, P)
    s_bob = modexp(A, b, P)
    print(f"  Alice private a={a}, public A={A}")
    print(f"  Bob   private b={b}, public B={B}")
    print(f"  Shared key (Alice) = {s_alice}")
    print(f"  Shared key (Bob)   = {s_bob}")
    print()


def mitm_dh():
    """Run a MITM where Mallory derives keys with each party."""
    print("MITM DH:")
    # Alice -> Mallory -> Bob
    a = random.randint(2, P-2)
    b = random.randint(2, P-2)
    m1 = random.randint(2, P-2)  # Mallory's secret with Alice
    m2 = random.randint(2, P-2)  # Mallory's secret with Bob

    A = modexp(G, a, P)
    B = modexp(G, b, P)
    M1 = modexp(G, m1, P)
    M2 = modexp(G, m2, P)

    # Mallory swaps: Alice sees M1 instead of B; Bob sees M2 instead of A
    # Shared keys:
    s_alice = modexp(M1, a, P)      # Alice with Mallory
    s_mallory_with_alice = modexp(A, m1, P)

    s_bob = modexp(M2, b, P)        # Bob with Mallory
    s_mallory_with_bob = modexp(B, m2, P)

    print(f"  Alice sends A={A}; Mallory replaces with M1={M1} to Bob")
    print(f"  Bob sends B={B};   Mallory replaces with M2={M2} to Alice")
    print(f"  Alice's key = {s_alice} (with Mallory)")
    print(f"  Mallory(A)  = {s_mallory_with_alice}")
    print(f"  Bob's key   = {s_bob} (with Mallory)")
    print(f"  Mallory(B)  = {s_mallory_with_bob}")
    print("  Note: Alice and Bob do not share the same key. Mallory can decrypt/modify.")


def main():
    honest_dh()
    mitm_dh()


if __name__ == "__main__":
    main()
