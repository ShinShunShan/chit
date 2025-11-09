"""Q10: Password protection demo using PBKDF2-HMAC-SHA256.

Concepts:
- Salt: random per password prevents rainbow table reuse.
- Iterations: slow down brute-force (adjust upward over time).
- Verification: recompute derived key and compare in constant time.

Usage:
    python q10.py hash MyPassword
    python q10.py verify <stored> MyPassword
Stored format: iterations:salt_hex:hash_hex
"""
import sys, os, hashlib, binascii

ITERATIONS = 150000


def hash_password(password: str) -> str:
    """Return encoded record containing iterations, salt, and derived key."""
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, ITERATIONS)
    return f"{ITERATIONS}:{salt.hex()}:{dk.hex()}"


def verify_password(stored: str, password: str) -> bool:
    """Check password against stored record; returns True on match."""
    try:
        iterations_str, salt_hex, hash_hex = stored.split(':')
        it = int(iterations_str)
        salt = bytes.fromhex(salt_hex)
        original = bytes.fromhex(hash_hex)
    except Exception:
        return False
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, it)
    # Use hash-of-dk comparison to keep timing uniform
    return hashlib.sha256(dk).digest() == hashlib.sha256(original).digest()


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage hash:   python q10.py hash <password>")
        print("Usage verify: python q10.py verify <stored> <password>")
    else:
        action = sys.argv[1]
        if action == 'hash':
            print(hash_password(sys.argv[2]))
        elif action == 'verify' and len(sys.argv) >= 4:
            print(verify_password(sys.argv[2], sys.argv[3]))
        else:
            print("Invalid usage")
