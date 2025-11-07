"""Vigenère (polyalphabetic) cipher.
Beginner-friendly.
Usage:
  python vigenere_cipher.py encrypt "ATTACK AT DAWN" LEMON
  python vigenere_cipher.py decrypt "LXFOPV EF RNHR" LEMON
Only A-Z are shifted; other characters pass through.
"""
import sys

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def _shift_for_key(key: str):
    return [ALPHABET.index(k) for k in key.upper() if k in ALPHABET]

def encrypt(plaintext: str, key: str) -> str:
    if not key:
        raise ValueError("Key must not be empty")
    key_shifts = _shift_for_key(key)
    if not key_shifts:
        raise ValueError("Key must contain at least one letter A-Z")
    result = []
    j = 0
    for ch in plaintext.upper():
        if ch in ALPHABET:
            shift = key_shifts[j % len(key_shifts)]
            idx = ALPHABET.index(ch)
            result.append(ALPHABET[(idx + shift) % 26])
            j += 1
        else:
            result.append(ch)
    return "".join(result)

def decrypt(ciphertext: str, key: str) -> str:
    if not key:
        raise ValueError("Key must not be empty")
    key_shifts = _shift_for_key(key)
    if not key_shifts:
        raise ValueError("Key must contain at least one letter A-Z")
    result = []
    j = 0
    for ch in ciphertext.upper():
        if ch in ALPHABET:
            shift = key_shifts[j % len(key_shifts)]
            idx = ALPHABET.index(ch)
            result.append(ALPHABET[(idx - shift) % 26])
            j += 1
        else:
            result.append(ch)
    return "".join(result)

def main():
    if len(sys.argv) < 4:
        print("Usage: python vigenere_cipher.py <encrypt|decrypt> <text> <key>")
        return
    action = sys.argv[1].lower()
    text = sys.argv[2]
    key = sys.argv[3]
    if action == "encrypt":
        print(encrypt(text, key))
    elif action == "decrypt":
        print(decrypt(text, key))
    else:
        print("Action must be encrypt or decrypt")

if __name__ == "__main__":
    main()
