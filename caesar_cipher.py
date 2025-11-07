"""Simple Caesar Cipher implementation.
Beginner-friendly.
Usage:
  python caesar_cipher.py encrypt "HELLO WORLD" 3
  python caesar_cipher.py decrypt "KHOOR ZRUOG" 3
Only letters A-Z are shifted; other characters stay the same.
"""
import sys

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def encrypt(plaintext: str, shift: int) -> str:
    result = []
    shift = shift % 26
    for ch in plaintext.upper():
        if ch in ALPHABET:
            idx = ALPHABET.index(ch)
            new_idx = (idx + shift) % 26
            result.append(ALPHABET[new_idx])
        else:
            result.append(ch)
    return "".join(result)

def decrypt(ciphertext: str, shift: int) -> str:
    return encrypt(ciphertext, -shift)

def main():
    if len(sys.argv) < 4:
        print("Usage: python caesar_cipher.py <encrypt|decrypt> <text> <shift>")
        return
    action = sys.argv[1].lower()
    text = sys.argv[2]
    try:
        shift = int(sys.argv[3])
    except ValueError:
        print("Shift must be an integer")
        return
    if action == "encrypt":
        print(encrypt(text, shift))
    elif action == "decrypt":
        print(decrypt(text, shift))
    else:
        print("Action must be encrypt or decrypt")

if __name__ == "__main__":
    main()
