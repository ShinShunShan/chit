"""Vernam cipher (XOR) over bytes.
Key must be the same length as the message.
Usage:
  python vernam_cipher.py encrypt "Hello" KEY__
  python vernam_cipher.py decrypt <hexcipher> KEY__
For simplicity, we:
- Accept plaintext as a normal string (UTF-8 encoded)
- Accept key as normal string of same length
- Output ciphertext as hex string
"""
import sys


def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes([d ^ k for d, k in zip(data, key)])


def encrypt(plaintext: str, key: str) -> str:
    p = plaintext.encode("utf-8")
    k = key.encode("utf-8")
    if len(p) != len(k):
        raise ValueError("Key must be the same length as message")
    c = xor_bytes(p, k)
    return c.hex()


def decrypt(cipher_hex: str, key: str) -> str:
    c = bytes.fromhex(cipher_hex)
    k = key.encode("utf-8")
    if len(c) != len(k):
        raise ValueError("Key must be the same length as message")
    p = xor_bytes(c, k)
    return p.decode("utf-8", errors="strict")


def main():
    if len(sys.argv) < 4:
        print("Usage: python vernam_cipher.py <encrypt|decrypt> <text|hex> <key>")
        return
    action = sys.argv[1].lower()
    data = sys.argv[2]
    key = sys.argv[3]
    if action == "encrypt":
        print(encrypt(data, key))
    elif action == "decrypt":
        print(decrypt(data, key))
    else:
        print("Action must be encrypt or decrypt")


if __name__ == "__main__":
    main()
