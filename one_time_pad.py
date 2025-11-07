"""One-Time Pad demo using random bytes.
Generates a truly random pad (using secrets) equal to message length and XORs.
If you reuse the pad, security is broken! This script just demonstrates basics.
Usage:
  python one_time_pad.py encrypt "HELLO"  # prints key(hex) and ciphertext(hex)
  python one_time_pad.py decrypt <cipherhex> <keyhex>
"""
import sys
import secrets


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes([x ^ y for x, y in zip(a, b)])


def encrypt(message: str):
    data = message.encode("utf-8")
    pad = secrets.token_bytes(len(data))  # random pad
    cipher = xor_bytes(data, pad)
    return pad.hex(), cipher.hex()


def decrypt(cipher_hex: str, pad_hex: str) -> str:
    cipher = bytes.fromhex(cipher_hex)
    pad = bytes.fromhex(pad_hex)
    if len(cipher) != len(pad):
        raise ValueError("Pad length must equal cipher length")
    plain = xor_bytes(cipher, pad)
    return plain.decode("utf-8")


def main():
    if len(sys.argv) < 3:
        print("Usage encrypt: python one_time_pad.py encrypt <message>")
        print("Usage decrypt: python one_time_pad.py decrypt <cipherhex> <padhex>")
        return
    action = sys.argv[1].lower()
    if action == "encrypt":
        pad_hex, cipher_hex = encrypt(sys.argv[2])
        print("Pad:", pad_hex)
        print("Cipher:", cipher_hex)
    elif action == "decrypt":
        if len(sys.argv) < 4:
            print("Need cipherhex and padhex for decrypt")
            return
        print(decrypt(sys.argv[2], sys.argv[3]))
    else:
        print("Action must be encrypt or decrypt")


if __name__ == "__main__":
    main()
