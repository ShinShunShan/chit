"""Q18: Custom encryption/decryption algorithm (educational).
Uses the same XOR+rotate scheme as q05, packaged with CLI.
Usage:
  python q18.py encrypt "Hello" key > out.hex
  python q18.py decrypt <hex> key
"""
import sys

def _rotl(b: int) -> int: return ((b << 1) & 0xFF) | (b >> 7)

def _rotr(b: int) -> int: return ((b >> 1) & 0x7F) | ((b & 1) << 7)

def encrypt(message: str, key: str) -> bytes:
    data = message.encode(); k = key.encode() or b"0"; out = bytearray()
    for i, byte in enumerate(data): out.append(_rotl(byte ^ k[i % len(k)]))
    return bytes(out)

def decrypt(cipher_hex: str, key: str) -> str:
    c = bytes.fromhex(cipher_hex); k = key.encode() or b"0"; out = bytearray()
    for i, byte in enumerate(c): out.append((_rotr(byte)) ^ k[i % len(k)])
    return bytes(out).decode()

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage encrypt: python q18.py encrypt <message> <key>")
        print("Usage decrypt: python q18.py decrypt <hex> <key>")
    else:
        if sys.argv[1] == 'encrypt' and len(sys.argv) >= 4:
            print(encrypt(sys.argv[2], sys.argv[3]).hex())
        elif sys.argv[1] == 'decrypt' and len(sys.argv) >= 4:
            print(decrypt(sys.argv[2], sys.argv[3]))
        else:
            print("Invalid usage")
