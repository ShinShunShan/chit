"""Q5: Custom encryption/decryption algorithm (educational, not secure).

Scheme (byte-wise):
    enc: b -> (b XOR key[i]) -> rotl1
    dec: c -> rotr1 -> XOR key[i]

Why not secure: XOR+rotate is linear and offers no real diffusion/confusion.
Dependencies: None beyond Python stdlib.
"""

def _rotl(b: int) -> int:
    return ((b << 1) & 0xFF) | (b >> 7)

def _rotr(b: int) -> int:
    return ((b >> 1) & 0x7F) | ((b & 1) << 7)

def encrypt(message: str, key: str) -> bytes:
    """Return raw bytes of toy 'ciphertext' for a UTF-8 message."""
    data = message.encode()
    k = key.encode() or b"0"
    out = bytearray()
    for i, byte in enumerate(data):
        x = byte ^ k[i % len(k)]
        out.append(_rotl(x))
    return bytes(out)

def decrypt(cipher: bytes, key: str) -> str:
    """Invert the toy cipher back to a UTF-8 string."""
    k = key.encode() or b"0"
    out = bytearray()
    for i, byte in enumerate(cipher):
        x = _rotr(byte)
        out.append(x ^ k[i % len(k)])
    return bytes(out).decode()

if __name__ == '__main__':
    msg = "Custom Demo"
    key = "key"
    ct = encrypt(msg, key)
    print("Cipher (hex):", ct.hex())
    pt = decrypt(ct, key)
    print("Decrypted:", pt)
