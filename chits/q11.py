"""Q11: Secure messaging with toy RSA encryption + signature (no external libs).

This version uses the pure-Python RSA from q02 (Miller-Rabin + textbook RSA).
Security note: This is for learning only (no OAEP/PSS padding; small keys).

Workflow
- X and Y each generate RSA keys (n, e, d).
- X encrypts a short message to Y: c = m^e mod n.
- X signs the SHA-256 digest: s = H(m)^d mod n.
- Y decrypts and verifies: H(m) == s^e mod n.
"""

from q02 import generate_rsa  # pure-Python toy RSA
import hashlib

MESSAGE = b"CONFIDENTIAL DATA"  # keep it small so m < n


def rsa_encrypt_bytes(msg: bytes, e: int, n: int) -> bytes:
    """Textbook RSA on bytes: encode to int, check fits under n, pow, return bytes.
    NOTE: No padding. Only for tiny demos."""
    m = int.from_bytes(msg, 'big')
    if m >= n:
        raise ValueError("Message too large for RSA modulus in toy demo")
    c = pow(m, e, n)
    # store ciphertext as same byte length as modulus
    clen = (n.bit_length() + 7) // 8
    return c.to_bytes(clen, 'big')


def rsa_decrypt_bytes(ct: bytes, d: int, n: int) -> bytes:
    c = int.from_bytes(ct, 'big')
    m = pow(c, d, n)
    mlen = (m.bit_length() + 7) // 8
    return m.to_bytes(mlen, 'big')


def sign_sha256(msg: bytes, d: int, n: int) -> int:
    h = hashlib.sha256(msg).digest()
    h_int = int.from_bytes(h, 'big')
    return pow(h_int, d, n)


def verify_sha256(msg: bytes, sig: int, e: int, n: int) -> bool:
    h = hashlib.sha256(msg).digest()
    h_int = int.from_bytes(h, 'big')
    return pow(sig, e, n) == h_int


def demo():
    # Generate tiny RSA keys for X and Y
    n_x, e_x, d_x = generate_rsa(512)
    n_y, e_y, d_y = generate_rsa(512)

    # X encrypts for Y
    ct = rsa_encrypt_bytes(MESSAGE, e_y, n_y)

    # X signs MESSAGE
    sig = sign_sha256(MESSAGE, d_x, n_x)

    # Y decrypts
    pt = rsa_decrypt_bytes(ct, d_y, n_y)

    # Y verifies signature using X's public key
    ok = verify_sha256(pt, sig, e_x, n_x)

    print("Ciphertext (hex):", ct.hex()[:60] + '...')
    print("Decrypted:", pt)
    print("Signature valid:", ok)


if __name__ == '__main__':
    demo()
