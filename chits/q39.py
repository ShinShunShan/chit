"""Q39: Secure messaging with RSA encryption + signature (standalone).

What this shows
- Confidentiality: RSA-OAEP encrypts the message for the recipient's public key.
- Integrity/Authenticity: Sender signs the plaintext with their private key.
- Verification: Receiver checks the signature using sender's public key.

Algorithms used
- RSA-OAEP with SHA-256 as the hash inside OAEP (IND-CPA secure padding for RSA).
- PKCS#1 v1.5 signatures over SHA-256 (simple, common in demos).

Run:
    python q39.py
Requires: pycryptodome
"""
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

MESSAGE = b"Message from X to Y"

def gen(bits: int = 1024):
    """Generate an RSA key pair (private, public).
    Note: 2048 bits is a stronger default in practice; 1024 keeps the demo fast."""
    priv = RSA.generate(bits)
    return priv, priv.publickey()

def enc(pub, data: bytes) -> bytes:
    """Encrypt data for the holder of the private key corresponding to pub.
    OAEP uses SHA-256 internally for masks and padding checks."""
    return PKCS1_OAEP.new(pub, hashAlgo=SHA256).encrypt(data)

def dec(priv, ct: bytes) -> bytes:
    """Decrypt OAEP ciphertext with the recipient's private key."""
    return PKCS1_OAEP.new(priv, hashAlgo=SHA256).decrypt(ct)

def sign(priv, data: bytes) -> bytes:
    """Sign the message hash with the sender's private key (PKCS#1 v1.5)."""
    return pkcs1_15.new(priv).sign(SHA256.new(data))

def verify(pub, data: bytes, sig: bytes) -> bool:
    """Verify signature using the sender's public key.
    Returns True if valid, else False."""
    try:
        pkcs1_15.new(pub).verify(SHA256.new(data), sig)
        return True
    except Exception:
        return False

if __name__ == '__main__':
    # X = sender, Y = recipient
    x_priv, x_pub = gen()
    y_priv, y_pub = gen()

    # Sender encrypts for recipient and signs the plaintext
    ct = enc(y_pub, MESSAGE)
    sig = sign(x_priv, MESSAGE)

    # Recipient decrypts, then verifies signature using sender's public key
    pt = dec(y_priv, ct)
    ok = verify(x_pub, pt, sig)

    print('Cipher (hex):', ct.hex()[:64] + '...')
    print('Decrypted:', pt)
    print('Signature valid:', ok)
