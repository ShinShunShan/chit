"""Q11: Secure messaging with RSA encryption + signature.

Demonstrates end-to-end:
- Keypairs: X and Y each generate RSA keys.
- Confidentiality: X encrypts to Y using RSA-OAEP (SHA-256 inside OAEP).
- Integrity/Non-repudiation: X signs plaintext using PKCS#1 v1.5 over SHA-256.
- Verification: Y verifies signature, then decrypts the ciphertext.

Dependencies: Only PyCryptodome besides stdlib.
Usage:
    python q11.py
"""
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

MESSAGE = b"CONFIDENTIAL DATA"  # what X sends to Y


def generate_keys(bits=1024):
    """Generate an RSA private/public keypair (fast 1024-bit for demo)."""
    priv = RSA.generate(bits)
    pub = priv.publickey()
    return priv, pub


def encrypt_for_receiver(message: bytes, receiver_pub):
    """Encrypt with OAEP so only the holder of receiver_priv can decrypt."""
    cipher = PKCS1_OAEP.new(receiver_pub, hashAlgo=SHA256)
    return cipher.encrypt(message)


def decrypt_received(ciphertext: bytes, receiver_priv):
    """Decrypt OAEP ciphertext using receiver's private key."""
    cipher = PKCS1_OAEP.new(receiver_priv, hashAlgo=SHA256)
    return cipher.decrypt(ciphertext)


def sign_message(message: bytes, sender_priv):
    """Create PKCS#1 v1.5 signature over SHA-256 digest of message."""
    h = SHA256.new(message)
    return pkcs1_15.new(sender_priv).sign(h)


def verify_signature(message: bytes, signature: bytes, sender_pub) -> bool:
    """Return True if signature validates for message under sender's public key."""
    h = SHA256.new(message)
    try:
        pkcs1_15.new(sender_pub).verify(h, signature)
        return True
    except Exception:
        return False


def demo():
    # Generate keys for X and Y
    x_priv, x_pub = generate_keys()
    y_priv, y_pub = generate_keys()

    # X encrypts the message for Y (confidentiality)
    ciphertext = encrypt_for_receiver(MESSAGE, y_pub)

    # X signs the original plaintext (non-repudiation, integrity)
    signature = sign_message(MESSAGE, x_priv)

    # Y decrypts
    decrypted = decrypt_received(ciphertext, y_priv)

    # Y verifies signature
    sig_ok = verify_signature(decrypted, signature, x_pub)

    print("Original:", MESSAGE)
    print("Ciphertext (hex):", ciphertext.hex()[:60] + '...')
    print("Decrypted:", decrypted)
    print("Signature valid:", sig_ok)

if __name__ == '__main__':
    demo()
