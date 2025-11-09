"""Q35: Secure messaging: RSA encryption (OAEP) + signature (PKCS#1 v1.5 over SHA-256).
Demonstrates confidentiality, integrity, and non-repudiation.
Run:
  python q35.py
Requires: pycryptodome
"""
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

MESSAGE = b"Confidential message from X to Y"

def gen_keys(bits=1024):
    priv=RSA.generate(bits); return priv, priv.publickey()

def encrypt_for(pub, data:bytes)->bytes:
    return PKCS1_OAEP.new(pub, hashAlgo=SHA256).encrypt(data)

def decrypt_with(priv, ct:bytes)->bytes:
    return PKCS1_OAEP.new(priv, hashAlgo=SHA256).decrypt(ct)

def sign_with(priv, data:bytes)->bytes:
    return pkcs1_15.new(priv).sign(SHA256.new(data))

def verify_with(pub, data:bytes, sig:bytes)->bool:
    try:
        pkcs1_15.new(pub).verify(SHA256.new(data), sig)
        return True
    except Exception:
        return False

if __name__=='__main__':
    x_priv,x_pub = gen_keys(); y_priv,y_pub = gen_keys()
    ct = encrypt_for(y_pub, MESSAGE)
    sig = sign_with(x_priv, MESSAGE)
    pt = decrypt_with(y_priv, ct)
    ok = verify_with(x_pub, pt, sig)
    print('Original:', MESSAGE)
    print('Cipher (hex):', ct.hex()[:64]+'...')
    print('Decrypted:', pt)
    print('Signature valid:', ok)
