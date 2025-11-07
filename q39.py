"""Q39: Secure messaging with RSA + signature + hash (standalone).
Uses RSA OAEP for encryption, PKCS#1 v1.5 signature over SHA-256.
Run:
  python q39.py
Requires: pycryptodome
"""
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

MESSAGE=b"Message from X to Y"

def gen(bits=1024):
    priv=RSA.generate(bits); return priv, priv.publickey()

def enc(pub,data): return PKCS1_OAEP.new(pub, hashAlgo=SHA256).encrypt(data)

def dec(priv,ct): return PKCS1_OAEP.new(priv, hashAlgo=SHA256).decrypt(ct)

def sign(priv,data): return pkcs1_15.new(priv).sign(SHA256.new(data))

def verify(pub,data,sig):
    try:
        pkcs1_15.new(pub).verify(SHA256.new(data), sig); return True
    except Exception: return False

if __name__=='__main__':
    x_priv,x_pub=gen(); y_priv,y_pub=gen()
    ct=enc(y_pub,MESSAGE)
    sig=sign(x_priv,MESSAGE)
    pt=dec(y_priv,ct)
    ok=verify(x_pub,pt,sig)
    print('Cipher (hex):', ct.hex()[:64]+'...')
    print('Decrypted:', pt)
    print('Signature valid:', ok)
