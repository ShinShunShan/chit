"""Q4: RSA timing experiment (same method as Q2, separate script).

Shows how RSA performance varies. Minimal external dependency: PyCryptodome.
"""
import time, secrets
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

def time_keygen(bits:int)->float:
    """Time key generation for the requested key size."""
    t0=time.perf_counter(); RSA.generate(bits); t1=time.perf_counter(); return t1-t0

def encrypt_large(data:bytes, pub):
    """Encrypt arbitrary bytes by chunking to OAEP block size."""
    c=PKCS1_OAEP.new(pub, hashAlgo=SHA256)
    k=pub.size_in_bytes(); h=SHA256.digest_size; maxb=k-2*h-2
    out=bytearray(); t0=time.perf_counter()
    for i in range(0,len(data),maxb): out.extend(c.encrypt(data[i:i+maxb]))
    t1=time.perf_counter(); return bytes(out), t1-t0

def decrypt_large(ct:bytes, priv):
    """Decrypt the OAEP-chunked ciphertext back to original bytes."""
    c=PKCS1_OAEP.new(priv, hashAlgo=SHA256)
    k=priv.size_in_bytes(); out=bytearray(); t0=time.perf_counter()
    for i in range(0,len(ct),k): out.extend(c.decrypt(ct[i:i+k]))
    t1=time.perf_counter(); return bytes(out), t1-t0

def run():
    print("key_bits,message_bits,keygen_s,encrypt_s,decrypt_s,ok")
    for kb in [1024,2048]:
        kg=time_keygen(kb)
        key=RSA.generate(kb); pub=key.publickey()
        for mb in [128,512,1024,2048]:
            mlen=(mb+7)//8; msg=secrets.token_bytes(mlen)
            ct,te=encrypt_large(msg,pub); pt,td=decrypt_large(ct,key)
            print(f"{kb},{mb},{kg:.6f},{te:.6f},{td:.6f},{pt==msg}")

if __name__=='__main__': run()
