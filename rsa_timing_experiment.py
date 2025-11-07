"""RSA timing experiment: keygen, encrypt, decrypt vs key size and message size.
Requires: pycryptodome
Usage examples:
  python rsa_timing_experiment.py
It will run a small table of timings and print them.
"""
import time
import secrets
from typing import List, Tuple
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

# Warning: RSA encrypts only small payloads (<= key_size_bytes - 2*hLen - 2 for OAEP) per operation.
# We simulate "n-bit message" by chunking to allowed block size.

def time_keygen(bits: int) -> float:
    t0 = time.perf_counter()
    RSA.generate(bits)
    t1 = time.perf_counter()
    return t1 - t0


def encrypt_large(plain: bytes, pub_key) -> Tuple[bytes, float]:
    cipher = PKCS1_OAEP.new(pub_key, hashAlgo=SHA256)
    key_bytes = pub_key.size_in_bytes()
    hlen = SHA256.digest_size
    max_block = key_bytes - 2 * hlen - 2
    out = bytearray()
    t0 = time.perf_counter()
    for i in range(0, len(plain), max_block):
        out.extend(cipher.encrypt(plain[i:i + max_block]))
    t1 = time.perf_counter()
    return bytes(out), (t1 - t0)


def decrypt_large(ciphertext: bytes, priv_key) -> Tuple[bytes, float]:
    cipher = PKCS1_OAEP.new(priv_key, hashAlgo=SHA256)
    key_bytes = priv_key.size_in_bytes()
    out = bytearray()
    t0 = time.perf_counter()
    for i in range(0, len(ciphertext), key_bytes):
        out.extend(cipher.decrypt(ciphertext[i:i + key_bytes]))
    t1 = time.perf_counter()
    return bytes(out), (t1 - t0)


def run_experiment(key_sizes: List[int], message_bits: List[int]):
    print("key_bits,message_bits,keygen_s,encrypt_s,decrypt_s,ok")
    for kb in key_sizes:
        # keygen
        kg = time_keygen(kb)
        # build keys
        key = RSA.generate(kb)
        pub = key.publickey()
        for mb in message_bits:
            mlen = (mb + 7) // 8
            msg = secrets.token_bytes(mlen)
            ct, te = encrypt_large(msg, pub)
            pt, td = decrypt_large(ct, key)
            ok = (pt == msg)
            print(f"{kb},{mb},{kg:.6f},{te:.6f},{td:.6f},{ok}")


def main():
    # Keep defaults small for fast runs on any machine
    key_sizes = [1024, 2048]
    message_bits = [128, 512, 1024, 2048]
    run_experiment(key_sizes, message_bits)


if __name__ == "__main__":
    main()
