"""Q17: Image confidentiality + integrity (educational, no external libs).

Since we must avoid external libraries, we cannot use AES-GCM here. Instead we
demonstrate a simplified scheme:
  - XOR stream cipher: keystream = SHA-1(counter || key) blocks
  - Integrity: SHA-1 over (key || nonce || ciphertext) as a tag

This is NOT secure like AES-GCM (predictable structure, SHA-1 weaknesses,
re-using key+nonce is catastrophic). It's purely to illustrate the *ideas*
of encrypt + authenticate with only hashlib/os/json/base64.

Usage:
  python q17.py encrypt input.jpg output.enc
  python q17.py decrypt output.enc recovered.jpg
"""
import sys, os, json, base64, hashlib

BLOCK = 20  # SHA-1 output bytes

def sha1(data: bytes) -> bytes:
    return hashlib.sha1(data).digest()

def kdf_stream(key: bytes, nonce: bytes, length: int) -> bytes:
    """Generate keystream of requested length using SHA-1(key||nonce||counter)."""
    out = bytearray(); counter = 0
    while len(out) < length:
        blk = sha1(key + nonce + counter.to_bytes(4, 'big'))
        out.extend(blk)
        counter += 1
    return bytes(out[:length])

def encrypt_image(in_path: str, out_path: str):
    key = os.urandom(16)
    nonce = os.urandom(8)
    data = open(in_path,'rb').read()
    keystream = kdf_stream(key, nonce, len(data))
    ciphertext = bytes(a ^ b for a, b in zip(data, keystream))
    tag = sha1(key + nonce + ciphertext)  # fragile, only for demo
    bundle = {
        'key_b64': base64.b64encode(key).decode(),  # demo only
        'nonce_b64': base64.b64encode(nonce).decode(),
        'cipher_b64': base64.b64encode(ciphertext).decode(),
        'tag_b64': base64.b64encode(tag).decode()
    }
    json.dump(bundle, open(out_path,'w'))
    print(f'Encrypted {in_path} -> {out_path}')

def decrypt_image(in_path: str, out_path: str):
    bundle = json.load(open(in_path,'r'))
    key = base64.b64decode(bundle['key_b64'])
    nonce = base64.b64decode(bundle['nonce_b64'])
    ciphertext = base64.b64decode(bundle['cipher_b64'])
    tag = base64.b64decode(bundle['tag_b64'])
    # recompute tag
    if sha1(key + nonce + ciphertext) != tag:
        print('Tag mismatch: data altered or wrong key'); return
    keystream = kdf_stream(key, nonce, len(ciphertext))
    data = bytes(a ^ b for a, b in zip(ciphertext, keystream))
    open(out_path,'wb').write(data)
    print(f'Decrypted {in_path} -> {out_path}')

if __name__ == '__main__':
    if len(sys.argv) < 4:
        print('Usage: python q17.py <encrypt|decrypt> <in> <out>')
    else:
        act = sys.argv[1]
        if act == 'encrypt': encrypt_image(sys.argv[2], sys.argv[3])
        elif act == 'decrypt': decrypt_image(sys.argv[2], sys.argv[3])
        else: print('Action must be encrypt or decrypt')
