"""Q40: Image security over an unsecured network using AES-GCM (standalone).

Concepts
- AES-GCM provides confidentiality + integrity (tag) in one step.
- We serialize key, nonce, tag, and ciphertext into a JSON bundle (educational only).
    WARNING: Exposing the key alongside ciphertext defeats real security — done here
    solely to keep the demo self-contained.

Usage:
    python q40.py encrypt input.jpg out.json
    python q40.py decrypt out.json restored.jpg
"""
import sys, json, base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt_image(inp: str, outp: str):
    """Encrypt image bytes with a fresh random 256-bit key and nonce.
    Returns nothing; writes JSON bundle (INSECURE packaging including key)."""
    key = get_random_bytes(32)            # 256-bit symmetric key
    cipher = AES.new(key, AES.MODE_GCM)   # GCM mode produces nonce + tag
    data = open(inp, 'rb').read()
    ct, tag = cipher.encrypt_and_digest(data)
    bundle = {
        'k': base64.b64encode(key).decode(),      # INSECURE: key should be kept secret
        'n': base64.b64encode(cipher.nonce).decode(),
        't': base64.b64encode(tag).decode(),
        'c': base64.b64encode(ct).decode()
    }
    json.dump(bundle, open(outp, 'w'))
    print(f'Encrypted {inp} -> {outp}')

def decrypt_image(inp: str, outp: str):
    """Recover original image bytes verifying tag integrity."""
    bundle = json.load(open(inp))
    key = base64.b64decode(bundle['k'])
    nonce = base64.b64decode(bundle['n'])
    tag = base64.b64decode(bundle['t'])
    ct = base64.b64decode(bundle['c'])
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    data = cipher.decrypt_and_verify(ct, tag)
    open(outp, 'wb').write(data)
    print(f'Decrypted {inp} -> {outp}')

if __name__ == '__main__':
    if len(sys.argv) < 4:
        print('Usage: python q40.py <encrypt|decrypt> <in> <out>')
    else:
        action = sys.argv[1]
        if action == 'encrypt':
            encrypt_image(sys.argv[2], sys.argv[3])
        elif action == 'decrypt':
            decrypt_image(sys.argv[2], sys.argv[3])
        else:
            print('Action must be encrypt or decrypt')
