"""Q17: Image security over an unsecured network.

We use AES-GCM to provide confidentiality and integrity (auth tag) for image bytes.
For learning convenience, the output JSON bundle includes the key (INSECURE in real life).

Requires: pycryptodome
Usage:
    python q17.py encrypt input.jpg output.enc
    python q17.py decrypt output.enc recovered.jpg
"""
import sys, os, json, base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

CHUNK = 64 * 1024

def encrypt_image(in_path: str, out_path: str):
    """Encrypt all bytes from in_path with a fresh random key and nonce.
    Writes a self-contained JSON bundle (for demo; includes key)."""
    key = get_random_bytes(32)  # 256-bit key
    cipher = AES.new(key, AES.MODE_GCM)
    with open(in_path, 'rb') as f:
        data = f.read()
    ciphertext, tag = cipher.encrypt_and_digest(data)
    bundle = {
        'key_b64': base64.b64encode(key).decode(),  # DEMO ONLY: never ship key like this
        'nonce_b64': base64.b64encode(cipher.nonce).decode(),
        'tag_b64': base64.b64encode(tag).decode(),
        'cipher_b64': base64.b64encode(ciphertext).decode()
    }
    with open(out_path, 'w') as f:
        json.dump(bundle, f)
    print(f"Encrypted {in_path} -> {out_path}")


def decrypt_image(in_path: str, out_path: str):
    """Verify tag and recover original bytes into out_path."""
    with open(in_path, 'r') as f:
        bundle = json.load(f)
    key = base64.b64decode(bundle['key_b64'])
    nonce = base64.b64decode(bundle['nonce_b64'])
    tag = base64.b64decode(bundle['tag_b64'])
    ciphertext = base64.b64decode(bundle['cipher_b64'])
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    with open(out_path, 'wb') as f:
        f.write(data)
    print(f"Decrypted {in_path} -> {out_path}")

if __name__ == '__main__':
    if len(sys.argv) < 4:
        print("Usage: python q17.py <encrypt|decrypt> <in> <out>")
    else:
        action = sys.argv[1]
        if action == 'encrypt':
            encrypt_image(sys.argv[2], sys.argv[3])
        elif action == 'decrypt':
            decrypt_image(sys.argv[2], sys.argv[3])
        else:
            print("Action must be encrypt or decrypt")
