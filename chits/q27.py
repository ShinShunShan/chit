"""Q27: Image security over an unsecured network (standalone AES-GCM).
Encrypt image bytes with AES-GCM and write bundle JSON. Decrypt reverses it.
Demo only: stores key in the JSON for convenience.
Usage:
  python q27.py encrypt input.jpg out.json
  python q27.py decrypt out.json restored.jpg
"""
import sys, json, base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt_image(in_path: str, out_path: str):
    key=get_random_bytes(32); c=AES.new(key,AES.MODE_GCM)
    data=open(in_path,'rb').read(); ct, tag = c.encrypt_and_digest(data)
    bundle={'key':base64.b64encode(key).decode(),'nonce':base64.b64encode(c.nonce).decode(),'tag':base64.b64encode(tag).decode(),'cipher':base64.b64encode(ct).decode()}
    json.dump(bundle, open(out_path,'w'))
    print(f'Encrypted {in_path} -> {out_path}')

def decrypt_image(in_path: str, out_path: str):
    b=json.load(open(in_path))
    key=base64.b64decode(b['key']); nonce=base64.b64decode(b['nonce'])
    tag=base64.b64decode(b['tag']); ct=base64.b64decode(b['cipher'])
    c=AES.new(key,AES.MODE_GCM,nonce=nonce); data=c.decrypt_and_verify(ct,tag)
    open(out_path,'wb').write(data)
    print(f'Decrypted {in_path} -> {out_path}')

if __name__=='__main__':
    if len(sys.argv)<4:
        print('Usage: python q27.py <encrypt|decrypt> <in> <out>')
    else:
        act=sys.argv[1]
        if act=='encrypt': encrypt_image(sys.argv[2], sys.argv[3])
        elif act=='decrypt': decrypt_image(sys.argv[2], sys.argv[3])
        else: print('Action must be encrypt or decrypt')
