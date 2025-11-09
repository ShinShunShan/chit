"""Q27: Image confidentiality + integrity (stdlib-only, educational).

No external crypto library. We use a SHA-1-based keystream (XOR) and a SHA-1 tag
over (key||nonce||ciphertext). This is not secure like AES-GCM and is for learning.
Usage:
  python q27.py encrypt input.jpg out.json
  python q27.py decrypt out.json restored.jpg
"""
import sys, os, json, base64, hashlib

def sha1(b: bytes) -> bytes: return hashlib.sha1(b).digest()

def stream(key: bytes, nonce: bytes, n: int) -> bytes:
    out=bytearray(); ctr=0
    while len(out)<n:
        out.extend(sha1(key+nonce+ctr.to_bytes(4,'big')))
        ctr+=1
    return bytes(out[:n])

def encrypt_image(inp: str, outp: str):
    key=os.urandom(16); nonce=os.urandom(8)
    data=open(inp,'rb').read()
    ks=stream(key,nonce,len(data))
    ct=bytes(a^b for a,b in zip(data,ks))
    tag=sha1(key+nonce+ct)
    bundle={'key':base64.b64encode(key).decode(),'nonce':base64.b64encode(nonce).decode(),'cipher':base64.b64encode(ct).decode(),'tag':base64.b64encode(tag).decode()}
    json.dump(bundle, open(outp,'w'))
    print(f'Encrypted {inp} -> {outp}')

def decrypt_image(inp: str, outp: str):
    b=json.load(open(inp,'r'))
    key=base64.b64decode(b['key']); nonce=base64.b64decode(b['nonce'])
    ct=base64.b64decode(b['cipher']); tag=base64.b64decode(b['tag'])
    if sha1(key+nonce+ct)!=tag:
        print('Tag mismatch'); return
    ks=stream(key,nonce,len(ct))
    data=bytes(a^b for a,b in zip(ct,ks))
    open(outp,'wb').write(data)
    print(f'Decrypted {inp} -> {outp}')

if __name__=='__main__':
    if len(sys.argv)<4:
        print('Usage: python q27.py <encrypt|decrypt> <in> <out>')
    else:
        a=sys.argv[1]
        if a=='encrypt': encrypt_image(sys.argv[2], sys.argv[3])
        elif a=='decrypt': decrypt_image(sys.argv[2], sys.argv[3])
        else: print('Action must be encrypt or decrypt')
