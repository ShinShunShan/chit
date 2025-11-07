"""Q43: Image security over an unsecured network (standalone AES-GCM).
Usage:
  python q43.py encrypt input.jpg out.json
  python q43.py decrypt out.json restored.jpg
"""
import sys, json, base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt_image(inp,outp):
    key=get_random_bytes(32); c=AES.new(key,AES.MODE_GCM); data=open(inp,'rb').read(); ct,tag=c.encrypt_and_digest(data)
    bundle={'k':base64.b64encode(key).decode(),'n':base64.b64encode(c.nonce).decode(),'t':base64.b64encode(tag).decode(),'c':base64.b64encode(ct).decode()}
    json.dump(bundle, open(outp,'w')); print(f'Encrypted {inp} -> {outp}')

def decrypt_image(inp,outp):
    b=json.load(open(inp)); key=base64.b64decode(b['k']); nonce=base64.b64decode(b['n']); tag=base64.b64decode(b['t']); ct=base64.b64decode(b['c'])
    c=AES.new(key,AES.MODE_GCM,nonce=nonce); data=c.decrypt_and_verify(ct,tag)
    open(outp,'wb').write(data); print(f'Decrypted {inp} -> {outp}')

if __name__=='__main__':
    if len(sys.argv)<4: print('Usage: python q43.py <encrypt|decrypt> <in> <out>')
    else:
        a=sys.argv[1]
        if a=='encrypt': encrypt_image(sys.argv[2], sys.argv[3])
        elif a=='decrypt': decrypt_image(sys.argv[2], sys.argv[3])
        else: print('Action must be encrypt or decrypt')
