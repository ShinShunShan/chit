"""Q44: Custom encryption/decryption algorithm (standalone, educational).
Scheme: XOR with repeating key then rotate left per byte.
Usage:
  python q44.py encrypt "Hello" key
  python q44.py decrypt <hex> key
"""
import sys

def _rotl(b): return ((b<<1)&0xFF)|(b>>7)

def _rotr(b): return ((b>>1)&0x7F)|((b&1)<<7)

def encrypt(msg,key)->bytes:
    data=msg.encode(); k=key.encode() or b'0'; out=bytearray()
    for i,byte in enumerate(data): out.append(_rotl(byte ^ k[i%len(k)]))
    return bytes(out)

def decrypt(hexdata,key)->str:
    c=bytes.fromhex(hexdata); k=key.encode() or b'0'; out=bytearray()
    for i,byte in enumerate(c): out.append((_rotr(byte)) ^ k[i%len(k)])
    return bytes(out).decode()

if __name__=='__main__':
    if len(sys.argv)<3:
        print('Usage encrypt: python q44.py encrypt <message> <key>')
        print('Usage decrypt: python q44.py decrypt <hex> <key>')
    else:
        a=sys.argv[1]
        if a=='encrypt' and len(sys.argv)>=4: print(encrypt(sys.argv[2], sys.argv[3]).hex())
        elif a=='decrypt' and len(sys.argv)>=4: print(decrypt(sys.argv[2], sys.argv[3]))
        else: print('Invalid usage')
