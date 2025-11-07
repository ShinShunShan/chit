"""Q21: SHA-1 hashing demonstration (message or file)."""
import sys, hashlib

def h_msg(m:str)->str: return hashlib.sha1(m.encode()).hexdigest()

def h_file(p:str)->str:
    h=hashlib.sha1()
    with open(p,'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''): h.update(chunk)
    return h.hexdigest()

if __name__=='__main__':
    if len(sys.argv)<3:
        print('Usage: python q21.py <message|file> <data>')
    else:
        a=sys.argv[1]
        if a=='message': print(h_msg(sys.argv[2]))
        elif a=='file': print(h_file(sys.argv[2]))
        else: print('First arg must be message or file')
