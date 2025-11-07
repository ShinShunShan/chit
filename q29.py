<<<<<<< HEAD
"""Q29: SHA-1 hashing demonstration (message or file) — standalone.
Usage:
  python q29.py message "Hello"
  python q29.py file path/to/file
"""
=======
"""Q29: SHA-1 hashing demonstration (message or file)."""
>>>>>>> 5c2263d (Add q25-q32 scripts (website security, DH MITM, image AES-GCM, SHA-1, RSA timing, custom cipher))
import sys, hashlib

def h_msg(m:str)->str: return hashlib.sha1(m.encode()).hexdigest()

def h_file(p:str)->str:
<<<<<<< HEAD
    h=hashlib.sha1()
=======
    h=hashlib.sha1();
>>>>>>> 5c2263d (Add q25-q32 scripts (website security, DH MITM, image AES-GCM, SHA-1, RSA timing, custom cipher))
    with open(p,'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''): h.update(chunk)
    return h.hexdigest()

if __name__=='__main__':
    if len(sys.argv)<3:
        print('Usage: python q29.py <message|file> <data>')
    else:
        kind=sys.argv[1]
        if kind=='message': print(h_msg(sys.argv[2]))
        elif kind=='file': print(h_file(sys.argv[2]))
        else: print('First arg must be message or file')
