"""Q9: SHA-1 hashing demo (message or file).
Usage:
  python q09.py message "Hello"
  python q09.py file path/to/file
"""
import sys, hashlib

def hash_message(msg: str) -> str:
    return hashlib.sha1(msg.encode()).hexdigest()

def hash_file(path: str) -> str:
    h = hashlib.sha1()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            h.update(chunk)
    return h.hexdigest()

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python q09.py <message|file> <data>")
    else:
        kind = sys.argv[1]
        if kind == 'message':
            print(hash_message(sys.argv[2]))
        elif kind == 'file':
            print(hash_file(sys.argv[2]))
        else:
            print("First arg must be message or file")
