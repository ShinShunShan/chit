"""Q8: SHA-1 hashing demo.
Compute SHA-1 of a message or file.
Usage:
  python q08.py message "Hello"
  python q08.py file path/to/file
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
        print("Usage: python q08.py <message|file> <data>")
    else:
        if sys.argv[1] == 'message':
            print(hash_message(sys.argv[2]))
        elif sys.argv[1] == 'file':
            print(hash_file(sys.argv[2]))
        else:
            print("First arg must be message or file")
