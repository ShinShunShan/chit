"""Q8: SHA-1 hashing demo.

Provides integrity digests for a string or file.
Why streaming for files: avoids loading entire large file into RAM.
Security note: SHA-1 collisions exist; use SHA-256 in real systems.
Usage:
    python q08.py message "Hello"
    python q08.py file path/to/file
"""
import sys, hashlib

def hash_message(msg: str) -> str:
    """Return SHA-1 hex digest of a UTF-8 message."""
    return hashlib.sha1(msg.encode()).hexdigest()

def hash_file(path: str) -> str:
    """Return SHA-1 hex digest of file contents using 4KB chunks."""
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
