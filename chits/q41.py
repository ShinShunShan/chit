"""Q41: SHA-1 hashing demonstration (message or file) — standalone.

Concepts
- A cryptographic hash maps arbitrary data to a fixed-size digest (here 160 bits).
- Intended properties: preimage resistance, second preimage resistance, collision resistance.
- SHA-1 collisions are practical today; use SHA-256/512 for security. Here for learning only.

Usage:
    python q41.py message "Hello"
    python q41.py file path/to/file
"""
import sys, hashlib

def h_msg(m: str) -> str:
    """Hash a UTF-8 string and return hex digest."""
    return hashlib.sha1(m.encode()).hexdigest()

def h_file(p: str) -> str:
    """Stream a file in 4KB chunks to avoid loading huge files into memory."""
    h = hashlib.sha1()
    with open(p, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            h.update(chunk)
    return h.hexdigest()

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('Usage: python q41.py <message|file> <data>')
    else:
        kind = sys.argv[1]
        if kind == 'message':
            print(h_msg(sys.argv[2]))
        elif kind == 'file':
            print(h_file(sys.argv[2]))
        else:
            print('First arg must be message or file')
