"""SHA-1 hashing demo (expanded explanation).

This file was previously empty; now it provides helper functions to:
- Hash a message string.
- Hash a file in streaming mode.
- Show internal block/length padding intuition (high-level).

Educational points:
1. Padding: append 0x80, then 0x00 bytes until length ≡ 56 (mod 64), then 64-bit length.
2. Processing: 512-bit blocks expand into 80 message schedule words.
3. Compression: mixes five 32-bit state words (A..E) per round.
4. Output: 160-bit digest (five 32-bit words concatenated).

WARNING: SHA-1 is deprecated for collision-sensitive use. Prefer SHA-256.

Usage:
  python sha1_demo.py message "Hello"
  python sha1_demo.py file path/to/file
"""
import sys, hashlib


def sha1_message(m: str) -> str:
	"""Return SHA-1 hex digest of a UTF-8 string."""
	return hashlib.sha1(m.encode()).hexdigest()


def sha1_file(path: str) -> str:
	"""Return SHA-1 hex digest of file contents using streaming updates."""
	h = hashlib.sha1()
	with open(path, 'rb') as f:
		for chunk in iter(lambda: f.read(8192), b''):
			h.update(chunk)
	return h.hexdigest()


def main():
	if len(sys.argv) < 3:
		print("Usage: python sha1_demo.py <message|file> <data>")
		return
	kind = sys.argv[1].lower()
	target = sys.argv[2]
	if kind == 'message':
		print(sha1_message(target))
	elif kind == 'file':
		print(sha1_file(target))
	else:
		print("First argument must be 'message' or 'file'")


if __name__ == '__main__':
	main()
