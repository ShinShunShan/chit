"""Q23: Secure messaging (toy RSA + SHA-1 signature, stdlib-only).

Adapted from q11 but uses SHA-1 per requirement (educational; insecure).
Demonstrates:
 - Toy RSA key generation (Miller-Rabin) from q02-like logic
 - Textbook RSA encrypt/decrypt (no padding)
 - Signature = RSA(sign(hash(message))) with SHA-1
"""
import random, hashlib

def is_probable_prime(n: int, k: int = 8) -> bool:
	if n < 2: return False
	small_primes = [2,3,5,7,11,13,17,19,23,29]
	for p in small_primes:
		if n == p: return True
		if n % p == 0: return n == p
	d = n - 1; s = 0
	while d % 2 == 0:
		d //= 2; s += 1
	for _ in range(k):
		a = random.randrange(2, n - 2)
		x = pow(a, d, n)
		if x == 1 or x == n - 1: continue
		for _ in range(s - 1):
			x = pow(x, 2, n)
			if x == n - 1: break
		else:
			return False
	return True

def generate_prime(bits: int) -> int:
	while True:
		candidate = random.getrandbits(bits) | 1 | (1 << (bits - 1))
		if is_probable_prime(candidate): return candidate

def egcd(a: int, b: int):
	if b == 0: return a, 1, 0
	g, x1, y1 = egcd(b, a % b)
	return g, y1, x1 - (a // b) * y1

def modinv(a: int, m: int) -> int:
	g, x, _ = egcd(a, m)
	if g != 1: raise ValueError('No inverse')
	return x % m

def gen_rsa(bits: int = 512):
	e = 65537
	while True:
		p = generate_prime(bits // 2)
		q = generate_prime(bits // 2)
		if p != q:
			phi = (p - 1) * (q - 1)
			if phi % e != 0: break
	n = p * q
	d = modinv(e, phi)
	return (n, e), (n, d)

def rsa_encrypt(m_int: int, pub):
	n, e = pub
	return pow(m_int, e, n)

def rsa_decrypt(c_int: int, priv):
	n, d = priv
	return pow(c_int, d, n)

def sha1_digest(data: bytes) -> int:
	return int.from_bytes(hashlib.sha1(data).digest(), 'big')

def sign(message: bytes, priv):
	h_int = sha1_digest(message)
	return rsa_decrypt(h_int, priv)

def verify(message: bytes, sig: int, pub) -> bool:
	h_int = sha1_digest(message)
	return rsa_encrypt(sig, pub) == h_int

def demo():
	pub_a, priv_a = gen_rsa(512)
	pub_b, priv_b = gen_rsa(512)
	msg = b'HELLO WORLD'
	m_int = int.from_bytes(msg, 'big')
	ct = rsa_encrypt(m_int, pub_b)
	pt_int = rsa_decrypt(ct, priv_b)
	recovered = pt_int.to_bytes((pt_int.bit_length() + 7)//8, 'big')
	sig = sign(msg, priv_a)
	ok = verify(msg, sig, pub_a)
	print('Message:', msg)
	print('Recovered:', recovered)
	print('Recovered OK?', recovered == msg)
	print('Signature OK?', ok)

if __name__=='__main__':
	demo()
