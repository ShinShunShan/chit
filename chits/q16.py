"""Q16: Password protection demo using PBKDF2-HMAC-SHA1 (CLI, stdlib only).

This is similar to Q13 but intentionally uses SHA-1 per requirement.
IMPORTANT: SHA-1 is considered WEAK for password storage today; modern
systems prefer PBKDF2-HMAC-SHA256, bcrypt, scrypt, or Argon2. We use it
here only because the exercise explicitly requests SHA-1.

Functions:
  register <user> <password>  - store salted PBKDF2-SHA1 hash
  login    <user> <password>  - verify with constant-time compare
  show                         - display stored hashes (educational)

Usage examples:
  python q16.py register alice MyPassword1
  python q16.py login alice MyPassword1
  python q16.py show
"""

import sys, os, time, hashlib, hmac, json

USERS = {}  # user -> (iter, salt_hex, hash_hex)
DB_PATH = os.path.join(os.path.dirname(__file__), 'q16_users.json')
ITER = 150_000  # Fewer iterations for speed in demo; real systems can use >200k
ATTEMPTS = {}  # user -> timestamps
LOCK_WINDOW = 60
MAX_ATTEMPTS = 5


def strong(p: str) -> bool:
	return (
		len(p) >= 8 and any(c.isupper() for c in p)
		and any(c.islower() for c in p) and any(c.isdigit() for c in p)
	)


def store(pw: str):
	salt = os.urandom(16)
	dk = hashlib.pbkdf2_hmac('sha1', pw.encode(), salt, ITER)
	return ITER, salt.hex(), dk.hex()


def verify(rec, pw: str) -> bool:
	it, salt_hex, hash_hex = rec
	salt = bytes.fromhex(salt_hex)
	target = bytes.fromhex(hash_hex)
	dk = hashlib.pbkdf2_hmac('sha1', pw.encode(), salt, it)
	return hmac.compare_digest(dk, target)


def rate_limited(user: str) -> bool:
	now = time.time()
	arr = ATTEMPTS.get(user, [])
	arr = [t for t in arr if now - t < LOCK_WINDOW]
	ATTEMPTS[user] = arr
	return len(arr) >= MAX_ATTEMPTS


def record(user: str):
	ATTEMPTS.setdefault(user, []).append(time.time())


def cmd_register(u: str, p: str):
	load_users()
	if u in USERS:
		print('User exists'); return
	if not strong(p):
		print('Weak password: need upper, lower, digit, >=8'); return
	USERS[u] = store(p)
	save_users()
	print('Registered')


def cmd_login(u: str, p: str):
	load_users()
	if rate_limited(u):
		print('Too many attempts; wait'); return
	record(u)
	rec = USERS.get(u)
	if rec and verify(rec, p):
		print('Login OK')
	else:
		print('Invalid credentials')


def cmd_show():
	load_users()
	for u, (it, s, h) in USERS.items():
		print(f'{u}: iter={it} salt={s} hash={h}')


def load_users():
	global USERS
	try:
		with open(DB_PATH,'r') as f:
			USERS = {k: tuple(v) for k,v in json.load(f).items()}
	except FileNotFoundError:
		USERS = {}


def save_users():
	with open(DB_PATH,'w') as f:
		json.dump(USERS, f)


def main():
	if len(sys.argv) < 2:
		print('Usage:')
		print('  python q16.py register <user> <password>')
		print('  python q16.py login <user> <password>')
		print('  python q16.py show')
		return
	cmd = sys.argv[1]
	if cmd == 'register' and len(sys.argv) >= 4:
		cmd_register(sys.argv[2], sys.argv[3])
	elif cmd == 'login' and len(sys.argv) >= 4:
		cmd_login(sys.argv[2], sys.argv[3])
	elif cmd == 'show':
		cmd_show()
	else:
		print('Invalid usage')


if __name__ == '__main__':
	main()
