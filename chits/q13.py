"""Q13: Password protection (CLI version, no external libraries).

This replaces the Flask web app with a simple command-line interface while
demonstrating the same ideas:
- PBKDF2-HMAC-SHA256 with per-user random salt and iterations
- Basic password policy (>=8, upper, lower, digit)
- Simple attempt counter (per-process, just to illustrate rate limiting)

Usage examples:
  python q13.py register alice MyPassword1
  python q13.py login    alice MyPassword1
  python q13.py show
"""

import sys
import os
import time
import hashlib
import hmac


USERS = {}  # username -> (iterations, salt_hex, hash_hex)
ITER = 200_000
ATTEMPTS = {}  # username -> [timestamps]
LOCK_WINDOW = 60
MAX_ATTEMPTS = 5


def strong_password(p: str) -> bool:
    return (
        len(p) >= 8 and any(c.isupper() for c in p)
        and any(c.islower() for c in p) and any(c.isdigit() for c in p)
    )


def store_password(password: str):
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, ITER)
    return ITER, salt.hex(), dk.hex()


def verify(stored, password: str) -> bool:
    it, salt_hex, hash_hex = stored
    salt = bytes.fromhex(salt_hex)
    expected = bytes.fromhex(hash_hex)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, it)
    return hmac.compare_digest(dk, expected)


def rate_limited(user: str) -> bool:
    now = time.time()
    lst = ATTEMPTS.get(user, [])
    lst = [t for t in lst if now - t < LOCK_WINDOW]
    ATTEMPTS[user] = lst
    return len(lst) >= MAX_ATTEMPTS


def record_attempt(user: str):
    ATTEMPTS.setdefault(user, []).append(time.time())


def cmd_register(user: str, password: str):
    if not user or not password:
        print('Provide username and password')
        return
    if user in USERS:
        print('User exists')
        return
    if not strong_password(password):
        print('Weak password: need upper, lower, digit, >=8')
        return
    USERS[user] = store_password(password)
    print('Registered')


def cmd_login(user: str, password: str):
    if rate_limited(user):
        print('Too many attempts; wait')
        return
    record_attempt(user)
    rec = USERS.get(user)
    if rec and verify(rec, password):
        print('Login OK')
    else:
        print('Invalid credentials')


def cmd_show():
    # Show stored users (salt+hash only) to understand representation
    for u, rec in USERS.items():
        it, salt_hex, hash_hex = rec
        print(f"{u}: {it}:{salt_hex}:{hash_hex}")


def main():
    if len(sys.argv) < 2:
        print('Usage:')
        print('  python q13.py register <user> <password>')
        print('  python q13.py login <user> <password>')
        print('  python q13.py show')
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
