"""Q25: Password protection (CLI, PBKDF2-HMAC-SHA1, stdlib-only).

Educational only. Uses JSON file q25_users.json for persistence across runs.
Usage:
  python q25.py register alice MyPassword1
  python q25.py login    alice MyPassword1
  python q25.py show
"""
import os, sys, json, time, hashlib, hmac

DB = os.path.join(os.path.dirname(__file__), 'q25_users.json')
USERS = {}
ITER = 150_000
ATT = {}
WIN = 60
MAXA = 5

def strong(p: str) -> bool:
    return len(p) >= 8 and any(c.isupper() for c in p) and any(c.islower() for c in p) and any(c.isdigit() for c in p)

def load():
    global USERS
    try:
        USERS = {k: tuple(v) for k,v in json.load(open(DB,'r')).items()}
    except FileNotFoundError:
        USERS = {}

def save():
    json.dump(USERS, open(DB,'w'))

def store(pw: str):
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha1', pw.encode(), salt, ITER)
    return ITER, salt.hex(), dk.hex()

def verify(rec, pw: str) -> bool:
    it, s_hex, h_hex = rec
    salt = bytes.fromhex(s_hex)
    want = bytes.fromhex(h_hex)
    got = hashlib.pbkdf2_hmac('sha1', pw.encode(), salt, it)
    return hmac.compare_digest(got, want)

def rl(user: str) -> bool:
    now = time.time(); arr = ATT.get(user, [])
    arr = [t for t in arr if now - t < WIN]; ATT[user] = arr
    return len(arr) >= MAXA

def rec(user: str):
    ATT.setdefault(user, []).append(time.time())

def cmd_register(u: str, p: str):
    load()
    if u in USERS: print('User exists'); return
    if not strong(p): print('Weak password'); return
    USERS[u] = store(p); save(); print('Registered')

def cmd_login(u: str, p: str):
    load()
    if rl(u): print('Too many attempts; wait'); return
    rec(u)
    if u in USERS and verify(USERS[u], p): print('Login OK')
    else: print('Invalid credentials')

def cmd_show():
    load()
    for u, (it,s,h) in USERS.items(): print(f'{u}: iter={it} salt={s} hash={h}')

if __name__=='__main__':
    if len(sys.argv) < 2:
        print('Usage:')
        print('  python q25.py register <user> <password>')
        print('  python q25.py login <user> <password>')
        print('  python q25.py show')
    else:
        cmd=sys.argv[1]
        if cmd=='register' and len(sys.argv)>=4: cmd_register(sys.argv[2], sys.argv[3])
        elif cmd=='login' and len(sys.argv)>=4: cmd_login(sys.argv[2], sys.argv[3])
        elif cmd=='show': cmd_show()
        else: print('Invalid usage')
