"""Q25: Website with password protection techniques to resist password cracking.
Standalone implementation (no imports from other local files).
Features (educational demo only):
  - User registration with PBKDF2-HMAC-SHA256 salted hashing
  - Password policy (>=8 chars, upper, lower, digit)
  - Login with constant-time verification
  - Simple per-IP rate limiting (in-memory)
Run:
  python q25.py
Open http://127.0.0.1:5003
"""
from flask import Flask, request, render_template_string, session
import os, time, hashlib, hmac
from collections import defaultdict

app = Flask(__name__)
app.secret_key = os.urandom(16)

USERS = {}  # username -> (iterations, salt_hex, hash_hex)
ATTEMPTS = defaultdict(list)  # ip -> timestamps

ITER = 200_000
LOCK_WINDOW = 60
MAX_ATTEMPTS = 5

FORM_PAGE = """
<h2>{{ title }}</h2>
{% if msg %}<p style='color:{{ 'green' if ok else 'red' }};'>{{ msg }}</p>{% endif %}
<form method="post">
  <label>User: <input name="u"></label><br>
  <label>Password: <input type="password" name="p"></label><br>
  <button type="submit">Submit</button>
</form>
<p><a href="/register">Register</a> | <a href="/login">Login</a> | <a href="/">Home</a></p>
"""

HOME = """
<h2>Home</h2>
<p>Simple password protection demo.</p>
<ul><li><a href="/register">Register</a></li><li><a href="/login">Login</a></li></ul>
{% if 'user' in session %}<p>Logged in as {{ session['user'] }}</p>{% endif %}
"""

def strong(p: str) -> bool:
    return (len(p) >= 8 and any(c.isupper() for c in p)
            and any(c.islower() for c in p) and any(c.isdigit() for c in p))

def store(password: str):
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, ITER)
    return ITER, salt.hex(), dk.hex()

def verify(stored, password: str) -> bool:
    it, salt_hex, hash_hex = stored
    salt = bytes.fromhex(salt_hex)
    expected = bytes.fromhex(hash_hex)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, it)
    return hmac.compare_digest(dk, expected)

def rate_limited(ip: str) -> bool:
    now = time.time()
    ATTEMPTS[ip] = [t for t in ATTEMPTS[ip] if now - t < LOCK_WINDOW]
    return len(ATTEMPTS[ip]) >= MAX_ATTEMPTS

def record(ip: str):
    ATTEMPTS[ip].append(time.time())

@app.route('/')
def home():
    return render_template_string(HOME)

@app.route('/register', methods=['GET','POST'])
def register():
    msg=None; ok=False
    if request.method == 'POST':
        u=request.form.get('u','').strip(); p=request.form.get('p','')
        if not u or not p: msg='Enter username and password'
        elif u in USERS: msg='User exists'
        elif not strong(p): msg='Weak password: need upper, lower, digit, >=8'
        else:
            USERS[u]=store(p); msg='Registered'; ok=True
    return render_template_string(FORM_PAGE, title='Register', msg=msg, ok=ok)

@app.route('/login', methods=['GET','POST'])
def login():
    msg=None; ok=False; ip=request.remote_addr or 'local'
    if request.method=='POST':
        if rate_limited(ip):
            msg='Too many attempts; wait'
        else:
            u=request.form.get('u','').strip(); p=request.form.get('p',''); record(ip)
            if u in USERS and verify(USERS[u], p):
                session['user']=u; msg='Login OK'; ok=True
            else: msg='Invalid credentials'
    return render_template_string(FORM_PAGE, title='Login', msg=msg, ok=ok)

if __name__=='__main__':
    app.run(port=5003)
