"""Q13: Simple website with password protection techniques to resist password cracking.
Features:
- User registration with PBKDF2-HMAC-SHA256 (salted, many iterations)
- Login verification with constant-time compare
- Basic password policy checks
- Simple per-IP rate limiting (in-memory)
This is a teaching demo, not production!
Run:
  python q13.py
Open http://127.0.0.1:5000
"""
from flask import Flask, request, redirect, render_template_string, session
import os, time, hashlib, hmac
from collections import defaultdict

app = Flask(__name__)
app.secret_key = os.urandom(16)

# In-memory "database"
USERS = {}  # username -> (iterations, salt_hex, hash_hex)
ATTEMPTS = defaultdict(list)  # ip -> timestamps of login attempts

ITER = 200_000
LOCK_WINDOW = 60  # seconds
MAX_ATTEMPTS = 5

PAGE = """
<h2>{{ title }}</h2>
{% if msg %}<p style='color:{{ 'green' if ok else 'red' }};'>{{ msg }}</p>{% endif %}
<form method="post">
  <label>Username: <input name="u"></label><br>
  <label>Password: <input name="p" type="password"></label><br>
  <button type="submit">Submit</button>
</form>
<p><a href="/register">Register</a> | <a href="/login">Login</a> | <a href="/">Home</a></p>
"""

HOME = """
<h2>Home</h2>
<p>Simple password protection demo.</p>
<ul>
<li><a href="/register">Register</a></li>
<li><a href="/login">Login</a></li>
</ul>
{% if 'user' in session %}
<p>Logged in as: {{ session['user'] }}</p>
{% endif %}
"""

def strong_password(p: str) -> bool:
    if len(p) < 8: return False
    has_upper = any(c.isupper() for c in p)
    has_lower = any(c.islower() for c in p)
    has_digit = any(c.isdigit() for c in p)
    return has_upper and has_lower and has_digit


def store_password(password: str):
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, ITER)
    return ITER, salt.hex(), dk.hex()


def verify(stored, password: str) -> bool:
    it, salt_hex, hash_hex = stored
    salt = bytes.fromhex(salt_hex)
    expected = bytes.fromhex(hash_hex)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, it)
    # Constant-time compare
    return hmac.compare_digest(dk, expected)


def rate_limited(ip: str) -> bool:
    now = time.time()
    # Keep only attempts within window
    ATTEMPTS[ip] = [t for t in ATTEMPTS[ip] if now - t < LOCK_WINDOW]
    return len(ATTEMPTS[ip]) >= MAX_ATTEMPTS


def record_attempt(ip: str):
    ATTEMPTS[ip].append(time.time())

@app.route('/')
def home():
    return render_template_string(HOME)

@app.route('/register', methods=['GET','POST'])
def register():
    msg = None; ok = False
    if request.method == 'POST':
        u = request.form.get('u','').strip()
        p = request.form.get('p','')
        if not u or not p:
            msg = 'Please enter username and password.'
        elif not strong_password(p):
            msg = 'Password must be >=8 chars with upper, lower, digit.'
        elif u in USERS:
            msg = 'User exists.'
        else:
            USERS[u] = store_password(p)
            msg = 'Registered successfully.'; ok = True
    return render_template_string(PAGE, title='Register', msg=msg, ok=ok)

@app.route('/login', methods=['GET','POST'])
def login():
    msg = None; ok = False
    ip = request.remote_addr or 'local'
    if request.method == 'POST':
        if rate_limited(ip):
            msg = 'Too many attempts. Try again later.'
        else:
            u = request.form.get('u','').strip()
            p = request.form.get('p','')
            record_attempt(ip)
            stored = USERS.get(u)
            if stored and verify(stored, p):
                session['user'] = u
                msg = 'Login successful.'; ok = True
            else:
                msg = 'Invalid credentials.'
    return render_template_string(PAGE, title='Login', msg=msg, ok=ok)

if __name__ == '__main__':
    app.run()
