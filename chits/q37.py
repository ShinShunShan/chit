"""Q37: Website password protection demo (standalone).
Features:
  - Registration with PBKDF2-HMAC-SHA256
  - Password policy
  - Rate limiting
Run:
  python q37.py
Open http://127.0.0.1:5004
"""
from flask import Flask, request, render_template_string, session
import os, time, hashlib, hmac
from collections import defaultdict

app = Flask(__name__)
app.secret_key = os.urandom(16)
USERS = {}
ATTEMPTS = defaultdict(list)
ITER=180_000; WINDOW=60; MAX_ATTEMPTS=5

PAGE="""<h2>{{ title }}</h2>
{% if msg %}<p style='color:{{ 'green' if ok else 'red' }};'>{{ msg }}</p>{% endif %}
<form method=post>
<input name=u placeholder=User><br>
<input name=p type=password placeholder=Password><br>
<button>Submit</button>
</form>
<p><a href=/register>Register</a> | <a href=/login>Login</a> | <a href=/>Home</a></p>"""
HOME="""<h2>Home</h2><p>Password demo.</p><ul><li><a href=/register>Register</a></li><li><a href=/login>Login</a></li></ul>{% if 'user' in session %}<p>Logged in: {{ session['user'] }}</p>{% endif %}"""

def strong(p):
    return len(p)>=8 and any(c.isupper() for c in p) and any(c.islower() for c in p) and any(c.isdigit() for c in p)

def store(p):
    s=os.urandom(16); h=hashlib.pbkdf2_hmac('sha256', p.encode(), s, ITER)
    return ITER, s.hex(), h.hex()

def verify(rec,p):
    it,s_hex,h_hex=rec; s=bytes.fromhex(s_hex); h_expected=bytes.fromhex(h_hex)
    h=hashlib.pbkdf2_hmac('sha256', p.encode(), s, it)
    return hmac.compare_digest(h,h_expected)

def limited(ip):
    now=time.time(); ATTEMPTS[ip]=[t for t in ATTEMPTS[ip] if now-t<WINDOW]; return len(ATTEMPTS[ip])>=MAX_ATTEMPTS

def record(ip): ATTEMPTS[ip].append(time.time())

@app.route('/')
def home(): return render_template_string(HOME)

@app.route('/register', methods=['GET','POST'])
def register():
    msg=None; ok=False
    if request.method=='POST':
        u=request.form.get('u','').strip(); p=request.form.get('p','')
        if not u or not p: msg='Missing';
        elif u in USERS: msg='Exists'
        elif not strong(p): msg='Weak password'
        else: USERS[u]=store(p); msg='Registered'; ok=True
    return render_template_string(PAGE, title='Register', msg=msg, ok=ok)

@app.route('/login', methods=['GET','POST'])
def login():
    msg=None; ok=False; ip=request.remote_addr or 'local'
    if request.method=='POST':
        if limited(ip): msg='Too many attempts'
        else:
            u=request.form.get('u','').strip(); p=request.form.get('p',''); record(ip)
            if u in USERS and verify(USERS[u],p): session['user']=u; msg='Login OK'; ok=True
            else: msg='Bad credentials'
    return render_template_string(PAGE, title='Login', msg=msg, ok=ok)

if __name__=='__main__': app.run(port=5004)
