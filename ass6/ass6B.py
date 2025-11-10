
"""ass6B.py: Toy RSA + signature demo with simple TCP sender/receiver modes.

Fixed & simplified:
 - User supplies primes p and q (tiny for demo) and optional exponent e.
 - Uses SHA-1 (per project requirement) not SHA-256.
 - Proper RSA signature: sig = H(message)^d mod n, verify by pow(sig, e, n).
 - Does NOT transmit private key d (original insecure sample did!).
 - Clean separation of roles: run receiver first, then sender.

Usage:
  Receiver: python ass6B.py receiver [port]
  Sender:   python ass6B.py sender [host] [port]

Example (two terminals):
  python ass6B.py receiver 5000
  python ass6B.py sender localhost 5000

Educational only: DO NOT use for real security.
"""
import sys, socket, hashlib, random

# ---------- Math helpers ----------
def egcd(a: int, b: int):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1

def mod_inverse(a: int, m: int) -> int:
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError('No modular inverse')
    return x % m

def is_probable_prime(n: int) -> bool:
    if n < 2: return False
    small = [2,3,5,7,11,13,17,19,23,29]
    for p in small:
        if n == p: return True
        if n % p == 0: return n == p
    # 3 rounds Miller-Rabin (overkill for tiny demo primes)
    d = n - 1; s = 0
    while d % 2 == 0:
        d //= 2; s += 1
    for a in [2,325,9375]:  # tiny deterministic set for <2^32 not strictly needed here
        a %= n
        if a in (0,1):
            continue
        x = pow(a, d, n)
        if x in (1, n-1):
            continue
        for _ in range(s-1):
            x = pow(x, 2, n)
            if x == n-1:
                break
        else:
            return False
    return True

# ---------- Hash / signature ----------
def sha1_int(message: str) -> int:
    h = hashlib.sha1(message.encode('utf-8')).digest()
    return int.from_bytes(h, 'big')

# ---------- Key generation ----------
def generate_keys(p: int, q: int, e: int | None = None):
    if not (is_probable_prime(p) and is_probable_prime(q)):
        raise ValueError('p and q must be prime')
    if p == q:
        raise ValueError('p and q must differ')
    n = p * q
    phi = (p - 1) * (q - 1)
    if e is None:
        # choose small e typical 65537 if coprime
        candidate = 65537
        if phi % candidate != 0:
            e = candidate
        else:
            # fallback find first odd coprime > 3
            e = 3
            while egcd(e, phi)[0] != 1:
                e += 2
    else:
        if egcd(e, phi)[0] != 1:
            raise ValueError('e not coprime with phi')
    d = mod_inverse(e, phi)
    return (n, e, d)

# ---------- RSA core ----------
def rsa_encrypt_int(m: int, e: int, n: int) -> int:
    return pow(m, e, n)

def rsa_decrypt_int(c: int, d: int, n: int) -> int:
    return pow(c, d, n)

def sign(message: str, d: int, n: int) -> int:
    h_int = sha1_int(message) % n
    return pow(h_int, d, n)

def verify(message: str, sig: int, e: int, n: int) -> bool:
    h_int = sha1_int(message) % n
    recovered = pow(sig, e, n)
    return recovered == h_int

# ---------- Networking helpers ----------
def recv_line(conn) -> str:
    data = b''
    while not data.endswith(b'\n'):
        chunk = conn.recv(1)
        if not chunk:
            break
        data += chunk
    return data.decode().strip()

# ---------- Modes ----------
def run_receiver(port: int):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(('', port))
        server.listen(1)
        print(f'[Receiver] Listening on port {port} ...')
        conn, addr = server.accept()
        with conn:
            print(f'[Receiver] Connection from {addr}')
            e = int(recv_line(conn))
            n = int(recv_line(conn))
            sig = int(recv_line(conn))
            length = int(recv_line(conn))
            cipher_vals = [int(recv_line(conn)) for _ in range(length)]
            # For demo we brute-force decrypt using that sender used per-char encryption with public key e (so actually encryption step is same as signature exponent). We cannot decrypt without private key, so we expect sender to send plaintext too OR design difference.
            # Simpler: treat cipher list as m^e mod n with e public; we cannot invert. Instead modify design: send plaintext length & plaintext directly (educational) so verification is meaningful.
            # To keep backward compatibility: attempt to recover plaintext assuming ciphertext were encrypted with e and we *do not* have d => can't decrypt. We'll just display raw ints.
            print(f'[Receiver] Cipher integers: {cipher_vals}')
            # Ask sender to also send plaintext (already hashed in signature). Try reading optional plaintext line.
            try:
                maybe_plain = recv_line(conn)
                if maybe_plain:
                    plaintext = maybe_plain
                    print(f'[Receiver] Plaintext (sent): {plaintext}')
                else:
                    plaintext = ''
            except Exception:
                plaintext = ''
            if plaintext:
                ok = verify(plaintext, sig, e, n)
                print(f'[Receiver] Signature valid? {ok}')
                resp = ('Signature Verified' if ok else 'Signature Invalid') + '\n'
            else:
                resp = 'No plaintext provided; cannot verify.\n'
            conn.sendall(resp.encode())

def run_sender(host: str, port: int):
    print('[Sender] Enter small primes (e.g. 13 17). For real RSA they must be large.')
    p = int(input('p: ').strip())
    q = int(input('q: ').strip())
    e_in = input('e (blank for default 65537): ').strip()
    e_val = int(e_in) if e_in else None
    n, e, d = None, None, None
    try:
        n, e, d = generate_keys(p, q, e_val)
    except ValueError as ex:
        print('Key generation error:', ex)
        return
    print(f'[Sender] Public key (e={e}, n={n})')
    print(f'[Sender] Private key d={d} (keep secret)')
    msg = input('Message: ')
    # Per-char encryption (toy)
    cipher_vals = [rsa_encrypt_int(ord(ch), e, n) for ch in msg]
    sig = sign(msg, d, n)
    print(f'[Sender] SHA-1 signature integer: {sig}')
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            out = s.makefile('w')
            # Send: e, n, signature, length, cipher list, plaintext (for verification)
            out.write(f'{e}\n{n}\n{sig}\n{len(cipher_vals)}\n')
            for v in cipher_vals:
                out.write(f'{v}\n')
            out.write(msg + '\n')
            out.flush()
            resp = s.makefile('r').readline().strip()
            print('[Sender] Receiver response:', resp)
    except ConnectionRefusedError:
        print('[Sender] Could not connect; is receiver running?')

def usage():
    print('Usage:')
    print('  python ass6B.py receiver [port]')
    print('  python ass6B.py sender <host> <port>')
    print('  python ass6B.py menu  # interactive selection')

def interactive_menu():
    """Interactive mode selection instead of command-line arguments.
    Lets the user choose sender or receiver and provide required inputs.
    """
    while True:
        print('\n=== RSA Demo Menu ===')
        print('1. Receiver (listen)')
        print('2. Sender (connect & send)')
        print('q. Quit')
        choice = input('Select: ').strip().lower()
        if choice == '1':
            port_in = input('Port to listen on [5000]: ').strip()
            port = int(port_in) if port_in.isdigit() else 5000
            run_receiver(port)
        elif choice == '2':
            host = input('Host [localhost]: ').strip() or 'localhost'
            port_in = input('Port [5000]: ').strip()
            port = int(port_in) if port_in.isdigit() else 5000
            run_sender(host, port)
        elif choice == 'q':
            print('Bye.')
            break
        else:
            print('Invalid selection.')

if __name__ == '__main__':
    if len(sys.argv) < 2:
        interactive_menu()
    else:
        mode = sys.argv[1].lower()
        if mode == 'receiver':
            port = int(sys.argv[2]) if len(sys.argv) >= 3 else 5000
            run_receiver(port)
        elif mode == 'sender':
            if len(sys.argv) < 4:
                usage()
            else:
                run_sender(sys.argv[2], int(sys.argv[3]))
        elif mode == 'menu':
            interactive_menu()
        else:
            usage()
