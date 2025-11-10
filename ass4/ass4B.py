import secrets
import hashlib

# --- Parameters (toy example) ---
P = 23
G = 5


# --- Utilities ---------------------------------------------------------
def random_private():
    """
    Produce a random private in the range [2, P-1] using same approach as Java:
    Java used max = P-3, generate rnd in [0..max] then add 2 to get [2..P-1].
    We'll mirror that behaviour.
    """
    max_val = P - 3
    if max_val <= 0:
        # fallback for very small P
        return 2
    bitlen = max_val.bit_length()
    while True:
        rnd = secrets.randbits(bitlen)
        if 1 < rnd <= max_val:
            return rnd + 2


def mod_exp(base: int, exp: int) -> int:
    """Compute base^exp mod P."""
    return pow(base, exp, P)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def key_from_shared(shared: int) -> int:
    """
    Hash the shared secret's decimal string with SHA-256,
    take the first 4 bytes as big-endian integer (same effect as
    building with shifts & masking in Java), return that int.
    """
    h = sha256(str(shared).encode())
    k = 0
    for i in range(4):
        k = (k << 8) | (h[i] & 0xFF)
    return k


def char_key(session_key: int, pos: int) -> int:
    """
    Derive a small per-character key value (0..25) from the integer session key and position.
    Mirrors Java's shift & masking:
      shift = (pos * 7) % 32
      v = (sessionKey >>> shift) & 0x1F
      return v % 26
    """
    shift = (pos * 7) % 32
    v = (session_key >> shift) & 0x1F  # 0..31
    return v % 26  # 0..25


# --- Entities ----------------------------------------------------------
class Participant:
    def __init__(self, name: str):
        self.name = name
        self.priv = None
        self.pub = None
        self.shared = None

    def generate_keys(self):
        self.priv = random_private()
        self.pub = mod_exp(G, self.priv)

    def compute_shared(self, other_pub: int):
        self.shared = mod_exp(other_pub, self.priv)

    def session_key_int(self) -> int:
        if self.shared is None:
            raise RuntimeError("Shared not computed")
        return key_from_shared(self.shared)


class Mallory:
    def __init__(self):
        # Link A is used when Mallory talks to Bob (i.e. Mallory sends pubA to Bob)
        # Link B is used when Mallory talks to Alice (i.e. Mallory sends pubB to Alice)
        self.privA = None
        self.pubA = None
        self.sharedA = None

        self.privB = None
        self.pubB = None
        self.sharedB = None

    def generate_keys_for_links(self):
        self.privA = random_private()
        self.pubA = mod_exp(G, self.privA)
        self.privB = random_private()
        self.pubB = mod_exp(G, self.privB)

    def compute_shared_with_alice(self, alice_pub: int):
        # alice_pub = g^a; Mallory uses privB so sharedA = (g^a)^{privB}
        self.sharedA = mod_exp(alice_pub, self.privB)

    def compute_shared_with_bob(self, bob_pub: int):
        # bob_pub = g^b; Mallory uses privA so sharedB = (g^b)^{privA}
        self.sharedB = mod_exp(bob_pub, self.privA)

    def session_key_int_for_alice(self) -> int:
        return key_from_shared(self.sharedA)

    def session_key_int_for_bob(self) -> int:
        return key_from_shared(self.sharedB)


# --- Letter-based encryption/decryption -------------------------------

def sanitize_letters(s: str) -> str:
    """Keep only A-Z and convert to uppercase."""
    return ''.join(ch for ch in s.upper() if 'A' <= ch <= 'Z')


def encrypt_letters(plain: str, session_key: int) -> str:
    """
    Encrypt letters -> ciphertext letters (A-Z)
    For each position:
      orig = plain[i] - 'A'           # 0..25
      k = charKey(sessionKey, i)     # 0..25
      xorVal = orig ^ k              # 0..31
      encVal = xorVal mod 26         # normalize to 0..25
      ciphertext char = encVal + 'A'
    """
    out = []
    for i, ch in enumerate(plain):
        orig = ord(ch) - ord('A')
        k = char_key(session_key, i)
        xor_val = orig ^ k
        enc_val = xor_val % 26
        out.append(chr(enc_val + ord('A')))
    return ''.join(out)


def decrypt_letters(cipher: str, session_key: int) -> str:
    """
    Decrypt ciphertext letters -> recover plaintext letters.
    For each ciphertext char encVal (0..25):
      brute-force val in 0..25 such that (val ^ k) mod 26 == encVal
    """
    out = []
    for i, ch in enumerate(cipher):
        enc_val = ord(ch) - ord('A')
        k = char_key(session_key, i)
        recovered = -1
        for val in range(26):
            xor_val = val ^ k
            if xor_val % 26 == enc_val:
                recovered = val
                break
        if recovered == -1:
            recovered = 0  # fallback; should not happen with correct algebra
        out.append(chr(recovered + ord('A')))
    return ''.join(out)


# --- Demo --------------------------------------------------------------
def main():
    print("=== Diffie-Hellman MITM Demo (Letters A-Z) — FIXED ===")
    print(f"Toy DH params: p = {P}, g = {G}\n")

    user_input = input("Enter plaintext (will be sanitized to A-Z only): ")
    plaintext = sanitize_letters(user_input)
    if not plaintext:
        print("No letters in input. Exiting.")
        return

    alice = Participant("Alice")
    bob = Participant("Bob")
    mallory = Mallory()

    # generate keys
    alice.generate_keys()
    bob.generate_keys()
    mallory.generate_keys_for_links()

    print("\nAlice pub: {}".format(alice.pub))
    print("Bob   pub: {}".format(bob.pub))
    print("Mallory pub_for_A (sent to Bob): {}".format(mallory.pubA))
    print("Mallory pub_for_B (sent to Alice): {}\n".format(mallory.pubB))

    # --- MITM substitution with correct mapping ---
    # Alice thinks she received Bob.pub but Mallory sent pubB
    alice.compute_shared(mallory.pubB)
    # Mallory must compute sharedA using privB to match Alice.shared
    mallory.compute_shared_with_alice(alice.pub)

    # Bob thinks he received Alice.pub but Mallory sent pubA
    bob.compute_shared(mallory.pubA)
    # Mallory must compute sharedB using privA to match Bob.shared
    mallory.compute_shared_with_bob(bob.pub)

    # DEBUG: show shared secrets and verify equality of pairs
    print("Alice computed shared (A <-> Mallory): {}".format(alice.shared))
    print("Mallory shared with Alice:            {}".format(mallory.sharedA))
    print("Bob computed shared   (B <-> Mallory): {}".format(bob.shared))
    print("Mallory shared with Bob:              {}\n".format(mallory.sharedB))

    # derive session keys
    a_key = alice.session_key_int()
    mA_key = mallory.session_key_int_for_alice()
    b_key = bob.session_key_int()
    mB_key = mallory.session_key_int_for_bob()

    print("Session keys (ints):")
    print(" Alice key:       {}".format(a_key))
    print(" Mallory->Alice:  {}".format(mA_key))
    print(" Bob   key:       {}".format(b_key))
    print(" Mallory->Bob:    {}\n".format(mB_key))

    # Alice encrypts (letters-only) using her key
    cipher_from_alice = encrypt_letters(plaintext, a_key)
    print("Plaintext (sanitized): {}".format(plaintext))
    print("Alice -> Ciphertext (A-Z): {}".format(cipher_from_alice))

    # Mallory intercepts and decrypts using her key with Alice
    mallory_reads = decrypt_letters(cipher_from_alice, mA_key)
    print("Mallory decrypts (reads): {}".format(mallory_reads))

    # Mallory modifies the message: change the first letter (A->B, Z->A)
    modified = mallory_reads
    if modified:
        arr = list(modified)
        arr[0] = chr(((ord(arr[0]) - ord('A') + 1) % 26) + ord('A'))
        modified = ''.join(arr)
    print("Mallory modifies to: {}".format(modified))

    # Mallory re-encrypts using her key with Bob and forwards
    cipher_to_bob = encrypt_letters(modified, mB_key)
    print("Mallory -> Ciphertext to Bob (A-Z): {}".format(cipher_to_bob))

    # Bob decrypts using his key
    bob_receives = decrypt_letters(cipher_to_bob, b_key)
    print("Bob receives (decrypted): {}".format(bob_receives))

    print("\nConclusion: Mallory read & modified the message (DH without auth is vulnerable).")

if __name__ == "__main__":
    main()