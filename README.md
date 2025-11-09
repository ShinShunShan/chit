# Cryptography Demos: Concepts, Formulas, and Notes

This repository contains beginner-friendly Python demos for classical and modern cryptography. Below are highly detailed notes that explain each concept with formulas, simple intuition, security properties, and the corresponding scripts to try.

Contents
- Classical substitution/transposition ciphers: Caesar, Vigenère (polyalphabetic), Rail Fence
- Vernam Cipher and One-Time Pad (OTP)
- Diffie–Hellman key exchange + Man-in-the-Middle (MITM)
- RSA: key generation, encryption/decryption, signatures, OAEP padding
- Timing experiments for RSA
- Hashing (SHA‑1) and where hashing fits
- Password protection (PBKDF2‑HMAC‑SHA256)
- Symmetric encryption for files/images with AES‑GCM
- Simple educational custom cipher (XOR + rotate)

Each section links to self-contained scripts in `chits/` (q01–q44).

---

## 1) Classical Ciphers

### 1.1 Caesar Cipher (shift cipher)
- Alphabet: map letters A..Z to numbers 0..25.
- Encryption with key k (integer):
  - $$ E_k(x) = (x + k) \bmod 26 $$
- Decryption:
  - $$ D_k(y) = (y - k) \bmod 26 $$
- Security: very weak; only 26 possibilities. Vulnerable to brute force and frequency analysis.
- Scripts: `caesar_cipher.py`, `chits/q01.py`, `chits/q14.py`.

### 1.2 Vigenère Cipher (polyalphabetic substitution)
- Key is a word (e.g., LEMON). Convert letters to shifts: L=11, E=4, M=12, O=14, N=13.
- For plaintext letters $x_i$ and key shifts $k_i$ (repeat the key):
  - $$ E(x_i) = (x_i + k_{i \bmod m}) \bmod 26 $$
  - $$ D(y_i) = (y_i - k_{i \bmod m}) \bmod 26 $$
- Better than Caesar but still weak versus Kasiski/Babbage attacks and IC analysis if long text.
- Scripts: `vigenere_cipher.py`, `chits/q01.py`, `chits/q14.py`, `chits/q36.py`.

### 1.3 Rail Fence Cipher (transposition/zig‑zag)
- Write text diagonally across N rails, then read row by row.
- Example for 3 rails, direction toggles at top/bottom.
- Not a substitution; letters are permuted by a known pattern.
- Weak; undone by reconstructing the zig-zag pattern counts.
- Scripts: `rail_fence_cipher.py`, `chits/q01.py`, `chits/q14.py`, `chits/q19.py`.

---

## 2) Vernam Cipher and One‑Time Pad (OTP)

### 2.1 Vernam Cipher (XOR with same‑length key)
- Represent message and key as bytes of equal length.
- Encryption/Decryption:
  - $$ C = P \oplus K $$
  - $$ P = C \oplus K $$
- Security: depends entirely on key secrecy and non‑reuse.
- Scripts: `vernam_cipher.py`, `chits/q03.py`, `chits/q19.py`, `chits/q36.py`.

### 2.2 One‑Time Pad (OTP)
- Same as Vernam but key $K$ is:
  - Truly random
  - As long as the message
  - Never reused
- Shannon’s perfect secrecy holds if the above conditions are met.
- Scripts: `one_time_pad.py`, `chits/q03.py`, `chits/q19.py`, `chits/q36.py`.

---

## 3) Diffie–Hellman (DH) Key Exchange + MITM

### 3.1 Honest DH
- Public parameters: large prime $p$, generator $g$.
- Alice chooses secret $a$, computes $A = g^a \bmod p$.
- Bob chooses secret $b$, computes $B = g^b \bmod p$.
- Shared secret (both compute):
  - $$ s = g^{ab} \bmod p = B^a \bmod p = A^b \bmod p $$
- Without authentication, DH provides confidentiality (shared secret) but not identity.

### 3.2 MITM Attack
- Attacker Mallory intercepts $A$ and $B$ and replaces them with $M_1=g^{m_1}$ and $M_2=g^{m_2}$.
- Alice’s key: $s_A = M_1^a = g^{m_1 a}$; Bob’s key: $s_B = M_2^b = g^{m_2 b}$.
- Mallory shares keys with both, decrypts/modifies traffic.
- Avoid with authentication (signatures, certificates, PAKE, etc.).
- Scripts: `diffie_hellman_mitm_demo.py`, `chits/q06.py`, `chits/q07.py`, `chits/q20.py`, `chits/q26.py`, `chits/q28.py`.

---

## 4) RSA Public‑Key Cryptography

### 4.1 Key Generation
- Choose distinct large primes $p,q$.
- $$ n = p q,\quad \varphi(n) = (p-1)(q-1) $$
- Choose public exponent $e$ s.t. $\gcd(e,\varphi(n))=1$ (commonly 65537).
- Compute private exponent $d$:
  - $$ d \equiv e^{-1} \pmod{\varphi(n)} $$
- Public key: $(n,e)$; private key: $(n,d)$.

### 4.2 Encryption/Decryption (textbook RSA)
- Encryption:
  - $$ c \equiv m^e \bmod n $$
- Decryption:
  - $$ m \equiv c^d \bmod n $$
- In practice use padding (OAEP) for IND‑CPA security.

### 4.3 RSA‑OAEP (high level)
- Limits per‑block plaintext size to $k - 2hLen - 2$ bytes (k = key size in bytes; hLen = hash output length).
- Encodes $m$ with randomized padding using MGF1 and a seed; resists chosen‑plaintext attacks.
- Construction (simplified):
  1. Let $DB = lHash \| PS \| 0x01 \| m$ where $lHash = H(label)$ and $PS$ is zeros.
  2. Pick random seed of length $hLen$.
  3. $dbMask = MGF1(seed, k - hLen - 1)$; $maskedDB = DB \oplus dbMask$.
  4. $seedMask = MGF1(maskedDB, hLen)$; $maskedSeed = seed \oplus seedMask$.
  5. Encoded message: $EM = 0x00 \| maskedSeed \| maskedDB$; then RSA encrypt $c = EM^e \bmod n$.
  6. Decryption reverses masks and checks structure to detect tampering.
- Our code uses `PKCS1_OAEP` with SHA‑256 (safe default for demos).

### 4.4 RSA Signatures (PKCS#1 v1.5 for demo)
- Signature:
  - $$ s \equiv H(m)^d \bmod n $$
- Verification:
  - $$ H(m) \stackrel{?}{=} s^e \bmod n $$
- Our demo uses `pkcs1_15` over SHA‑256 (simple and common for learning).

### 4.6 Common pitfalls and checks
- Never use textbook RSA without padding.
- Verify signatures over the exact bytes (or a canonical encoding) you intended.
- Reject OAEP decoding if structure checks fail (library does this).
- Choose key sizes ≥2048 bits for modern security.

### 4.5 Timing Experiment
- Measure keygen, encrypt, decrypt vs key size (1024, 2048) and message sizes.
- OAEP block size: $$ \text{max\_block} = k - 2\cdot hLen - 2 $$
- Scripts: `rsa_timing_experiment.py`, `chits/q02.py`, `chits/q04.py`, `chits/q12.py`, `chits/q30.py`, `chits/q34.py`.
- Secure messaging demos: `chits/q11.py`, `chits/q15.py`, `chits/q23.py`, `chits/q35.py`, `chits/q39.py`.

---

## 5) Hash Functions (SHA‑1)

### 5.1 What hashing provides
- Deterministic, fixed‑length digest of data.
- Integrity checks; used in signatures, MACs, KDFs.
- Non‑invertibility: given digest, hard to find preimage; second preimage and collision resistance vary by algorithm.

### 5.2 SHA‑1 overview (educational)
- Output: 160 bits (5 words).
- Processes 512‑bit blocks after padding the message to length \n
  $$ M' = \text{Pad}(M) $$
  - Padding steps: append `0x80`, then `0x00` bytes to make length ≡ 448 mod 512, then append 64‑bit big‑endian original length.
- Message schedule: for rounds $t=16..79$:
  $$ W_t = (W_{t-3} \oplus W_{t-8} \oplus W_{t-14} \oplus W_{t-16}) \lll 1 $$
- Round functions with constants $K_t$ and function $f_t$ over 80 steps:
  - For $t\in[0,19]$: $f = (B\land C) \lor (\lnot B \land D)$, $K=0x5A827999$
  - For $t\in[20,39]$: $f = B \oplus C \oplus D$, $K=0x6ED9EBA1$
  - For $t\in[40,59]$: $f = (B\land C) \lor (B\land D) \lor (C\land D)$, $K=0x8F1BBCDC$
  - For $t\in[60,79]$: $f = B \oplus C \oplus D$, $K=0xCA62C1D6$
- Update working variables A..E per round, then add to hash state.
- Note: SHA‑1 is no longer collision‑resistant for high‑security use; prefer SHA‑256/512.
- Scripts: `sha1_demo.py`, `chits/q08.py`, `chits/q09.py`, `chits/q21.py`, `chits/q29.py`, `chits/q33.py`, `chits/q41.py`.

### 5.3 Where SHA‑1 appears in this repo
- As an educational hash function in hashing demos.
- Not for password storage (we use PBKDF2‑HMAC‑SHA256).
- Not for signatures in our RSA demos (we use SHA‑256 there).

---

## 6) Password Protection (PBKDF2‑HMAC‑SHA256)

### 6.1 Goal
- Store only salted, iterated hashes of passwords; never plaintext.
- Slow down brute force.

### 6.2 PBKDF2 formula
- Desired key length DK is built from blocks $T_1\|T_2\|\dots$ where:
  - $$ T_i = F(P, S, c, i) $$
  - $$ F(P,S,c,i) = U_1 \oplus U_2 \oplus \dots \oplus U_c $$
  - $$ U_1 = PRF(P,\, S\,\|\,\text{INT}_{32\,BE}(i)) $$
  - $$ U_j = PRF(P,\, U_{j-1}),\ j=2..c $$
- Here $PRF$ is HMAC‑SHA256 in our demos. We store `iterations:salt_hex:hash_hex`.
- Scripts: `chits/q10.py`, `chits/q13.py`, `chits/q16.py`, `chits/q22.py`, `chits/q25.py`, `chits/q37.py`, `chits/q42.py`.

### 6.3 Parameter choices (practical)
- Iterations: pick as high as tolerable (e.g., 100k–600k on your hardware) and revisit over time.
- Salt: unique per user, at least 128 bits (we use 16–32 bytes randomly generated).
- Storage format: keep algorithm, iterations, salt, and hash to enable future migration.

### 6.3 Policy and rate limiting
- Require length and mix (upper/lower/digit) to reduce weak passwords.
- Basic per‑IP attempt limiting to slow online guessing.

---

## 7) Symmetric Authenticated Encryption: AES‑GCM

### 7.1 Why AES‑GCM
- Provides confidentiality + integrity (authenticity) in one operation.
- Safer than AES‑CBC + ad‑hoc MAC for most beginners.

### 7.2 AES‑GCM formula (high level)
- Let $H = E_K(0^{128})$ be the GHASH subkey.
- Compute ciphertext with CTR mode starting from counter $J_0$.
- Authentication tag:
  - $$ T = E_K(J_0) \oplus GHASH(H, A, C) $$
- Where $GHASH$ is polynomial multiplication in $GF(2^{128})$ over additional data $A$ and ciphertext $C$.
- Never reuse (key, nonce) pairs.
- Scripts (image/demo): `chits/q17.py`, `chits/q24.py`, `chits/q27.py`, `chits/q31.py`, `chits/q40.py`, `chits/q43.py`.

### 7.3 Common mistakes
- Reusing nonce with the same key (catastrophic).
- Forgetting to include associated data (AAD) if headers must be authenticated.
- Truncating the tag too aggressively (<96 bits) increases forgery risk.

---

## 8) Custom Educational Cipher (XOR + Rotate)

- Let key bytes repeat to match message length.
- Encryption per byte $b$ with key byte $k$:
  - $$ x = b \oplus k $$
  - $$ c = (x \lll 1) \bmod 256 $$ (left rotate by 1)
- Decryption per byte $c$ with key byte $k$:
  - $$ x = (c \ggg 1) \bmod 256 $$ (right rotate inverse)
  - $$ b = x \oplus k $$
- Not secure; for education about reversible transforms.
- Scripts: `chits/q05.py`, `chits/q18.py`, `chits/q32.py`, `chits/q38.py`, `chits/q44.py`.

### 8.1 Why include this?
- To practice reasoning about reversible operations and bitwise transformations.
- To contrast “works and is reversible” with “cryptographically secure.”

---

## 9) Which script does what (quick map)

- Classical ciphers: `caesar_cipher.py`, `vigenere_cipher.py`, `rail_fence_cipher.py`, plus `chits/q01.py`, `q14.py`, `q36.py`.
- Vernam/OTP: `vernam_cipher.py`, `one_time_pad.py`, `chits/q03.py`, `q19.py`, `q36.py`.
- Diffie–Hellman + MITM: `diffie_hellman_mitm_demo.py`, `chits/q06.py`, `q07.py`, `q20.py`, `q26.py`, `q28.py`.
- RSA secure messaging & signatures: `chits/q11.py`, `q15.py`, `q23.py`, `q35.py`, `q39.py`.
- RSA timing: `rsa_timing_experiment.py`, `chits/q02.py`, `q04.py`, `q12.py`, `q30.py`, `q34.py`.
- SHA‑1 demos: `sha1_demo.py`, `chits/q08.py`, `q09.py`, `q21.py`, `q29.py`, `q33.py`, `q41.py`.
- Password protection: `chits/q10.py`, `q13.py`, `q16.py`, `q22.py`, `q25.py`, `q37.py`, `q42.py`.
- AES‑GCM image encryption: `chits/q17.py`, `q24.py`, `q27.py`, `q31.py`, `q40.py`, `q43.py`.
- Custom cipher: `chits/q05.py`, `q18.py`, `q32.py`, `q38.py`, `q44.py`.

---

## 10) Security properties quick guide

- Confidentiality: Caesar, Vigenère (weak), OTP (perfect with rules), AES‑GCM (strong), RSA‑OAEP (public‑key encryption)
- Integrity/Authenticity: AES‑GCM tag; RSA signatures (PKCS#1 v1.5 over SHA‑256)
- Non‑repudiation: Digital signatures (verification with public key)
- Key agreement: Diffie–Hellman (needs authentication to prevent MITM)
- Password storage: PBKDF2‑HMAC‑SHA256 with unique salts and high iterations
- Hashing: SHA‑1 shown for education; prefer SHA‑256/512 for new systems

## 11) Glossary
- IND‑CPA: Indistinguishability under Chosen‑Plaintext Attack (encryption security notion).
- OAEP: Optimal Asymmetric Encryption Padding (randomized padding for RSA encryption).
- GHASH: The polynomial authenticator used by GCM for integrity.
- KDF: Key Derivation Function (e.g., PBKDF2) that stretches passwords into keys.
- AAD: Additional Authenticated Data; authenticated but not encrypted metadata.

---

## 11) Practical tips

- Never reuse (key, nonce) pairs in AES‑GCM.
- Never reuse OTP keys; keep them truly random and as long as the message.
- For RSA, prefer OAEP (encryption) and PSS (signatures) in production.
- For passwords, use Argon2/bcrypt/scrypt/PBKDF2 with per‑user unique salts.
- Always authenticate key exchange (certificates, signatures, or PAKE) to defeat MITM.

---

## 12) Try it

From PowerShell in the project root:

```powershell
# Install dependencies
pip install -r .\requirements.txt

# Run a few demos
python .\caesar_cipher.py encrypt "HELLO WORLD" 3
python .\vigenere_cipher.py encrypt "ATTACK AT DAWN" LEMON
python .\chits\q11.py   # RSA encrypt + sign demo
python .\chits\q17.py encrypt .\some_image.jpg .\enc.json
python .\chits\q17.py decrypt .\enc.json .\restored.jpg
python .\chits\q25.py  # Password site (http://127.0.0.1:5003)
```

---

If you want me to add SHA‑1 hashes to the output of each script (e.g., print SHA‑1 of plaintext/ciphertext), I can wire that in next without changing existing behavior.
