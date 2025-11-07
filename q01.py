"""Q1: Implement classical encryption techniques: Caesar, Polyalphabetic (Vigenere), Rail Fence.
Provides simple functions and demo when run.
"""
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def caesar_encrypt(text, shift):
    shift %= 26
    out = []
    for c in text.upper():
        if c in ALPHABET:
            out.append(ALPHABET[(ALPHABET.index(c)+shift)%26])
        else:
            out.append(c)
    return "".join(out)

def caesar_decrypt(cipher, shift):
    return caesar_encrypt(cipher, -shift)

def vigenere_encrypt(text, key):
    shifts = [ALPHABET.index(k) for k in key.upper() if k in ALPHABET]
    if not shifts:
        raise ValueError("Key must have letters")
    out=[]; j=0
    for c in text.upper():
        if c in ALPHABET:
            s=shifts[j%len(shifts)]
            out.append(ALPHABET[(ALPHABET.index(c)+s)%26]); j+=1
        else: out.append(c)
    return "".join(out)

def vigenere_decrypt(cipher, key):
    shifts = [ALPHABET.index(k) for k in key.upper() if k in ALPHABET]
    out=[]; j=0
    for c in cipher.upper():
        if c in ALPHABET:
            s=shifts[j%len(shifts)]
            out.append(ALPHABET[(ALPHABET.index(c)-s)%26]); j+=1
        else: out.append(c)
    return "".join(out)

def rail_fence_encrypt(text, rails):
    text = ''.join(ch for ch in text if not ch.isspace())
    rows=[[] for _ in range(rails)]
    row=0; dir=1
    for ch in text:
        rows[row].append(ch)
        row+=dir
        if row==rails-1 or row==0: dir*=-1
    return ''.join(''.join(r) for r in rows)

def rail_fence_decrypt(cipher, rails):
    pattern=[]; row=0; dir=1
    for _ in range(len(cipher)):
        pattern.append(row)
        row+=dir
        if row==rails-1 or row==0: dir*=-1
    counts=[pattern.count(r) for r in range(rails)]
    pos=0; rows=[]
    for c in counts:
        rows.append(list(cipher[pos:pos+c])); pos+=c
    idx=[0]*rails; out=[]
    for r in pattern:
        out.append(rows[r][idx[r]]); idx[r]+=1
    return ''.join(out)

if __name__=='__main__':
    msg="WE ARE DISCOVERED FLEE AT ONCE"; print("Message:", msg)
    print("Caesar 3:", caesar_encrypt(msg,3))
    vig=vigenere_encrypt(msg,"LEMON"); print("Vigenere LEMON:", vig)
    rf=rail_fence_encrypt(msg,3); print("RailFence 3:", rf)
    print("RailFence decrypt:", rail_fence_decrypt(rf,3))
