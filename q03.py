"""Q3: Implement Vernam, Vigenere, One-Time Pad (OTP) ciphers.
All demos are simple and educational (not secure for real use).
"""
import secrets
ALPHABET="ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def vernam_encrypt(text:str, key:str)->str:
    a=text.encode(); b=key.encode()
    if len(a)!=len(b): raise ValueError("Key must equal message length")
    return bytes(x^y for x,y in zip(a,b)).hex()

def vernam_decrypt(hexct:str, key:str)->str:
    c=bytes.fromhex(hexct); b=key.encode()
    if len(c)!=len(b): raise ValueError("Key must equal cipher length")
    return bytes(x^y for x,y in zip(c,b)).decode()

def vigenere_encrypt(text,key):
    shifts=[ALPHABET.index(k) for k in key.upper() if k in ALPHABET]
    if not shifts: raise ValueError("Key must contain letters")
    out=[]; j=0
    for ch in text.upper():
        if ch in ALPHABET:
            out.append(ALPHABET[(ALPHABET.index(ch)+shifts[j%len(shifts)])%26]); j+=1
        else: out.append(ch)
    return ''.join(out)

def vigenere_decrypt(text,key):
    shifts=[ALPHABET.index(k) for k in key.upper() if k in ALPHABET]
    out=[]; j=0
    for ch in text.upper():
        if ch in ALPHABET:
            out.append(ALPHABET[(ALPHABET.index(ch)-shifts[j%len(shifts)])%26]); j+=1
        else: out.append(ch)
    return ''.join(out)

def otp_encrypt(message:str):
    data=message.encode(); pad=secrets.token_bytes(len(data))
    ct=bytes(x^y for x,y in zip(data,pad))
    return pad.hex(), ct.hex()

def otp_decrypt(cipher_hex:str, pad_hex:str)->str:
    c=bytes.fromhex(cipher_hex); p=bytes.fromhex(pad_hex)
    if len(c)!=len(p): raise ValueError("Pad length mismatch")
    return bytes(x^y for x,y in zip(c,p)).decode()

if __name__=='__main__':
    msg="HELLO"; key_same="WORLD"  # same length for Vernam/OTP demo
    print("Vernam enc:", vernam_encrypt(msg, key_same))
    pad_hex, ct_hex = otp_encrypt(msg)
    print("OTP pad:", pad_hex); print("OTP ct:", ct_hex)
    print("Vigenere LEMON:", vigenere_encrypt("ATTACK AT DAWN","LEMON"))
