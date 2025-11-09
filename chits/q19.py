"""Q19: Vernam cipher, One-Time Pad, and Rail Fence (all stdlib, educational).

Vernam: XOR of message and equal-length key bytes.
OTP: Truly random pad (secrets); NEVER reuse pad.
Rail Fence: Transposition cipher pattern demonstration.
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

def otp_encrypt(message:str):
    data=message.encode(); pad=secrets.token_bytes(len(data))
    ct=bytes(x^y for x,y in zip(data,pad))
    return pad.hex(), ct.hex()

def rail_fence_encrypt(text, rails):
    text=''.join(ch for ch in text if not ch.isspace())
    rows=[[] for _ in range(rails)]
    r=0; d=1
    for ch in text:
        rows[r].append(ch); r+=d
        if r==rails-1 or r==0: d*=-1
    return ''.join(''.join(x) for x in rows)

if __name__=='__main__':
    msg="HELLO"; key="WORLD"
    print("Vernam:", vernam_encrypt(msg,key))
    pad, ct = otp_encrypt(msg); print("OTP pad:", pad); print("OTP ct:", ct)
    print("RailFence:", rail_fence_encrypt("WE ARE DISCOVERED FLEE AT ONCE",3))
