<<<<<<< HEAD
"""Q28: Diffie-Hellman key exchange with MITM (standalone).
Shows attacker establishing two different shared secrets.
Run:
  python q28.py
"""
import random
P=23; G=5

def modexp(b,e,m): return pow(b,e,m)

def mitm():
    a=random.randint(2,P-2); b=random.randint(2,P-2); m1=random.randint(2,P-2); m2=random.randint(2,P-2)
    A=modexp(G,a,P); B=modexp(G,b,P); M1=modexp(G,m1,P); M2=modexp(G,m2,P)
    sA=modexp(M1,a,P); sM_A=modexp(A,m1,P); sB=modexp(M2,b,P); sM_B=modexp(B,m2,P)
    print('Alice key:', sA, 'Mallory(A):', sM_A)
    print('Bob key:', sB, 'Mallory(B):', sM_B)
    print('Mismatch shows interception possible.')

if __name__=='__main__': mitm()
=======
"""Q28: Diffie-Hellman MITM attack demonstration (repeat)."""
from diffie_hellman_mitm_demo import main as run
if __name__=='__main__': run()
>>>>>>> 5c2263d (Add q25-q32 scripts (website security, DH MITM, image AES-GCM, SHA-1, RSA timing, custom cipher))
