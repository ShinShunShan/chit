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
