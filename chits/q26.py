"""Q26: Diffie-Hellman key exchange with Man-In-The-Middle attack (standalone).
Tiny prime and generator for clarity (INSECURE!).
Run:
  python q26.py
"""
import random
P=23; G=5

def modexp(b,e,m): return pow(b,e,m)

def honest():
    a=random.randint(2,P-2); b=random.randint(2,P-2)
    A=modexp(G,a,P); B=modexp(G,b,P)
    sA=modexp(B,a,P); sB=modexp(A,b,P)
    print('Honest exchange:')
    print(' Alice A=',A,' Bob B=',B)
    print(' Shared keys:',sA,sB)  # should match
    print()

def mitm():
    a=random.randint(2,P-2); b=random.randint(2,P-2); m1=random.randint(2,P-2); m2=random.randint(2,P-2)
    A=modexp(G,a,P); B=modexp(G,b,P); M1=modexp(G,m1,P); M2=modexp(G,m2,P)
    s_alice=modexp(M1,a,P); s_mallory_a=modexp(A,m1,P)
    s_bob=modexp(M2,b,P); s_mallory_b=modexp(B,m2,P)
    print('MITM exchange:')
    print(' Alice sends A but Bob sees M2, Bob sends B but Alice sees M1')
    print(' Alice key:',s_alice,' Mallory(A):',s_mallory_a)
    print(' Bob key:',s_bob,' Mallory(B):',s_mallory_b)
    print(' Keys differ; attacker can read/modify messages.')

if __name__=='__main__':
    honest(); mitm()
