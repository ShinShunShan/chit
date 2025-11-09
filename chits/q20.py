"""Q20: Inline Diffie-Hellman key exchange + MITM demo (stdlib only).

Previously this imported an external script; here we embed a minimal version
so the file is self-contained. Tiny numbers are used for clarity, not security.
"""
import random

P = 23  # small prime (INSECURE)
G = 5   # generator

def honest():
	a = random.randint(2, P-2)
	b = random.randint(2, P-2)
	A = pow(G, a, P)
	B = pow(G, b, P)
	s1 = pow(B, a, P)
	s2 = pow(A, b, P)
	print('Honest DH:')
	print(f'  a={a} A={A} b={b} B={B}')
	print(f'  Shared (Alice)={s1} Shared (Bob)={s2}\n')

def mitm():
	a = random.randint(2, P-2)
	b = random.randint(2, P-2)
	m1 = random.randint(2, P-2)
	m2 = random.randint(2, P-2)
	A = pow(G,a,P); B = pow(G,b,P)
	M1 = pow(G,m1,P); M2 = pow(G,m2,P)
	s_alice = pow(M2,a,P)
	s_mallory_a = pow(A,m2,P)
	s_bob = pow(M1,b,P)
	s_mallory_b = pow(B,m1,P)
	print('MITM DH:')
	print(f'  Alice A={A} -> Mallory swaps to M1={M1} for Bob')
	print(f'  Bob B={B}   -> Mallory swaps to M2={M2} for Alice')
	print(f'  Alice key (with Mallory)={s_alice}')
	print(f'  Mallory key with Alice  ={s_mallory_a}')
	print(f'  Bob key (with Mallory)  ={s_bob}')
	print(f'  Mallory key with Bob    ={s_mallory_b}')
	print('  Alice & Bob do NOT share a key; Mallory can read/modify messages.')

def main():
	honest(); mitm()

if __name__=='__main__':
	main()
