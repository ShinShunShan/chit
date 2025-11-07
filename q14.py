"""Q14: Classical ciphers again (Caesar, Vigenere, Rail Fence)."""
from q01 import caesar_encrypt, vigenere_encrypt, rail_fence_encrypt
if __name__=='__main__':
    msg="HELLO WORLD"; print(caesar_encrypt(msg,5)); print(vigenere_encrypt(msg,"KEY")); print(rail_fence_encrypt(msg,3))
