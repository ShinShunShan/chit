"""Q24: Image security over insecure network (repeat of q17)."""
from q17 import encrypt_image, decrypt_image
import sys
if __name__=='__main__':
    if len(sys.argv)<4:
        print('Usage: python q24.py <encrypt|decrypt> <in> <out>')
    else:
        if sys.argv[1]=='encrypt': encrypt_image(sys.argv[2], sys.argv[3])
        elif sys.argv[1]=='decrypt': decrypt_image(sys.argv[2], sys.argv[3])
        else: print('Action must be encrypt or decrypt')
