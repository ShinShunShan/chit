import socket
import hashlib

def mod_pow(base, exp, mod):
    """Equivalent to (base ** exp) % mod using simple loop (like in Java)."""
    result = 1
    for _ in range(exp):
        result = (result * base) % mod
    return result

def decrypt(cipher, d, n):
    """RSA decryption: (cipher^d) mod n"""
    return mod_pow(cipher, d, n)

def sha256(input_str):
    """Compute SHA-256 hash as hex string."""
    hash_obj = hashlib.sha256(input_str.encode())
    return hash_obj.hexdigest()

def verify(message, signature, e, n):
    """Verify signature using RSA and SHA-256."""
    new_hash = sha256(message)
    hash_val = abs(hash(new_hash) % n)
    decrypted_hash = decrypt(signature, e, n)

    print(f"\nComputed Hash (SHA-256): {new_hash}")
    print(f" Hash Value (mod n): {hash_val}")
    print(f" Decrypted Hash (from Signature): {decrypted_hash}")

    return decrypted_hash == hash_val

def main():
    HOST = ''      # Listen on all interfaces
    PORT = 5000

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((HOST, PORT))
        server.listen(1)
        print(" Receiver waiting for connection on port 5000...")

        conn, addr = server.accept()
        with conn:
            print(f"Connected to Sender: {addr}")

            # Helper to read lines from socket
            def recv_line():
                data = b''
                while not data.endswith(b'\n'):
                    chunk = conn.recv(1)
                    if not chunk:
                        break
                    data += chunk
                return data.decode().strip()

            e = int(recv_line())
            n = int(recv_line())
            d = int(recv_line())
            signature = int(recv_line())

            length = int(recv_line())
            cipher = [int(recv_line()) for _ in range(length)]

            # Decrypt message
            decrypted_msg = ''.join(chr(decrypt(val, d, n)) for val in cipher)
            print(f"\nDecrypted Message: {decrypted_msg}")

            valid = verify(decrypted_msg, signature, e, n)
            print(f"\n Signature Verification Result: {'MATCHED' if valid else 'NOT MATCHED'}")

            response = "Signature Verified!\n" if valid else "Signature Invalid!\n"
            conn.sendall(response.encode())

if __name__ == "__main__":
    main()
