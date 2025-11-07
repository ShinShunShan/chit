"""Rail Fence cipher (zig-zag) with encode/decode.
Usage:
  python rail_fence_cipher.py encrypt "WE ARE DISCOVERED FLEE AT ONCE" 3
  python rail_fence_cipher.py decrypt <cipher> 3
Spaces are removed for processing to keep it simple.
"""
import sys


def encrypt(plaintext: str, rails: int) -> str:
    if rails < 2:
        raise ValueError("Rails must be >= 2")
    # remove spaces for simplicity
    text = "".join(ch for ch in plaintext if not ch.isspace())
    rows = [[] for _ in range(rails)]
    row = 0
    direction = 1  # 1 down, -1 up
    for ch in text:
        rows[row].append(ch)
        row += direction
        if row == rails - 1 or row == 0:
            direction *= -1
    return "".join("".join(r) for r in rows)


def decrypt(ciphertext: str, rails: int) -> str:
    if rails < 2:
        raise ValueError("Rails must be >= 2")
    # Determine the pattern of rows indices
    pattern = []
    row = 0
    direction = 1
    for _ in range(len(ciphertext)):
        pattern.append(row)
        row += direction
        if row == rails - 1 or row == 0:
            direction *= -1
    # Count how many chars per row
    counts = [pattern.count(r) for r in range(rails)]
    # Slice ciphertext into rows
    pos = 0
    rows = []
    for c in counts:
        rows.append(list(ciphertext[pos:pos + c]))
        pos += c
    # Reconstruct original order following pattern
    indices = [0] * rails
    result = []
    for r in pattern:
        result.append(rows[r][indices[r]])
        indices[r] += 1
    return "".join(result)


def main():
    if len(sys.argv) < 4:
        print("Usage: python rail_fence_cipher.py <encrypt|decrypt> <text> <rails>")
        return
    action = sys.argv[1].lower()
    text = sys.argv[2]
    try:
        rails = int(sys.argv[3])
    except ValueError:
        print("Rails must be an integer")
        return
    if action == "encrypt":
        print(encrypt(text, rails))
    elif action == "decrypt":
        print(decrypt(text, rails))
    else:
        print("Action must be encrypt or decrypt")


if __name__ == "__main__":
    main()
