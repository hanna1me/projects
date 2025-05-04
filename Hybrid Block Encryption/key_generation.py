# key_generation.py
import hashlib

def generate_key(email: str):
    """
    Generate a 256-bit key using SHA-256 from the given email.
    The 64-character hex digest (256 bits) is split into 8 segments of 8 hex digits each.
    """
    hash_obj = hashlib.sha256(email.encode())
    hex_key = hash_obj.hexdigest()  # 64 hex digits = 256 bits
    key_segments = [hex_key[i:i+8] for i in range(0, 64, 8)]
    return key_segments

if __name__ == "__main__":
    email = input("Enter your email for key generation: ")
    key_segments = generate_key(email)
    print("Generated Key Segments:", key_segments)
