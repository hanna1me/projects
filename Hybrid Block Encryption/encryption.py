# encryption.py
from tables import expansion, s_box_substitution
from permutation import apply_permutation, generate_user_permutation

def hex_to_bin(hex_str: str, bits: int) -> str:
    """
    Convert a hex string to a binary string with a specified bit-length.
    """
    return format(int(hex_str, 16), '0{}b'.format(bits))

def xor_bin(bin_str1: str, bin_str2: str) -> str:
    """
    XOR two binary strings of equal length.
    """
    return ''.join('1' if a != b else '0' for a, b in zip(bin_str1, bin_str2))

def encrypt_message(plaintext_hex: str, key_segments: list, permutation_table: list) -> str:
    """
    Encrypt a 256-bit plaintext (64 hex digits) using the hybrid block cipher.
    
    Steps:
      1. Convert the plaintext to a 256-bit binary string.
      2. Apply an initial permutation (IP) using the provided permutation table.
      3. Split the permuted block into 8 segments (32 bits each).
      4. For each segment:
           - Expand from 32 to 48 bits.
           - Apply DES S-box substitution (48 -> 32 bits).
           - XOR with the corresponding key segment (converted to 32-bit binary).
      5. Reassemble the 8 segments into a 256-bit encrypted block.
    """
    if len(plaintext_hex) != 64:
        raise ValueError("Plaintext must be 64 hex digits (256 bits).")
    plaintext_bin = hex_to_bin(plaintext_hex, 256)
    
    # Apply the initial permutation (IP)
    permuted_plaintext = apply_permutation(plaintext_bin, permutation_table)
    
    encrypted_block = ""
    for i in range(8):
        segment = permuted_plaintext[i*32:(i+1)*32]
        expanded = expansion(segment)                   # 32 -> 48 bits
        substituted = s_box_substitution(expanded)        # 48 -> 32 bits
        key_bin = hex_to_bin(key_segments[i], 32)         # Convert key segment to 32-bit binary
        encrypted_segment = xor_bin(substituted, key_bin) # XOR with key segment
        encrypted_block += encrypted_segment
    
    return encrypted_block

if __name__ == "__main__":
    plaintext_hex = input("Enter 64 hex digits (256-bit) plaintext: ").strip()
    key_segments = []
    for i in range(8):
        seg = input(f"Enter key segment {i+1} (8 hex digits): ").strip()
        if len(seg) != 8:
            raise ValueError("Key segment must be 8 hex digits.")
        key_segments.append(seg)
    email = input("Enter your email (for permutation generation): ").strip()
    perm_table = generate_user_permutation(email, size=256)
    encrypted_bin = encrypt_message(plaintext_hex, key_segments, perm_table)
    print("Encrypted block (binary):", encrypted_bin)
    encrypted_hex = format(int(encrypted_bin, 2), '064x')
    print("Encrypted block (hex):", encrypted_hex)
