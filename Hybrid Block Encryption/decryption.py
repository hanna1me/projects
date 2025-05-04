# decryption.py
from tables import reverse_s_box_substitution, reverse_expansion
from permutation import apply_permutation, generate_user_permutation, inverse_permutation_table

def xor_bin(bin_str1: str, bin_str2: str) -> str:
    """
    XOR two binary strings of equal length.
    """
    return ''.join('1' if a != b else '0' for a, b in zip(bin_str1, bin_str2))

def hex_to_bin(hex_str: str, bits: int) -> str:
    """
    Convert a hex string to a binary string with a specified bit-length.
    """
    return format(int(hex_str, 16), '0{}b'.format(bits))

def decrypt_message(encrypted_hex: str, key_segments: list, permutation_table: list) -> str:
    """
    Decrypt a 256-bit encrypted message (64 hex digits) using the hybrid decryption process.
    
    Steps:
      1. Convert the encrypted hex to a 256-bit binary string.
      2. Split into 8 segments (32 bits each).
      3. For each segment:
           - XOR with the corresponding key segment.
           - Apply the placeholder reverse S-box substitution (32 -> 48 bits) and reverse expansion (48 -> 32 bits).
      4. Combine the segments into a 256-bit block.
      5. Apply the inverse permutation (IP⁻¹) to recover the original plaintext.
    """
    if len(encrypted_hex) != 64:
        raise ValueError("Encrypted block must be 64 hex digits (256 bits).")
    encrypted_bin = hex_to_bin(encrypted_hex, 256)
    
    decrypted_block = ""
    for i in range(8):
        encrypted_segment = encrypted_bin[i*32:(i+1)*32]
        key_bin = hex_to_bin(key_segments[i], 32)
        substituted = xor_bin(encrypted_segment, key_bin)
        expanded = reverse_s_box_substitution(substituted)  # Placeholder reverse substitution
        original_segment = reverse_expansion(expanded)        # Placeholder reverse expansion
        decrypted_block += original_segment
    
    # Apply the inverse of the initial permutation (IP⁻¹)
    inv_perm_table = inverse_permutation_table(permutation_table)
    recovered_plaintext = apply_permutation(decrypted_block, inv_perm_table)
    return recovered_plaintext

if __name__ == "__main__":
    encrypted_hex = input("Enter encrypted block (64 hex digits): ").strip()
    key_segments = []
    for i in range(8):
        seg = input(f"Enter key segment {i+1} (8 hex digits): ").strip()
        if len(seg) != 8:
            raise ValueError("Key segment must be 8 hex digits.")
        key_segments.append(seg)
    email = input("Enter your email (for permutation generation): ").strip()
    perm_table = generate_user_permutation(email, size=256)
    decrypted_bin = decrypt_message(encrypted_hex, key_segments, perm_table)
    print("Decrypted block (binary):", decrypted_bin)
    decrypted_hex = format(int(decrypted_bin, 2), '064x')
    print("Decrypted block (hex):", decrypted_hex)
