# main.py
import key_generation
import encryption
import decryption
from permutation import generate_user_permutation

def main():
    mode = input("Select mode: E for encryption, D for decryption: ").strip().upper()
    email = input("Enter your email (for key generation and permutation): ").strip()
    key_segments = key_generation.generate_key(email)
    print("Generated Key Segments:", key_segments)
    
    # Generate a unique permutation table based on the email.
    perm_table = generate_user_permutation(email, size=256)
    
    if mode == 'E':
        plaintext_hex = input("Enter plaintext as 64 hex digits (256 bits): ").strip()
        encrypted_bin = encryption.encrypt_message(plaintext_hex, key_segments, perm_table)
        encrypted_hex = format(int(encrypted_bin, 2), '064x')
        print("Encrypted block (hex):", encrypted_hex)
    elif mode == 'D':
        encrypted_hex = input("Enter encrypted block as 64 hex digits: ").strip()
        decrypted_bin = decryption.decrypt_message(encrypted_hex, key_segments, perm_table)
        decrypted_hex = format(int(decrypted_bin, 2), '064x')
        print("Decrypted block (hex):", decrypted_hex)
    else:
        print("Invalid mode selected.")

if __name__ == "__main__":
    main()
