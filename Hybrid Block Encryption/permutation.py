# permutation.py
import random

def generate_user_permutation(email: str, size=256):
    """
    Generate a unique permutation table for a 256-bit block using the user's email as a seed.
    This table (a list of indices) is used for the Initial Permutation (IP).
    """
    seed = sum(ord(c) for c in email)
    random.seed(seed)
    table = list(range(size))
    random.shuffle(table)
    return table

def apply_permutation(bit_string: str, table: list) -> str:
    """
    Apply a permutation to a bit string according to the given table.
    The table is a list of indices that rearrange the bits.
    """
    if len(bit_string) != len(table):
        raise ValueError("Bit string length must equal permutation table size.")
    return ''.join(bit_string[i] for i in table)

def inverse_permutation_table(table: list) -> list:
    """
    Generate the inverse of a permutation table.
    """
    inv = [0] * len(table)
    for i, pos in enumerate(table):
        inv[pos] = i
    return inv
