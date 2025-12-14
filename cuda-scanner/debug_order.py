#!/usr/bin/env python3
"""
Debug: Check if original word order produces valid checksum
"""

from mnemonic import Mnemonic

mnemo = Mnemonic("english")

# Original order from words_test_12.txt
original = "galaxy man boy evil donkey child cross chair egg meat blood space"

# Check if valid
is_valid = mnemo.check(original)
print(f"Original order: {original}")
print(f"Valid BIP39: {is_valid}")

if is_valid:
    # Get word indices
    wordlist = mnemo.wordlist
    words = original.split()
    indices = [wordlist.index(w) for w in words]
    print(f"Indices: {indices}")
    
    # Check if first permutation (k=0) would be this order
    # k=0 means identity permutation (original order)
    print("\nNote: k=0 should give the original order (0,1,2,3,4,5,6,7,8,9,10,11)")
    print("The permutation algorithm uses factoradic to convert k to permutation")
else:
    print("\n*** CRITICAL: Original order is NOT a valid BIP39 phrase! ***")
    print("This explains why it wasn't found - the checksum is invalid!")
    
    # Try to find a valid checksum for these words
    import itertools
    print("\nSearching for valid permutations...")
    words = original.split()
    
    count = 0
    for perm in itertools.permutations(words):
        phrase = " ".join(perm)
        if mnemo.check(phrase):
            count += 1
            if count <= 5:
                indices = [wordlist.index(w) for w in perm]
                print(f"Valid #{count}: {phrase}")
                print(f"  Indices: {indices}")
    print(f"\nTotal valid permutations: {count}")
