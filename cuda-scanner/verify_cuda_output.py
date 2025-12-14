#!/usr/bin/env python3
"""
Verify specific mnemonic from CUDA debug output
"""

from mnemonic import Mnemonic
import hashlib
import hmac

def hash160(data):
    h = hashlib.new('ripemd160')
    h.update(hashlib.sha256(data).digest())
    return h.digest()

# Mnemonic from CUDA debug output
mnemonic = "man evil blood meat donkey space egg cross galaxy boy chair child"

mnemo = Mnemonic("english")

print("="*80)
print(f"Mnemonic: {mnemonic}")
print("="*80)

# Check validity
is_valid = mnemo.check(mnemonic)
print(f"\nValid BIP39: {is_valid}")

if is_valid:
    # Generate seed
    seed = mnemo.to_seed(mnemonic, passphrase="")
    print(f"\n[EXPECTED] SEED: {seed[:32].hex()}...")
    
    # Master key
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    master_key = I[:32]
    print(f"[EXPECTED] MASTER KEY: {master_key.hex()}")
    
    # For comparison - note CUDA output:
    print("\n--- CUDA Output ---")
    print("SEED: 955d2a2ba652f4ce586dbcf1c6690e353a2cbac3eab2f66456f6219020b5f178...")
    print("MASTER KEY: fca35f8a5344aa9a7f825a3ded904bb3ce53d168c102f2afb59cd1d512ddf145")
    print("HASH160: 48bd956a87aea165876106d496e4d2b820786842")
    
    # Check if they match
    cuda_seed = "955d2a2ba652f4ce586dbcf1c6690e353a2cbac3eab2f66456f6219020b5f178"
    expected_seed = seed[:32].hex()
    
    print("\n--- Comparison ---")
    if cuda_seed == expected_seed:
        print("✓ SEED MATCHES!")
    else:
        print("✗ SEED MISMATCH!")
        print(f"  Expected: {expected_seed}")
        print(f"  Got:      {cuda_seed}")
else:
    print("Invalid mnemonic!")
