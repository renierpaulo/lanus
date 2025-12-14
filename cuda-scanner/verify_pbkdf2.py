#!/usr/bin/env python3
"""
Verify PBKDF2-SHA512 implementation for BIP39
Compares CUDA output with Python reference implementation
"""

from mnemonic import Mnemonic
import hashlib
import hmac

def test_pbkdf2():
    # Test mnemonic from the debug output
    test_mnemonics = [
        "boy man evil donkey meat space blood chair egg cross galaxy child",
        "boy man evil donkey meat space blood child galaxy chair cross egg",
        "donkey space meat blood chair egg child cross boy galaxy man evil"
    ]
    
    mnemo = Mnemonic("english")
    
    print("=" * 80)
    print("PBKDF2-SHA512 Verification Test")
    print("=" * 80)
    
    for mnemonic in test_mnemonics:
        print(f"\nMnemonic: {mnemonic}")
        
        # Check if valid
        is_valid = mnemo.check(mnemonic)
        print(f"Valid BIP39: {is_valid}")
        
        if is_valid:
            # Generate seed using reference implementation
            seed = mnemo.to_seed(mnemonic, passphrase="")
            print(f"Expected Seed: {seed.hex()[:64]}...")
            
            # Show first 32 bytes for comparison
            print(f"First 32 bytes: {seed[:32].hex()}")
            
            # Manual PBKDF2 calculation for verification
            password = mnemonic.encode('utf-8')
            salt = b"mnemonic"
            
            manual_seed = hashlib.pbkdf2_hmac('sha512', password, salt, 2048)
            print(f"Manual PBKDF2: {manual_seed[:32].hex()}")
            
            # Verify they match
            if seed == manual_seed:
                print("✓ Reference and manual match!")
            else:
                print("✗ Mismatch!")
        
        print("-" * 80)

if __name__ == "__main__":
    test_pbkdf2()
