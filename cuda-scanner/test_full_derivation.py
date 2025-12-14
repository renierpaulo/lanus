#!/usr/bin/env python3
"""
Full validation test for BIP39 CUDA Scanner
Tests each step: mnemonic -> seed -> master key -> derived key -> address
"""

from mnemonic import Mnemonic
import hashlib
import hmac
from bip32utils import BIP32Key
from ecdsa import SigningKey, SECP256k1
import binascii

def ripemd160(data):
    h = hashlib.new('ripemd160')
    h.update(data)
    return h.digest()

def hash160(data):
    return ripemd160(hashlib.sha256(data).digest())

def derive_bip32_path(seed, path="m/44'/0'/0'/0/0"):
    """Derive key using BIP32 path"""
    key = BIP32Key.fromEntropy(seed, public=False)
    
    # Parse path
    parts = path.split('/')
    for part in parts[1:]:  # Skip 'm'
        hardened = part.endswith("'")
        index = int(part.rstrip("'"))
        if hardened:
            key = key.ChildKey(index + 0x80000000)
        else:
            key = key.ChildKey(index)
    
    return key

def test_mnemonic(mnemonic_str):
    print("="*80)
    print(f"Testing: {mnemonic_str}")
    print("="*80)
    
    mnemo = Mnemonic("english")
    
    # Step 1: Validate mnemonic
    is_valid = mnemo.check(mnemonic_str)
    print(f"\n[Step 1] Valid BIP39: {is_valid}")
    
    if not is_valid:
        print("INVALID MNEMONIC - Skipping")
        return None
    
    # Step 2: Generate seed (PBKDF2)
    seed = mnemo.to_seed(mnemonic_str, passphrase="")
    print(f"\n[Step 2] PBKDF2 Seed (64 bytes):")
    print(f"  Full: {seed.hex()}")
    print(f"  First 32: {seed[:32].hex()}")
    
    # Step 3: Derive master key (HMAC-SHA512 with "Bitcoin seed")
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    master_private = I[:32]
    master_chain = I[32:]
    print(f"\n[Step 3] Master Key (HMAC-SHA512):")
    print(f"  Private: {master_private.hex()}")
    print(f"  Chain:   {master_chain.hex()}")
    
    # Step 4: Derive m/44'/0'/0'/0/0
    key = derive_bip32_path(seed, "m/44'/0'/0'/0/0")
    private_key_bytes = key.PrivateKey()
    print(f"\n[Step 4] Derived Private Key (m/44'/0'/0'/0/0):")
    print(f"  Private: {private_key_bytes.hex()}")
    
    # Step 5: Get public key (compressed)
    signing_key = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    verifying_key = signing_key.get_verifying_key()
    pubkey_uncompressed = verifying_key.to_string()
    
    # Compress public key
    x = int.from_bytes(pubkey_uncompressed[:32], 'big')
    y = int.from_bytes(pubkey_uncompressed[32:], 'big')
    prefix = b'\x02' if y % 2 == 0 else b'\x03'
    pubkey_compressed = prefix + pubkey_uncompressed[:32]
    
    print(f"\n[Step 5] Public Key (compressed):")
    print(f"  Pubkey: {pubkey_compressed.hex()}")
    
    # Step 6: Hash160 (RIPEMD160(SHA256(pubkey)))
    pubkey_hash = hash160(pubkey_compressed)
    print(f"\n[Step 6] Hash160 (RIPEMD160(SHA256(pubkey))):")
    print(f"  Hash160: {pubkey_hash.hex()}")
    
    # Step 7: Generate address
    version = b'\x00'  # mainnet
    payload = version + pubkey_hash
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    address_bytes = payload + checksum
    
    # Base58 encode
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num = int.from_bytes(address_bytes, 'big')
    address = ''
    while num:
        num, rem = divmod(num, 58)
        address = alphabet[rem] + address
    
    # Add leading 1s for leading zeros
    for byte in address_bytes:
        if byte == 0:
            address = '1' + address
        else:
            break
    
    print(f"\n[Step 7] Bitcoin Address:")
    print(f"  Address: {address}")
    
    print("\n" + "="*80)
    
    return {
        'mnemonic': mnemonic_str,
        'seed': seed.hex(),
        'master_key': master_private.hex(),
        'private_key': private_key_bytes.hex(),
        'pubkey': pubkey_compressed.hex(),
        'hash160': pubkey_hash.hex(),
        'address': address
    }

if __name__ == "__main__":
    # Test with known valid mnemonics from our word list
    test_phrases = [
        "galaxy man boy evil donkey child cross chair egg meat blood space",
        "boy man evil donkey meat space blood child galaxy chair cross egg",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    ]
    
    results = []
    for phrase in test_phrases:
        result = test_mnemonic(phrase)
        if result:
            results.append(result)
    
    print("\n\n" + "="*80)
    print("SUMMARY - Expected Values for CUDA Verification")
    print("="*80)
    for r in results:
        print(f"\nMnemonic: {r['mnemonic']}")
        print(f"Expected Hash160: {r['hash160']}")
        print(f"Expected Address: {r['address']}")
