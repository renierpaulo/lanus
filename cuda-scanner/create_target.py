#!/usr/bin/env python3
"""
Create a target address from a valid mnemonic in our word list
"""

from mnemonic import Mnemonic
from bip32utils import BIP32Key
from ecdsa import SigningKey, SECP256k1
import hashlib

def hash160(data):
    h = hashlib.new('ripemd160')
    h.update(hashlib.sha256(data).digest())
    return h.digest()

def derive_bip32_path(seed, path="m/44'/0'/0'/0/0"):
    key = BIP32Key.fromEntropy(seed, public=False)
    parts = path.split('/')
    for part in parts[1:]:
        hardened = part.endswith("'")
        index = int(part.rstrip("'"))
        if hardened:
            key = key.ChildKey(index + 0x80000000)
        else:
            key = key.ChildKey(index)
    return key

def mnemonic_to_address(mnemonic_str):
    mnemo = Mnemonic("english")
    if not mnemo.check(mnemonic_str):
        return None, None, None
    
    seed = mnemo.to_seed(mnemonic_str, passphrase="")
    key = derive_bip32_path(seed, "m/44'/0'/0'/0/0")
    private_key = key.PrivateKey()
    
    # Get compressed public key
    signing_key = SigningKey.from_string(private_key, curve=SECP256k1)
    verifying_key = signing_key.get_verifying_key()
    pubkey_uncompressed = verifying_key.to_string()
    
    x = pubkey_uncompressed[:32]
    y = int.from_bytes(pubkey_uncompressed[32:], 'big')
    prefix = b'\x02' if y % 2 == 0 else b'\x03'
    pubkey = prefix + x
    
    pubkey_hash = hash160(pubkey)
    
    # Generate address
    version = b'\x00'
    payload = version + pubkey_hash
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    address_bytes = payload + checksum
    
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num = int.from_bytes(address_bytes, 'big')
    address = ''
    while num:
        num, rem = divmod(num, 58)
        address = alphabet[rem] + address
    for byte in address_bytes:
        if byte == 0:
            address = '1' + address
        else:
            break
    
    return address, pubkey_hash.hex(), private_key.hex()

# Test mnemonics from our word list (permutations of the 12 words)
words = ["galaxy", "man", "boy", "evil", "donkey", "child", "cross", "chair", "egg", "meat", "blood", "space"]

# Try a few valid permutations
test_phrases = [
    "galaxy man boy evil donkey child cross chair egg meat blood space",
    "boy man evil donkey meat space blood child galaxy chair cross egg",
    "man evil blood meat donkey space egg cross galaxy boy chair child",
]

print("="*80)
print("Finding valid mnemonics and their addresses")
print("="*80)

valid_results = []
for phrase in test_phrases:
    result = mnemonic_to_address(phrase)
    if result[0]:
        addr, h160, privkey = result
        print(f"\nMnemonic: {phrase}")
        print(f"Address: {addr}")
        print(f"Hash160: {h160}")
        valid_results.append((phrase, addr, h160))

# Write target file with the first valid address
if valid_results:
    print("\n" + "="*80)
    print("Writing target_test.txt with address to find:")
    print("="*80)
    with open("target_test.txt", "w") as f:
        addr = valid_results[0][1]
        f.write(addr + "\n")
    print(f"Target: {valid_results[0][1]}")
    print(f"Hash160: {valid_results[0][2]}")
    print(f"\nExpected mnemonic: {valid_results[0][0]}")
