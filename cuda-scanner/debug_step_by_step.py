#!/usr/bin/env python3
"""
Step-by-step debugging for BIP39 derivation
Shows exact expected values at each step
"""

import hashlib
import hmac
from hashlib import pbkdf2_hmac

def hex_dump(name, data):
    if isinstance(data, str):
        data = data.encode()
    print(f"{name}: {data.hex()}")

# Test mnemonic
mnemonic = "galaxy man boy evil donkey child cross chair egg meat blood space"

print("=" * 80)
print("Step 1: Mnemonic")
print("=" * 80)
print(f"Mnemonic string: '{mnemonic}'")
print(f"Mnemonic bytes: {mnemonic.encode().hex()}")
print(f"Mnemonic length: {len(mnemonic)} bytes")

print("\n" + "=" * 80)
print("Step 2: PBKDF2-SHA512")
print("=" * 80)

password = mnemonic.encode('utf-8')
salt = b"mnemonic"

print(f"Password (mnemonic utf-8): {password.hex()}")
print(f"Salt: {salt.hex()}")
print(f"Iterations: 2048")

seed = pbkdf2_hmac('sha512', password, salt, 2048)
print(f"Seed (64 bytes): {seed.hex()}")
print(f"Seed first 32: {seed[:32].hex()}")

print("\n" + "=" * 80)
print("Step 3: Master Key (HMAC-SHA512)")
print("=" * 80)

key = b"Bitcoin seed"
I = hmac.new(key, seed, hashlib.sha512).digest()
master_key = I[:32]
master_chain = I[32:]

print(f"HMAC key: {key.hex()}")
print(f"HMAC data (seed): {seed.hex()}")
print(f"HMAC result: {I.hex()}")
print(f"Master Key (IL): {master_key.hex()}")
print(f"Master Chain (IR): {master_chain.hex()}")

print("\n" + "=" * 80)
print("Step 4: Derive m/44'/0'/0'/0/0")
print("=" * 80)

from ecdsa import SECP256k1, SigningKey
from bip32utils import BIP32Key

# Use BIP32 library
key_obj = BIP32Key.fromEntropy(seed, public=False)
k44 = key_obj.ChildKey(44 + 0x80000000)
k44_0 = k44.ChildKey(0 + 0x80000000)
k44_0_0 = k44_0.ChildKey(0 + 0x80000000)
k44_0_0_0 = k44_0_0.ChildKey(0)
k44_0_0_0_0 = k44_0_0_0.ChildKey(0)

private_key = k44_0_0_0_0.PrivateKey()
print(f"Private Key m/44'/0'/0'/0/0: {private_key.hex()}")

print("\n" + "=" * 80)
print("Step 5: Public Key (compressed)")
print("=" * 80)

from ecdsa import SigningKey, SECP256k1

sk = SigningKey.from_string(private_key, curve=SECP256k1)
vk = sk.get_verifying_key()
pubkey_uncompressed = vk.to_string()

x = int.from_bytes(pubkey_uncompressed[:32], 'big')
y = int.from_bytes(pubkey_uncompressed[32:], 'big')

if y % 2 == 0:
    prefix = b'\x02'
else:
    prefix = b'\x03'

pubkey_compressed = prefix + pubkey_uncompressed[:32]
print(f"Public Key X: {pubkey_uncompressed[:32].hex()}")
print(f"Public Key Y: {pubkey_uncompressed[32:].hex()}")
print(f"Prefix (02 if even, 03 if odd): {prefix.hex()}")
print(f"Compressed Pubkey: {pubkey_compressed.hex()}")

print("\n" + "=" * 80)
print("Step 6: Hash160 = RIPEMD160(SHA256(pubkey))")
print("=" * 80)

sha = hashlib.sha256(pubkey_compressed).digest()
print(f"SHA256(pubkey): {sha.hex()}")

ripemd = hashlib.new('ripemd160')
ripemd.update(sha)
hash160 = ripemd.digest()
print(f"RIPEMD160(sha): {hash160.hex()}")

print("\n" + "=" * 80)
print("Step 7: Bitcoin Address")
print("=" * 80)

# Version byte (0x00 for mainnet)
version = b'\x00'
payload = version + hash160
checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
address_bytes = payload + checksum

print(f"Version: {version.hex()}")
print(f"Payload (version + hash160): {payload.hex()}")
print(f"Checksum (first 4 bytes of double SHA256): {checksum.hex()}")
print(f"Full address bytes: {address_bytes.hex()}")

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

print(f"Bitcoin Address: {address}")

print("\n" + "=" * 80)
print("SUMMARY - Values to Match in CUDA")
print("=" * 80)
print(f"1. Seed: {seed.hex()}")
print(f"2. Master Key: {master_key.hex()}")
print(f"3. Private Key: {private_key.hex()}")
print(f"4. Pubkey: {pubkey_compressed.hex()}")
print(f"5. Hash160: {hash160.hex()}")
print(f"6. Address: {address}")
