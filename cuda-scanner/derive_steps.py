import hmac, hashlib

def derive_child_hardened(parent_key, parent_chain, index):
    index = index | 0x80000000
    data = b'\x00' + parent_key + index.to_bytes(4, 'big')
    I = hmac.new(parent_chain, data, hashlib.sha512).digest()
    IL, IR = I[:32], I[32:]
    
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    child = (int.from_bytes(IL, 'big') + int.from_bytes(parent_key, 'big')) % n
    child_key = child.to_bytes(32, 'big')
    return child_key, IR

def derive_child_normal(parent_key, parent_chain, index):
    # Get compressed pubkey
    from ecdsa import SigningKey, SECP256k1
    sk = SigningKey.from_string(parent_key, curve=SECP256k1)
    vk = sk.get_verifying_key()
    pubkey = vk.to_string()
    x = pubkey[:32]
    y = int.from_bytes(pubkey[32:], 'big')
    prefix = b'\x02' if y % 2 == 0 else b'\x03'
    compressed = prefix + x
    
    print(f"  Compressed pubkey for normal derivation: {compressed.hex()}")
    
    data = compressed + index.to_bytes(4, 'big')
    print(f"  HMAC data: {data.hex()}")
    
    I = hmac.new(parent_chain, data, hashlib.sha512).digest()
    IL, IR = I[:32], I[32:]
    
    print(f"  HMAC IL: {IL.hex()}")
    
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    child = (int.from_bytes(IL, 'big') + int.from_bytes(parent_key, 'big')) % n
    child_key = child.to_bytes(32, 'big')
    return child_key, IR

master_key = bytes.fromhex('7441876923f2e91c3f89d3d1eb6e498ae684f8d2ad4a0bdde655cb352472e227')
master_chain = bytes.fromhex('b60f974f1368373053f893780a7c6bcf95feb4f7254922658a1af1dde8932e2c')

print('Master Key:', master_key.hex())
print('Master Chain:', master_chain.hex())

# m/44'
key, chain = derive_child_hardened(master_key, master_chain, 44)
print("\nm/44':")
print('  Key:', key.hex())
print('  Chain:', chain.hex())

# m/44'/0'
key, chain = derive_child_hardened(key, chain, 0)
print("\nm/44'/0':")
print('  Key:', key.hex())
print('  Chain:', chain.hex())

# m/44'/0'/0'
key, chain = derive_child_hardened(key, chain, 0)
print("\nm/44'/0'/0':")
print('  Key:', key.hex())
print('  Chain:', chain.hex())

# m/44'/0'/0'/0
key, chain = derive_child_normal(key, chain, 0)
print("\nm/44'/0'/0'/0:")
print('  Key:', key.hex())
print('  Chain:', chain.hex())

# m/44'/0'/0'/0/0
key, chain = derive_child_normal(key, chain, 0)
print("\nm/44'/0'/0'/0/0:")
print('  Key:', key.hex())
print('  Chain:', chain.hex())
