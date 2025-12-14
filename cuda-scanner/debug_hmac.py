from bip_utils import Bip39SeedGenerator, Bip32Slip10Secp256k1
import binascii
import hmac
import hashlib

mnemonic = "galaxy man boy evil donkey child cross chair egg meat blood space"
seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
bip32_ctx = Bip32Slip10Secp256k1.FromSeed(seed_bytes)

# m/44'
k1 = bip32_ctx.DerivePath("44'")
priv_44 = k1.PrivateKey().Raw().ToBytes()
chain_44 = k1.ChainCode().ToBytes()

print(f"m/44' Priv: {priv_44.hex()}")
print(f"m/44' Chain: {chain_44.hex()}")

# Manual derivation of m/44'/0'
# Hardened index 0
index = 0 + 0x80000000
data = b'\x00' + priv_44 + index.to_bytes(4, 'big')

I = hmac.new(chain_44, data, hashlib.sha512).digest()
IL = I[:32]
IR = I[32:]

print(f"Calculated I_L (HMAC output): {IL.hex()}")
print(f"Calculated I_R (Next Chain):  {IR.hex()}")

# Verify with library
k2 = k1.DerivePath("0'")
print(f"Library m/44'/0' Priv: {k2.PrivateKey().Raw().ToHex()}")
print(f"Library m/44'/0' Chain: {k2.ChainCode().ToHex()}")
