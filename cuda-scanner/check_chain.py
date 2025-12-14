from bip_utils import Bip39SeedGenerator, Bip32Slip10Secp256k1
import binascii

mnemonic = "galaxy man boy evil donkey child cross chair egg meat blood space"
print(f"Mnemonic: {mnemonic}")

seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
print(f"Seed: {binascii.hexlify(seed_bytes).decode()}")

# Master
bip32_ctx = Bip32Slip10Secp256k1.FromSeed(seed_bytes)
print(f"Master Priv:  {bip32_ctx.PrivateKey().Raw().ToHex()}")
print(f"Master Chain: {bip32_ctx.ChainCode().ToHex()}")

# m/44'
bip32_44 = bip32_ctx.DerivePath("44'")
print(f"m/44' Priv:   {bip32_44.PrivateKey().Raw().ToHex()}")
print(f"m/44' Chain:  {bip32_44.ChainCode().ToHex()}")

# m/44'/0'
bip32_coin = bip32_44.DerivePath("0'")
print(f"m/44'/0' Priv:  {bip32_coin.PrivateKey().Raw().ToHex()}")
print(f"m/44'/0' Chain: {bip32_coin.ChainCode().ToHex()}")
