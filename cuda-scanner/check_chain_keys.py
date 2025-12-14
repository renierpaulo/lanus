from bip_utils import Bip39SeedGenerator, Bip32Slip10Secp256k1
import binascii

mnemonic = "galaxy man boy evil donkey child cross chair egg meat blood space"
seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

bip32_ctx = Bip32Slip10Secp256k1.FromSeed(seed_bytes)
print(f"Master:       {bip32_ctx.PrivateKey().Raw().ToHex()}")
k1 = bip32_ctx.DerivePath("44'")
print(f"m/44':        {k1.PrivateKey().Raw().ToHex()}")
k2 = k1.DerivePath("0'")
print(f"m/44'/0':     {k2.PrivateKey().Raw().ToHex()}")
k3 = k2.DerivePath("0'")
print(f"m/44'/0'/0':  {k3.PrivateKey().Raw().ToHex()}")
k4 = k3.DerivePath("0")
print(f"m/44'/0'/0'/0: {k4.PrivateKey().Raw().ToHex()}")
k5 = k4.DerivePath("0")
print(f"Final Priv:   {k5.PrivateKey().Raw().ToHex()}")
print(f"Final Pub:    {k5.PublicKey().RawCompressed().ToHex()}")
