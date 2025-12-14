from bip_utils import Bip39SeedGenerator, Bip32Slip10Secp256k1, Base58Decoder
import binascii

mnemonic = "galaxy man boy evil donkey child cross chair egg meat blood space"
print(f"Mnemonic: {mnemonic}")

seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
print(f"Seed: {binascii.hexlify(seed_bytes).decode()}")

# Master
bip32_ctx = Bip32Slip10Secp256k1.FromSeed(seed_bytes)
print(f"Master:       {bip32_ctx.PrivateKey().Raw().ToHex()}")
print(f"Master Chain: {bip32_ctx.ChainCode().ToHex()}")

# m/44'
k1 = bip32_ctx.DerivePath("44'")
print(f"m/44':        {k1.PrivateKey().Raw().ToHex()}")
print(f"m/44' Ch:     {k1.ChainCode().ToHex()}")

# m/44'/0'
k2 = k1.DerivePath("0'")
print(f"m/44'/0':     {k2.PrivateKey().Raw().ToHex()}")
print(f"m/44'/0' Ch:  {k2.ChainCode().ToHex()}")

# m/44'/0'/0'
k3 = k2.DerivePath("0'")
print(f"m/44'/0'/0':  {k3.PrivateKey().Raw().ToHex()}")
print(f"m/44'/0'/0' Ch: {k3.ChainCode().ToHex()}")

# m/44'/0'/0'/0
k4 = k3.DerivePath("0")
print(f"m/44'/0'/0'/0: {k4.PrivateKey().Raw().ToHex()}")
print(f"m/44'/0'/0'/0 Ch: {k4.ChainCode().ToHex()}")

# m/44'/0'/0'/0/0
k5 = k4.DerivePath("0")
print(f"Final Priv:   {k5.PrivateKey().Raw().ToHex()}")
print(f"Final Pub:    {k5.PublicKey().RawCompressed().ToHex()}")

# Address from k5
addr = k5.PublicKey().ToAddress()
print(f"Address:      {addr}")

decoded = Base58Decoder.CheckDecode(addr)
hash160 = decoded[1:21]
print(f"Hash160:      {binascii.hexlify(hash160).decode()}")
