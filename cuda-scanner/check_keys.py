from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins
import binascii

mnemonic = "galaxy man boy evil donkey child cross chair egg meat blood space"
seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
bip44_mst = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)

print(f"Master: {bip44_mst.PrivateKey().Raw().ToHex()}")
print(f"m/44':  {bip44_mst.Purpose().PrivateKey().Raw().ToHex()}")
print(f"m/44'/0': {bip44_mst.Purpose().Coin().PrivateKey().Raw().ToHex()}")
