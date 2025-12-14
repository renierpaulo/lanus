from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes

mnemonic = "galaxy man boy evil donkey child cross chair egg meat blood venture"
seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
bip44_mst = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
bip44_acc = bip44_mst.Purpose().Coin().Account(0)
bip44_chain = bip44_acc.Change(Bip44Changes.CHAIN_EXT)
bip44_addr = bip44_chain.AddressIndex(0)

print(f"Address: {bip44_addr.PublicKey().ToAddress()}")
