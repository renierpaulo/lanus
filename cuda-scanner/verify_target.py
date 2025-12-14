from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes, Base58Decoder

mnemonic = "galaxy man boy evil donkey child cross chair egg meat blood space"
seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
print(f"Standard Seed: {seed_bytes.hex()}")

bip44_mst = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
bip44_acc = bip44_mst.Purpose().Coin().Account(0)
bip44_chain = bip44_acc.Change(Bip44Changes.CHAIN_EXT)
bip44_addr = bip44_chain.AddressIndex(0)
print(f"Address: {bip44_addr.PublicKey().ToAddress()}")
print(f"Pubkey: {bip44_addr.PublicKey().RawCompressed().ToHex()}")

# Hash160 of pubkey
import hashlib
ripemd160 = hashlib.new('ripemd160')
ripemd160.update(hashlib.sha256(bip44_addr.PublicKey().RawCompressed().ToBytes()).digest())
pub_hash = ripemd160.hexdigest()
print(f"Pubkey Hash160: {pub_hash}")

# Decode target address
target_addr = "14D3pSqxVQdq2i9299k7KJpNmDoGPcw96B"
decoded = Base58Decoder.CheckDecode(target_addr)
# Version byte is first byte (0x00 for BTC Mainnet P2PKH). Remove it.
pkh = decoded[1:]
print(f"Target Addr Hash160: {pkh.hex()}")
