from bip_utils import Bip39MnemonicValidator, Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
import binascii

mnemonic = "galaxy man boy evil donkey child cross chair egg meat blood space"

print("="*60)
print(f"Mnemonic: {mnemonic}")
print("="*60)

# Seed
seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
print(f"Seed: {binascii.hexlify(seed_bytes).decode()}")

# Master Key
bip44_mst = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
print(f"Master Private Key: {bip44_mst.PrivateKey().Raw().ToHex()}")

# m/44'
node_44h = bip44_mst.Purpose()
print(f"m/44' Private Key:  {node_44h.PrivateKey().Raw().ToHex()}")

# m/44'/0'
node_coin = node_44h.Coin()
print(f"m/44'/0' Private Key: {node_coin.PrivateKey().Raw().ToHex()}")

# m/44'/0'/0'
node_acc = node_coin.Account(0)
print(f"m/44'/0'/0' Private Key: {node_acc.PrivateKey().Raw().ToHex()}")

# m/44'/0'/0'/0
node_change = node_acc.Change(Bip44Changes.CHAIN_EXT)
print(f"m/44'/0'/0'/0 Private Key: {node_change.PrivateKey().Raw().ToHex()}")

# m/44'/0'/0'/0/0
final_node = node_change.AddressIndex(0)
print(f"m/44'/0'/0'/0/0 Private Key: {final_node.PrivateKey().Raw().ToHex()}")

print(f"Address: {final_node.PublicKey().ToAddress()}")
