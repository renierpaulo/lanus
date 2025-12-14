from bip_utils import Bip39MnemonicValidator, Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
import binascii

mnemonic = "galaxy man boy evil donkey child cross chair egg meat blood space"
try:
    # Validate
    is_valid = Bip39MnemonicValidator().Validate(mnemonic)
    print(f"Mnemonic: {mnemonic}")
    print(f"Valid: {is_valid}")

    # Seed
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    print(f"Seed: {binascii.hexlify(seed_bytes).decode()}")

    # Derive Address
    bip44_mst = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
    bip44_acc = bip44_mst.Purpose().Coin().Account(0)
    bip44_chain = bip44_acc.Change(Bip44Changes.CHAIN_EXT)
    bip44_addr = bip44_chain.AddressIndex(0)

    print(f"Address: {bip44_addr.PublicKey().ToAddress()}")
    print(f"PrivKey: {bip44_addr.PrivateKey().Raw().ToHex()}")
    print(f"PubKey: {bip44_addr.PublicKey().RawCompressed().ToHex()}")
    
    # Hash160 (RIPEMD160(SHA256(PubKey))) - Manual check if needed, but address covers it
    # We can try to decode address to see the hash160
    from bip_utils import Base58Decoder
    decoded = Base58Decoder.CheckDecode(bip44_addr.PublicKey().ToAddress())
    # First byte is version, last 4 are checksum. Inner 20 bytes are hash160.
    hash160 = decoded[1:21]
    print(f"Hash160: {binascii.hexlify(hash160).decode()}")

except Exception as e:
    print(f"Error: {e}")
