from bip_utils import Bip39SeedGenerator

mnemonic = "galaxy man boy evil donkey child cross chair egg meat blood venture"
try:
    seed = Bip39SeedGenerator(mnemonic).Generate()
    print(f"Venture Seed: {seed.hex()}")
except:
    # Bip39SeedGenerator validates checksum by default. Override?
    # Bip39SeedGenerator(mnemonic, checksum_validation=False) ?
    pass

# We can use mnemonic package or force it.
# Actually bip_utils Bip39SeedGenerator might allow skipping validation?
# documentation says yes? Or Bip39Mnemonic.
from bip_utils import Bip39Mnemonic
try:
    # This might allow invalid?
    seed = Bip39SeedGenerator(mnemonic).Generate() 
except ValueError:
    print("Invalid mnemonic caught by library")

# Use a non-validating method
import hashlib, binascii
salt = b"mnemonic"
pwd = mnemonic.encode('utf-8')
# PBKDF2-HMAC-SHA512, 2048
dk = hashlib.pbkdf2_hmac('sha512', pwd, salt, 2048)
print(f"Manual Seed: {dk.hex()}")
