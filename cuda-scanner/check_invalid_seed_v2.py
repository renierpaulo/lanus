import hashlib

mnemonic = "galaxy man boy evil donkey child cross chair egg meat blood venture"
salt = b"mnemonic"
pwd = mnemonic.encode('utf-8')
dk = hashlib.pbkdf2_hmac('sha512', pwd, salt, 2048)
print(f"Manual Seed: {dk.hex()}")
