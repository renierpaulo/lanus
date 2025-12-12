import hashlib
import binascii
import itertools
from multiprocessing import Pool, cpu_count

# Target address
TARGET_ADDRESS = "1At7z8J3t3JJiAqtBTyJuHdCMKx45HmyVp"

# Words from the image (Rows of 3 options)
WORD_ROWS = [
    ["galaxy", "man", "boy"],
    ["devil", "donkey", "child"],
    ["cross", "chair", "egg"],
    ["meat", "blood", "venture"],
    ["space", "oxygen", "laugh"],
    ["monster", "two", "dress"],
    ["evil", "face", "green"],
    ["demise", "drop", "happy"],
    ["steak", "donate", "couple"],
    ["beef", "donor", "girl"],
    ["head", "mule", "woman"],
    ["suit", "old", "family"]
]

# Note: The last few rows in the user message were:
# "give", "clown", "elder", "window", "couch"
# Let's re-read the user message carefully.
# The user text:
# galaxy man boy
# devil donkey child
# cross chair egg
# meat blood venture
# space oxygen laugh
# monster two dress
# evil face green
# demise drop happy
# steak donate couple
# beef donor girl
# head mule woman
# suit old family
#      give clown
#      elder window
#      couch
# There are extra lines!
# "suit old family" seems to be row 12.
# Then "give clown", "elder window", "couch".
# This suggests there might be MORE than 12 rows, or some rows have >3 options?
# Or maybe the seed is 15 words? 18 words? 24?
# 12 words is standard. 24 is standard. 15/18/21 are non-standard.
# If it's a 24 word seed, we need 24 rows.
# There are 15 text lines total?
# 12 lines of 3 words = 36 words.
# + give, clown (line 13)
# + elder, window (line 14)
# + couch (line 15)
# Total lines = 15.
# If the target is a "12 word wallet", then maybe the extra words are distractors or the last lines are alternatives for the last position?
# Let's assume the first 12 rows are the candidates for the 12 words.
# We will check this first.
# If it fails, we might consider 24 words, but we don't have enough rows (need 24).
# So we stick to 12 words.

def derive_address(mnemonic):
    # This is a simplified derivation for checking. 
    # For speed, valid BIP39 derivation requires pbkdf2_hmac which is slow.
    # We use fastpbkdf2 if available or standard hashlib.
    
    seed = hashlib.pbkdf2_hmac(
        'sha512', 
        mnemonic.encode('utf-8'), 
        b'mnemonic', 
        2048
    )
    
    # Master Key (simple check, assume m/44'/0'/0'/0/0 or similar)
    # Implementing full BIP32 here is verbose.
    # We can use 'bip_utils' or 'mnemonic' lib if installed, but to be dependency-free is hard.
    # Given the constraint, valid verification needs proper ECC.
    # We can assume the user has a way to check or we use a library.
    # But wait, looking for a GPU scanner implies BRUTE FORCE.
    # If the space is small (500k), we can generate the list of mnemonics and feed it to the GPU scanner!
    # Yes! That exploits the 5090 speed for the crypto part.
    return mnemonic

def generate_combinations():
    count = 0
    with open("candidates.txt", "w") as f:
        for p in itertools.product(*WORD_ROWS[0:12]):
            mnemonic = " ".join(p)
            f.write(mnemonic + "\n")
            count += 1
    print(f"Generated {count} candidates in candidates.txt")
    
if __name__ == "__main__":
    generate_combinations()
