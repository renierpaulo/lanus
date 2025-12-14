from bip_utils import Bip39MnemonicValidator

words_pool = "galaxy man boy evil donkey child cross chair egg meat blood venture space oxygen laugh monster two dress evil face green demise drop happy steak donate couple beef donor girl head mule woman suit old friend give clown elder window couch".split()
prefix = words_pool[:11] 

for w in words_pool:
    cand = prefix + [w]
    mnem = " ".join(cand)
    try:
        Bip39MnemonicValidator().Validate(mnem)
        print(f"FOUND VALID: {mnem}")
    except:
        pass
