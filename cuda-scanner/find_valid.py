from bip_utils import Bip39MnemonicValidator, Bip39WordsNum, Bip39Languages

validator = Bip39MnemonicValidator(Bip39Languages.ENGLISH)
words = "galaxy man boy evil donkey child cross chair egg meat blood".split()

# Try all words in the wordlist as the 12th word
wordlist = validator.GetWordList()
for word in wordlist:
    candidate = list(words) + [word]
    mnemonic = " ".join(candidate)
    try:
        if validator.Validate(mnemonic):
            print(f"Valid phrase: {mnemonic}")
            break
    except:
        pass
