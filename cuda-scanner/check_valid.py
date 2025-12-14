from bip_utils import Bip39MnemonicValidator

mnemonic = "galaxy man boy evil donkey child cross chair egg meat blood venture"
try:
    is_valid = Bip39MnemonicValidator().Validate(mnemonic)
    print(f"Valid: {is_valid}")
except Exception as e:
    print(f"Invalid: {e}")
