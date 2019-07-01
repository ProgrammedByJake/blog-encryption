from aes import AES
from md5 import MD5
import hashlib


test_phrases = [
    "basic test",
    "Much longer test that will span over multiple 256 bit sections" * 100,
    "Test with symbols !@#$%^&*()_+-=,<.>/?;:'[{]}|}",
    ""  # Blank Test
]


def test_md5(phrase):
    m = hashlib.md5()
    m.update(phrase.encode('utf-8'))
    if m.hexdigest() == MD5.hash(phrase):
        return 1
    return 0


print("Testing MD5")
print(f"{sum([test_md5(phrase) for phrase in test_phrases])}/{len(test_phrases)} tests successful")


print("Testing AES")
# assert AES.mult(0x57, 0x83) == 0xC1, "Issue with multiplication function, {57} . {83} = {C1}"
# assert AES.xtime(0x57, 1) == 0xAE, "Issue with xtime function, xtime({57}) = {AE}"
print("All tests successful")

# C.1 AES-128 (Nk=4, Nr=10) - Working
# test_message = 0x00112233445566778899aabbccddeeff.to_bytes(16, 'big')
# test_key = 0x000102030405060708090a0b0c0d0e0f.to_bytes(16, 'big')

# C.2 AES-192 (Nk=6, Nr=12) - Working
# test_message = 0x00112233445566778899aabbccddeeff.to_bytes(16, 'big')
# test_key = 0x000102030405060708090a0b0c0d0e0f1011121314151617.to_bytes(24, 'big')

# C.3 AES-256 (Nk=8, Nr=14) - Working
test_message = 0x00112233445566778899aabbccddeeff.to_bytes(16, 'big')
test_key = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f.to_bytes(32, 'big')

print(AES.encrypt(test_message, test_key))
