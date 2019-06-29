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
assert AES.mult(0x57, 0x83) == 0xC1, "Issue with multiplication function, {57} . {83} = {C1}"
assert AES.xtime(0x57, 1) == 0xAE, "Issue with xtime function, xtime({57}) = {AE}"
print("All tests successful")

print(AES.encrypt("testblahedit", "tresdfhgefrtghtd"))
