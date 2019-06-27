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
