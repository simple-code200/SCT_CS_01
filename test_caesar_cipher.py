import unittest
from caesar_cipher import encrypt, decrypt

class TestCaesarCipher(unittest.TestCase):

    def test_basic_encryption(self):
        self.assertEqual(encrypt("abc", 1), "bcd")
        self.assertEqual(encrypt("xyz", 2), "zab")

    def test_basic_decryption(self):
        self.assertEqual(decrypt("bcd", 1), "abc")
        self.assertEqual(decrypt("zab", 2), "xyz")

    def test_case_sensitivity(self):
        self.assertEqual(encrypt("AbC", 1), "BcD")
        self.assertEqual(decrypt("BcD", 1), "AbC")

    def test_non_alpha_characters(self):
        self.assertEqual(encrypt("hello, world!", 3), "khoor, zruog!")
        self.assertEqual(decrypt("khoor, zruog!", 3), "hello, world!")

    def test_large_shift(self):
        self.assertEqual(encrypt("abc", 27), "bcd")  # 27 % 26 == 1
        self.assertEqual(decrypt("bcd", 27), "abc")

    def test_negative_shift(self):
        self.assertEqual(encrypt("bcd", -1), "abc")
        self.assertEqual(decrypt("abc", -1), "bcd")

    def test_empty_string(self):
        self.assertEqual(encrypt("", 5), "")
        self.assertEqual(decrypt("", 5), "")

if __name__ == "__main__":
    unittest.main()
