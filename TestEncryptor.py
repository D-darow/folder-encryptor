import unittest
import os
from Encryptor import Encryptor


class TestEncryptor(unittest.TestCase):
    def testEncryptorClassCreation(self):
        encryptor = Encryptor()
        self.assertIsNotNone(encryptor)

    def testGenerateAesKey(self):
        key = Encryptor.generate_aes_key()
        self.assertEqual(44, len(key))


if __name__ == '__main__':
    unittest.main()
