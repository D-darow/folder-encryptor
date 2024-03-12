import unittest
from Encryptor import Encryptor


class TestEncryptor(unittest.TestCase):
    def testEncryptorClassCreation(self):
        encryptor = Encryptor()
        self.assertIsNotNone(encryptor)


if __name__ == '__main__':
    unittest.main()
