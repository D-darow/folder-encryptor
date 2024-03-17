import unittest
import os
from Encryptor import Encryptor


class TestEncryptor(unittest.TestCase):
    def testEncryptorClassCreation(self):
        encryptor = Encryptor()
        self.assertIsNotNone(encryptor)

    def testGenerateAesKey(self):
        key = Encryptor.generate_aes_key('123'.encode(), os.urandom(16))
        self.assertEqual(32, len(key))

    def testGenerateAesKeyWithSaltAndKeyMaterial(self):
        key = Encryptor.generate_aes_key('123'.encode(), b'ECGcProLV1ikU3LPLdNfBQ==')
        self.assertEqual(key, b'9\x9b\xc3qri\xd5\xe4\xbfq\x8a\xccA\x94\xe75o\x7f\x8f5\xec\xae<\x1d\x8a0N9'b'\xbf\xa6^+')

    def testGenerateAesKeyWithSaltAndKeyMaterial2(self):
        key = Encryptor.generate_aes_key('321'.encode(), b'\x8f\xaaC\xcf-\x8e8D\xf4ND\xfc\xdf3\xc0d')
        self.assertEqual(key, b'|\x8c_\x0c\xc1\xed\x9by\xc5\xf1}D\xda\xf5[\xa5\xd60\x8bv\x8a\xbeL\xb4'
                              b'\x19%\x8f\x9eP\xdaK\xa4')

    def testOneFileEncryption(self):
        file, file_encrypted = 0, 0
        key = Encryptor.generate_aes_key('123'.encode(), b'ECGcProLV1ikU3LPLdNfBQ==')
        with open('test/test.txt', 'rb') as f:
            file = f.read()
        Encryptor.encrypt_aes(os.path.abspath('test/test.txt'), key)
        with open('test/test.txt', 'rb') as f:
            file_encrypted = f.read()
        self.assertNotEqual(file, file_encrypted)

    def testOneFileEncryptionAndDecryption(self):
        file_before_encryption, file_after_encryption = 0, 0
        key = Encryptor.generate_aes_key('123'.encode(), b'ECGcProLV1ikU3LPLdNfBQ==')
        with open('test/test2.txt', 'rb') as f:
            file_before_encryption = f.read()
        Encryptor.encrypt_aes(os.path.abspath('test/test2.txt'), key)
        Encryptor.decrypt_aes(os.path.abspath('test/test2.txt'), key)
        with open('test/test2.txt', 'rb') as f:
            file_after_encryption = f.read()
        self.assertEqual(file_before_encryption, file_after_encryption)


if __name__ == '__main__':
    unittest.main()
