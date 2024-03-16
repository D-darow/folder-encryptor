import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


class Encryptor:
    """Класс шифратора"""
    def __init__(self):
        pass

    @staticmethod
    def generate_aes_key(password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password)

    @staticmethod
    def encrypt_aes(file_path, key):
        # todo: finish encrypt_aes(file_path, key) later
        with open(file_path, 'wb') as f:
            f.write(os.urandom(16))
