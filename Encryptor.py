import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import Blowfish
from Crypto.Protocol.KDF import scrypt


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
    def generate_blowfish_key(password, salt):
        return scrypt(password, salt, 32, N=2 ** 14, r=8, p=1)

    @staticmethod
    def encrypt_aes(file_path, key):
        iv = os.urandom(16)

        with open(file_path, 'rb') as f:
            plaintext = f.read()

        backend = default_backend()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(128).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()

        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        # Сохранение IV вместе с зашифрованными данными
        with open(file_path, 'wb') as f:
            f.write(iv + ciphertext)

    @staticmethod
    def encrypt_blowfish(file_path, key):
        with open(file_path, 'rb') as f:
            plaintext = f.read()

        blowfish_cipher = Blowfish.new(key, Blowfish.MODE_ECB)
        padder = padding.PKCS7(128).padder()
        ciphertext = blowfish_cipher.encrypt(padder.update(plaintext) + padder.finalize())

        with open(file_path, 'wb') as f:
            f.write(ciphertext)

    @staticmethod
    def decrypt_aes(file_path, key):
        with open(file_path, 'rb') as f:
            iv_with_ciphertext = f.read()

        # Извлечение IV и зашифрованных данных
        iv = iv_with_ciphertext[:16]
        ciphertext = iv_with_ciphertext[16:]

        backend = default_backend()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()

        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

        with open(file_path, 'wb') as f:
            f.write(unpadded_data)

    @staticmethod
    def decrypt_blowfish(file_path, key):
        with open(file_path, 'rb') as f:
            ciphertext = f.read()

        twofish_cipher = Blowfish.new(key, Blowfish.MODE_ECB)
        decrypted_data = twofish_cipher.decrypt(ciphertext)

        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

        with open(file_path, 'wb') as f:
            f.write(unpadded_data)

    def encrypt_folder(self, folder_path, key):
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                self.encrypt_aes(file_path, key)

    def decrypt_folder(self, folder_path, key):
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                self.decrypt_aes(file_path, key)
