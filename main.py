import os
import getpass
from Encryptor import Encryptor  # Убедитесь, что класс Encryptor находится в том же каталоге или правильно импортирован


def get_user_choice(prompt, valid_choices):
    """
    Функция для запроса у пользователя выбора из предложенных вариантов.
    Повторяет запрос, пока не будет получен допустимый ответ.
    """
    choice = input(prompt).lower()
    while choice not in valid_choices:
        print("Неверный ввод. Пожалуйста, попробуйте снова.")
        choice = input(prompt).lower()
    return choice


def main():
    encryptor = Encryptor()
    while True:
        print("\nWelcome to the Folder Encryption/Decryption Program.")
        print("1. Encrypt a folder")
        print("2. Decrypt a folder")
        print("3. Exit the program")
        choice = get_user_choice("Option (1/2/3): ", ['1', '2', '3'])

        if choice == '3':
            print("Exiting. Goodbye!")
            break

        folder_path = input("Enter the path of the folder: ")
        while not os.path.isdir(folder_path):
            print("Folder does not exist. Please enter a valid folder path.")
            folder_path = input("Enter the path of the folder: ")

        method = get_user_choice("Choose encryption method (aes/blowfish): ", ['aes', 'blowfish'])

        if choice == '1':
            use_existing_key = get_user_choice("Do you want to use an existing key? (y/n): ", ['y', 'n'])
            if use_existing_key == 'y':
                key_path = input("Enter the path to the key file: ")
                while not os.path.isfile(key_path):
                    print("File does not exist. Please enter a valid file path.")
                    key_path = input("Enter the path to the key file: ")
                with open(key_path, 'rb') as key_file:
                    key = key_file.read()
            else:
                password = input("Enter a password for key generation: ").encode('utf-8')
                salt = os.urandom(16)  # Generate a random salt
                if method == 'aes':
                    key = encryptor.generate_aes_key(password, salt)
                else:
                    key = encryptor.generate_blowfish_key(password, salt)
                key_path = input("Enter the path to save the key file: ")
                with open(key_path, 'wb') as key_file:
                    key_file.write(key)
                print(f"Key saved to {key_path}")
        else:
            key_path = input("Enter the path to the key file: ")
            while not os.path.isfile(key_path):
                print("File does not exist. Please enter a valid file path.")
                key_path = input("Enter the path to the key file: ")
            with open(key_path, 'rb') as key_file:
                key = key_file.read()

        if choice == '1':
            encryptor.encrypt_folder(folder_path, method, key)
            print("Folder encrypted successfully.")
        else:
            encryptor.decrypt_folder(folder_path, method, key)
            print("Folder decrypted successfully.")


if __name__ == "__main__":
    main()
