'''A simple password manager made by me, EVAN GRINNELL'''
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import os
import json
import getpass

passwords = {}
decryption_key = None
passwords_file = 'encrypted_passwords.json'

class PasswordManager: # This class handles all of the encrypting/decrypting of passwords
    @staticmethod
    def encrypt_text(text, key): # Encrypts the inputted text with the inputted key
        """
        Args:
            text (string): The password that the user wants to encrypt
            key (string): The key that the user wants to use to encrypt the password

        Returns:
            string: The encrypted password
        """
        key = key.ljust(32)[:32].encode('utf-8')
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(text.encode('utf-8'), AES.block_size))
        return base64.b64encode(iv + encrypted).decode('utf-8')

    @staticmethod
    def decrypt_text(encrypted_text, key): # Decrypts the inputted text with the inputted key
        """
        Args:
            encrypted_text (string): The encrypted password that the user wants to decrypt
            key (string): The key that was used to encrypt the password

        Returns:
            string: The decrypted password
        """       
        key = key.ljust(32)[:32].encode('utf-8')
        encrypted_data = base64.b64decode(encrypted_text)
        iv = encrypted_data[:16]
        encrypted = encrypted_data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
        return decrypted.decode('utf-8')

def load_passwords(): # Loads all of the encrypted passwords from |encrypted_passwords.json| into the |passwords| variable
    global passwords
    if os.path.exists(passwords_file): # Checks if there is a file called |encrypted_passwords.json|
        with open(passwords_file, 'r') as file: # Opens |encrypted_passwords.json| in read mode
            passwords = json.load(file)

def save_passwords(): # Saves all of the encrypted passwords from |passwords| variable into the |encrypted_passwords.json| file
    global passwords
    with open(passwords_file, 'w') as file: # Opens |encrypted_passwords.json| in write mode
        json.dump(passwords, file)

def list_passwords(): # Creates a list of all the passwords and usernames
    """
    Returns:
        string: All of the usernames and passwords compiled into a list
    """ 
    global passwords, decryption_key
    result = ''
    pm = PasswordManager()

    if decryption_key: # Checks to see if |decryption_key| has a value
        for site, password in passwords.items():
            result += f"{site}: {pm.decrypt_text(password, decryption_key)}\n"
    else:
        for site, password in passwords.items():
            result += f"{site}: {password}\n"

    return result

def clear_terminal(): # Clears the termanal
    if os.name == 'nt': # Checks to see if the operating system is Windows or some other operating system
        os.system('cls')
    else:
        os.system('clear')

def main(): # This is the main loop that is the UI
    global passwords, decryption_key

    load_passwords()
    pm = PasswordManager()
    done = False

    while not done:
        clear_terminal()
        print(f'Passwords:\n\n{list_passwords()}')

        print('''Options
        (1) Decrypt all passwords
        (2) Add new password
        (q) Quit
        ''')

        choice = input('')
        clear_terminal()

        if choice == '1': # Checks what the user input was
            decryption_key = getpass.getpass('What is your decryption key: ')
        elif choice == '2':
            site = input('What is the site\'s name: ')
            username_email = input('What is your username / e-mail: ')
            password = getpass.getpass('What is your password: ')

            if decryption_key: # Checks to see if |decryption_key| has a value
                passwords[f'{site}.{username_email}'] = pm.encrypt_text(password, decryption_key)
            else:
                decryption_key = getpass.getpass('What is your decryption key: ')
                passwords[f'{site}.{username_email}'] = pm.encrypt_text(password, decryption_key)
            save_passwords()
        elif choice == 'q':
            save_passwords()
            done = True
        else: # Prints invalid input if the user types an option that is not listed
            print('Invalid input')

if __name__ == '__main__':
    main()