from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import b64encode, b64decode

# Function to generate a key from a password
def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm='sha256',
        length=32,  # 256 bit key
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Function to encrypt the file
def encrypt_file(file_path: str, password: str, output_file: str):
    # Read the content of the file
    with open(file_path, 'rb') as file:
        data = file.read()
    
    # Generate a salt and key from the password
    salt = os.urandom(16)
    key = generate_key(password, salt)

    # Create the cipher object
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the data to ensure it's a multiple of block size (16 bytes for AES)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Encrypt the data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Write the encrypted data to the output file
    with open(output_file, 'wb') as file:
        file.write(salt + iv + encrypted_data)

    print(f"Encryption complete. Encrypted data saved to {output_file}")

# Function to decrypt the file
def decrypt_file(file_path: str, password: str, output_file: str):
    # Read the encrypted file
    with open(file_path, 'rb') as file:
        file_data = file.read()

    # Extract salt, iv, and encrypted data
    salt = file_data[:16]
    iv = file_data[16:32]
    encrypted_data = file_data[32:]

    # Generate the key from the password
    key = generate_key(password, salt)

    # Create the cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the data
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Unpad the decrypted data
    unpadder = padding.PKCS7(128).unpadder()
    original_data = unpadder.update(decrypted_data) + unpadder.finalize()

    # Write the decrypted data to the output file
    with open(output_file, 'wb') as file:
        file.write(original_data)

    print(f"Decryption complete. Decrypted data saved to {output_file}")

# Main function
def main():
    print("File Encryption/Decryption Tool")
    action = input("Do you want to (e)ncrypt or (d)ecrypt a file? ").strip().lower()

    if action == 'e':
        file_path = input("Enter the path of the file to encrypt: ").strip()
        password = input("Enter the password for encryption: ").strip()
        output_file = input("Enter the output file name for the encrypted file: ").strip()
        encrypt_file(file_path, password, output_file)

    elif action == 'd':
        file_path = input("Enter the path of the file to decrypt: ").strip()
        password = input("Enter the password for decryption: ").strip()
        output_file = input("Enter the output file name for the decrypted file: ").strip()
        decrypt_file(file_path, password, output_file)

    else:
        print("Invalid option. Please choose either 'e' for encrypt or 'd' for decrypt.")

if __name__ == '__main__':
    main()
