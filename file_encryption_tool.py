import os
import base64
import argparse
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def generate_key(password, salt=None):
    """Generate a Fernet key from a password and salt."""
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt


def encrypt_file(file_path, password, output_file=None):
    """Encrypt a text file using a password."""
    try:
        # Generate a key from the password
        key, salt = generate_key(password)
        
        # Create a Fernet cipher with the key
        cipher = Fernet(key)
        
        # Read the file
        with open(file_path, 'rb') as file:
            file_data = file.read()
        
        # Encrypt the data
        encrypted_data = cipher.encrypt(file_data)
        
        # Prepend the salt to the encrypted data
        final_data = salt + encrypted_data
        
        # Determine output file path
        if output_file is None:
            output_file = file_path + '.encrypted'
        
        # Write the encrypted data to the output file
        with open(output_file, 'wb') as file:
            file.write(final_data)
        
        print(f"File encrypted successfully. Output: {output_file}")
        return True
    
    except Exception as e:
        print(f"Encryption failed: {str(e)}")
        return False


def decrypt_file(file_path, password, output_file=None):
    """Decrypt an encrypted text file using a password."""
    try:
        # Read the encrypted file
        with open(file_path, 'rb') as file:
            file_data = file.read()
        
        # Extract the salt (first 16 bytes)
        salt = file_data[:16]
        encrypted_data = file_data[16:]
        
        # Generate the key from the password and salt
        key, _ = generate_key(password, salt)
        
        # Create a Fernet cipher with the key
        cipher = Fernet(key)
        
        # Decrypt the data
        decrypted_data = cipher.decrypt(encrypted_data)
        
        # Determine output file path
        if output_file is None:
            if file_path.endswith('.encrypted'):
                output_file = file_path[:-10] + '.decrypted'
            else:
                output_file = file_path + '.decrypted'
        
        # Write the decrypted data to the output file
        with open(output_file, 'wb') as file:
            file.write(decrypted_data)
        
        print(f"File decrypted successfully. Output: {output_file}")
        return True
    
    except Exception as e:
        print(f"Decryption failed: {str(e)}")
        return False


def main():
    parser = argparse.ArgumentParser(description='Encrypt or decrypt text files with a password.')
    
    parser.add_argument('-e', '--encrypt', action='store_true', help='Encrypt the file')
    parser.add_argument('-d', '--decrypt', action='store_true', help='Decrypt the file')
    parser.add_argument('-f', '--file', required=True, help='File to encrypt/decrypt')
    parser.add_argument('-o', '--output', help='Output file path (optional)')
    
    args = parser.parse_args()
    
    if args.encrypt and args.decrypt:
        print("Error: You can only encrypt or decrypt, not both at the same time.")
        return
    
    if not (args.encrypt or args.decrypt):
        print("Error: You must specify either encrypt (-e) or decrypt (-d).")
        return
    
    if not os.path.isfile(args.file):
        print(f"Error: File '{args.file}' does not exist.")
        return
    
    # Get password securely
    password = getpass("Enter password: ")
    
    if args.encrypt:
        encrypt_file(args.file, password, args.output)
    else:
        decrypt_file(args.file, password, args.output)


if __name__ == "__main__":
    main()
