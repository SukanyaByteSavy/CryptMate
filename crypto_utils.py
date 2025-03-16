import os
import logging
from crypto_impl import CryptoUtils
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def generate_key_pair():
    """Generate RSA key pair for hybrid encryption"""
    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        return private_key.public_key(), private_key
    except Exception as e:
        logger.error(f"RSA key pair generation failed: {str(e)}")
        raise RuntimeError(f"Key pair generation failed: {str(e)}")

def encrypt_file_aes(file_path):
    """Encrypt a file using AES-256 in CBC mode"""
    try:
        logger.debug(f"Starting AES encryption of file: {file_path}")
        logger.debug(f"Using OpenSSL version: {CryptoUtils.get_openssl_version()}")

        # Calculate initial entropy
        initial_entropy = CryptoUtils.calculate_entropy(file_path)
        logger.debug(f"Input file entropy: {initial_entropy:.2f} bits per byte")

        # Use C++ implementation for file encryption
        try:
            key_hex, encrypted_file = CryptoUtils.encrypt_file(file_path)
            logger.debug(f"Encryption successful, key length: {len(key_hex)}")

            # Validate generated key
            if not CryptoUtils.validate_key(key_hex):
                raise ValueError("Generated key validation failed")

            # Calculate encrypted file entropy
            encrypted_entropy = CryptoUtils.calculate_entropy(encrypted_file)
            logger.debug(f"Encrypted file entropy: {encrypted_entropy:.2f} bits per byte")

            return key_hex, encrypted_file
        except Exception as e:
            logger.error(f"C++ encryption failed: {str(e)}")
            raise
    except Exception as e:
        logger.error(f"File encryption failed: {str(e)}")
        raise RuntimeError(f"File encryption failed: {str(e)}")

def decrypt_file_aes(file_path, key_hex):
    """Decrypt a file using AES-256 in CBC mode"""
    try:
        logger.debug(f"Starting AES decryption of file: {file_path}")

        # Validate key before attempting decryption
        if not CryptoUtils.validate_key(key_hex):
            raise ValueError("Invalid decryption key format")

        # Use C++ implementation for file decryption
        try:
            decrypted_file = CryptoUtils.decrypt_file(file_path, key_hex)
            logger.debug(f"Decryption successful, output file: {decrypted_file}")
            return decrypted_file
        except Exception as e:
            logger.error(f"C++ decryption failed: {str(e)}")
            raise
    except Exception as e:
        logger.error(f"File decryption failed: {str(e)}")
        raise RuntimeError(f"File decryption failed: {str(e)}")

def encrypt_file_rsa(file_path, public_key):
    """Encrypt a file using RSA public key (hybrid encryption with AES)"""
    try:
        # For hybrid encryption, we'll use AES for the file and RSA for the AES key
        key_hex, encrypted_file = encrypt_file_aes(file_path)
        logger.debug("AES encryption completed, encrypting AES key with RSA")

        # Encrypt the AES key with RSA
        encrypted_key = public_key.encrypt(
            key_hex.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        logger.debug(f"RSA encryption of AES key completed, encrypted key size: {len(encrypted_key)}")

        # Create final encrypted file with encrypted key
        final_encrypted_file = encrypted_file + ".rsa"
        with open(final_encrypted_file, 'wb') as f:
            # Write the size of encrypted key and the key itself
            f.write(len(encrypted_key).to_bytes(4, byteorder='big'))
            f.write(encrypted_key)
            # Append the encrypted file content
            with open(encrypted_file, 'rb') as ef:
                f.write(ef.read())
        logger.debug("Created final encrypted file with key and data")

        # Clean up intermediate file
        os.unlink(encrypted_file)
        return final_encrypted_file
    except Exception as e:
        logger.error(f"RSA encryption failed: {str(e)}")
        raise RuntimeError(f"RSA encryption failed: {str(e)}")

def decrypt_file_rsa(file_path, private_key_pem):
    """Decrypt a file using RSA private key"""
    try:
        # Load private key
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None,
            backend=default_backend()
        )
        logger.debug("Loaded RSA private key")

        # Read the encrypted file
        with open(file_path, 'rb') as f:
            # Read the encrypted AES key
            key_size = int.from_bytes(f.read(4), byteorder='big')
            encrypted_key = f.read(key_size)
            # Read the rest as encrypted data
            encrypted_data = f.read()
        logger.debug(f"Read encrypted file: key size {key_size}, data size {len(encrypted_data)}")

        # Create temporary file for AES-encrypted data
        temp_aes_file = file_path + ".aes_temp"
        with open(temp_aes_file, 'wb') as f:
            f.write(encrypted_data)

        # Decrypt the AES key
        key_hex = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()
        logger.debug("Decrypted AES key with RSA")

        # Decrypt the file using AES
        decrypted_file = decrypt_file_aes(temp_aes_file, key_hex)
        logger.debug("Completed AES decryption")

        # Clean up intermediate file
        os.unlink(temp_aes_file)
        return decrypted_file
    except Exception as e:
        logger.error(f"RSA decryption failed: {str(e)}")
        raise RuntimeError(f"RSA decryption failed: {str(e)}")