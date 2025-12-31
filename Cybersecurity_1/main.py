Key : f9d9d55f335df42efd893f76709a257b541300c5beb130a58c29b89e259914df

IV : 0f462f3455317e31991d5ebd14e958a2


## With out Input

import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def generate_password(device_id: str, key_hex: str, iv_hex: str):
    # Convert hex key and IV to bytes
    key = bytes.fromhex(key_hex)
    iv = bytes.fromhex(iv_hex)

    # Validate key and IV sizes
    if len(key) != 32:
        raise ValueError("❌ AES key must be 256 bits (32 bytes / 64 hex characters)")
    if len(iv) != 16:
        raise ValueError("❌ IV must be 128 bits (16 bytes / 32 hex characters)")

    # Step 1: SHA256 hash of the device ID
    sha256_hash = hashlib.sha256(device_id.encode()).digest()

    # Step 2: Pad the SHA256 hash to AES block size
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(sha256_hash) + padder.finalize()

    # Step 3: AES-CBC encryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return {
        'device_id': device_id,
        'sha256': sha256_hash.hex(),
        'aes_key': key_hex,
        'iv': iv_hex,
        'pswd': ciphertext.hex()
    }

# --- 🧑 User Input ---
print("🔐 AES-CBC-256 Encryption")
device_id = input("Enter Device ID: ")
key_input = input("Enter 256-bit AES Key (64 hex characters): ")
iv_input = input("Enter 128-bit IV (32 hex characters): ")

# --- Run the encryption ---
try:
    result = generate_password(device_id, key_input, iv_input)
    print("\n--- 🔒 Encrypted Output ---")
    for k, v in result.items():
        print(f"{k}: {v}")
except ValueError as ve:
    print(f"\n⚠️ Error: {ve}")
    
    
    
## with Input
import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def generate_password(device_id: str, key_hex: str, iv_hex: str):
    # Convert hex key and IV to bytes
    key = bytes.fromhex(key_hex)
    iv = bytes.fromhex(iv_hex)

    # Validate key and IV sizes
    if len(key) != 32:
        raise ValueError("AES key must be 32 bytes (64 hex characters)")
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes (32 hex characters)")

    # Step 1: SHA256 hash of the device ID
    sha256_hash = hashlib.sha256(device_id.encode()).digest()

    # Step 2: Pad the SHA256 hash to AES block size
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(sha256_hash) + padder.finalize()

    # Step 3: AES-CBC encryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return {
        'device_id': device_id,
        'sha256': sha256_hash.hex(),
        'aes_key': key_hex,
        'iv': iv_hex,
        'pswd': ciphertext.hex()
    }

# --- User input (example) ---
device_id = "MyDevice123"
key_input = "00112233445566778899aabbcc7d0eff00112233445566778899aabbccddeeff"  # 64 hex chars
iv_input = "aabbccddeeff00112233445566778839"  # 32 hex chars

# Run the function
result = generate_password(device_id, key_input, iv_input)

# Print results
for k, v in result.items():
    print(f"{k}: {v}")
    
    
## For Random Number generation

import os

# Generate a 256-bit random number (32 bytes)
random_256_bit = os.urandom(32)

# Generate a 128-bit random number (16 bytes)
random_128_bit = os.urandom(16)

# Print results in hexadecimal
print("🔐 Random Numbers")
print(f"256-bit (32 bytes): {random_256_bit.hex()}")
print(f"128-bit (16 bytes): {random_128_bit.hex()}")
