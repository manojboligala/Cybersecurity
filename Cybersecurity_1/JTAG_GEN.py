import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
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

    # Step 1: SHA256 hash of the device ID (32 bytes)
    sha256_hash = hashlib.sha256(device_id.encode()).digest()

    # Step 2: AES-CBC encryption (without padding)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(sha256_hash) + encryptor.finalize()

    return {
        'device_id': device_id,
        'sha256': sha256_hash.hex(),
        'aes_key': key_hex,
        'iv': iv_hex,
        'pswd': ciphertext.hex()  # This will now be exactly 64 hex chars (32 bytes)
    }

# --- User Input ---
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
