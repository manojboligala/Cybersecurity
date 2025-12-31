from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives import hashes
# 👇 ADD THIS IMPORT
from cryptography.hazmat.backends import default_backend 
import binascii

# --- FIXED INPUTS (from uds_crypto.h) ---
SYMMETRIC_KEY_HEX = "00112233445566778899AABBCCDDEEFF"
STATIC_SEED_HEX   = "A8069EC447D187575A5801AFF71585BB"

# Convert fixed hex strings to bytes
K = binascii.unhexlify(SYMMETRIC_KEY_HEX)
S = binascii.unhexlify(STATIC_SEED_HEX)

print("--- UDS Security Key CMAC Calculator ---")
print(f"Shared Symmetric Key (K): {SYMMETRIC_KEY_HEX}")
print(f"Static Seed (S):          {STATIC_SEED_HEX}\n")

# --- Step 1: Get the Challenge/Seed from the ECU ---
while True:
    try:
        C_hex = input("Step 1: Enter the 16-byte Challenge (Seed) received from the ECU (32 hex characters): ").strip().upper()
        if len(C_hex) != 32:
            print("Error: Input must be exactly 32 hexadecimal characters.")
            continue
        
        # Convert challenge hex string to bytes
        C = binascii.unhexlify(C_hex)
        break
    except binascii.Error:
        print("Error: Invalid hexadecimal characters detected.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

# --- Step 2: Concatenate the Data (Challenge || StaticSeed) ---
M = C + S
M_hex = binascii.hexlify(M).decode().upper()
print(f"\nStep 2: Concatenated Input Message (C || S, 32 bytes): {M_hex}")

# --- Step 3: Calculate the Key (AES-128 CMAC) ---
try:
    # 👇 FIX: Pass the backend argument here
    c = CMAC(algorithms.AES(K), backend=default_backend())
    c.update(M)
    R = c.finalize()
    
    R_hex = binascii.hexlify(R).decode().upper()
    
    print("\n------------------------------------------------------")
    print("✅ Step 3: CALCULATED SECURITY KEY (RESPONSE R):")
    print(f"   {R_hex}")
    print("------------------------------------------------------")
    print("\nStep 4: Enter this 32-character key into the running Client terminal when prompted.")

except Exception as e:
    print(f"\n❌ CMAC Calculation Failed: {e}")
