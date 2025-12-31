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
