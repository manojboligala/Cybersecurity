#ifndef UDS_CRYPTO_H
#define UDS_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

// --- Network Configuration ---
#define PORT 8080
#define IP_ADDRESS "127.0.0.1"

// --- Security Access (Service 27) Configuration ---
#define KEY_SIZE_BYTES 16     // AES-128 key size
#define SEED_SIZE_BYTES 16    // Challenge size (16 bytes)
#define RESPONSE_SIZE_BYTES 16 // CMAC size (16 bytes)

// --- Shared Secrets (Known by both Client and Server) ---
// The secret AES-128 Key (K)
static const uint8_t SYMMETRIC_KEY[KEY_SIZE_BYTES] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
};

// The fixed Static Seed (S) used in the CMAC calculation: Challenge || StaticSeed
/*static const uint8_t STATIC_SEED[SEED_SIZE_BYTES] = {
    0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 
    0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F
}; */

// --- UDS Command Definitions ---
// Requests
#define UDS_REQ_SEED_2701 0x2701 // SecurityAccess (Request Seed)
#define UDS_REQ_KEY_2702 0x2702  // SecurityAccess (Send Key)

// Positive Responses
#define UDS_RES_SEED_6701 0x6701 // SecurityAccess (Positive Response + Seed)
#define UDS_RES_PASS_6702 0x6702 // SecurityAccess (Positive Response - Access Granted)

// Negative Response Codes (NRC)
#define UDS_RES_FAIL_7F35 0x7F35 // SecurityAccess (NRC: Invalid Key)

// --- UDS Message Structure ---
// Simplified UDS message structure for this specific 27 protocol flow
typedef struct {
    uint16_t command; // e.g., 0x2701, 0x6701, 0x7F35
    uint8_t data[SEED_SIZE_BYTES]; // Data payload (Seed or Key)
} uds_message_t;

#endif // UDS_CRYPTO_H

