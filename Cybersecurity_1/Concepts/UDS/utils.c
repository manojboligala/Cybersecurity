// utils.c
#include <stdio.h>
#include <string.h>
#include <fcntl.h>     // <-- ADDED
#include <unistd.h>    // <-- ADDED
#include <openssl/cmac.h>
#include <openssl/evp.h>
#include "uds_crypto.h"

void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s (Size: %zu): ", label, len);
    for (size_t i = 0; i < len; ++i) printf("%02X", data[i]);
    printf("\n");
}

/* ================= ADDED FUNCTION ================= */
/* TRNG-backed dynamic seed generation (Linux) */
int generate_dynamic_seed(uint8_t *seed, size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
        return 0;

    ssize_t r = read(fd, seed, len);
    close(fd);

    return (r == (ssize_t)len);
}
/* ================================================== */

// Compute CMAC of (challenge || seed) using AES-128 CMAC
int calculate_cmac(const uint8_t* key,
                   const uint8_t* challenge,
                   const uint8_t* seed,
                   uint8_t* response)
{
    CMAC_CTX *ctx = CMAC_CTX_new();
    if (!ctx) return 0;

    uint8_t input[SEED_SIZE_BYTES + SEED_SIZE_BYTES];
    memcpy(input, challenge, SEED_SIZE_BYTES);
    memcpy(input + SEED_SIZE_BYTES, seed, SEED_SIZE_BYTES);

    size_t out_len = 0;
    if (!CMAC_Init(ctx, key, KEY_SIZE_BYTES, EVP_aes_128_cbc(), NULL)) goto err;
    if (!CMAC_Update(ctx, input, sizeof(input))) goto err;
    if (!CMAC_Final(ctx, response, &out_len)) goto err;

    CMAC_CTX_free(ctx);
    return (out_len == RESPONSE_SIZE_BYTES);

err:
    CMAC_CTX_free(ctx);
    return 0;
}
