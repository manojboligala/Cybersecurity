// server.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/rand.h>

#include "uds_crypto.h"  // contains SYMMETRIC_KEY, STATIC_SEED, typedefs & sizes
// utils.c provides print_hex() and calculate_cmac()
extern void print_hex(const char* label, const uint8_t* data, size_t len);
extern int calculate_cmac(const uint8_t* key, const uint8_t* challenge, const uint8_t* seed, uint8_t* response);

static uint8_t CURRENT_CHALLENGE[SEED_SIZE_BYTES] = {0};

void handle_client(int sock_fd) {
    uds_message_t request, response;
    ssize_t valread;

    printf("\n✅ Client connected. Starting UDS Security Access (Service 27).\n");

    // --- PHASE 1: Client Request Seed (27 01) ---
    valread = read(sock_fd, &request, sizeof(request));
    if (valread <= 0) {
        printf("❌ Error reading from socket.\n");
        return;
    }

    if (request.command != UDS_REQ_SEED_2701) {
        printf("⚠️ Received unexpected command 0x%X (expected 0x%X -> 27 01)\n", request.command, UDS_REQ_SEED_2701);
        // send NRC (reuse your enum)
        response.command = UDS_RES_FAIL_7F35;
        send(sock_fd, &response, sizeof(response), 0);
        print_hex(" [TX] Sent Negative Response (NRC)", (uint8_t*)&response.command, sizeof(response.command));
        return;
    }

    printf(" [RX] Received Client Request: 27 01 (Request Seed)\n");

    // Generate a 128-bit random seed (challenge)
    if (!RAND_bytes(CURRENT_CHALLENGE, SEED_SIZE_BYTES)) {
        fprintf(stderr, "❌ ERROR: Failed to generate random Challenge.\n");
        return;
    }

    // Server sends the seed with 67 01 positive response
    response.command = UDS_RES_SEED_6701;
    memcpy(response.data, CURRENT_CHALLENGE, SEED_SIZE_BYTES);
    send(sock_fd, &response, sizeof(response), 0);
    print_hex(" [TX] Sending Positive Response: 67 01 + Seed (C)", response.data, SEED_SIZE_BYTES);

    // --- PHASE 2: Wait for Client Key (27 02) ---
    printf("\n [SERVER] Waiting for Client Key (27 02)...\n");
    valread = read(sock_fd, &request, sizeof(request));
    if (valread <= 0) {
        printf("❌ Error reading 27 02 from socket.\n");
        return;
    }

    if (request.command != UDS_REQ_KEY_2702) {
        printf("⚠️ Received unexpected command 0x%X (expected 0x%X -> 27 02)\n", request.command, UDS_REQ_KEY_2702);
        response.command = UDS_RES_FAIL_7F35;
        send(sock_fd, &response, sizeof(response), 0);
        print_hex(" [TX] Sent Negative Response (NRC)", (uint8_t*)&response.command, sizeof(response.command));
        return;
    }

    print_hex(" [RX] Received Client Key (R)", request.data, RESPONSE_SIZE_BYTES);

    // --- PHASE 3: Verification ---
    uint8_t expected_response[RESPONSE_SIZE_BYTES];
    if (!calculate_cmac(SYMMETRIC_KEY, CURRENT_CHALLENGE, CURRENT_CHALLENGE, expected_response)) {
        printf("❌ Verification calculation failed.\n");
        return;
    }
    print_hex(" [SERVER] Expected Key (R_exp)", expected_response, RESPONSE_SIZE_BYTES);

    if (memcmp(request.data, expected_response, RESPONSE_SIZE_BYTES) == 0) {
        // Success
        response.command = UDS_RES_PASS_6702;
        send(sock_fd, &response, sizeof(response), 0);
        printf("\n✅ VERIFICATION SUCCESS! ECU Unlocked. [TX]: 67 02 (Positive Response)\n");
    } else {
        // Failure
        response.command = UDS_RES_FAIL_7F35;
        send(sock_fd, &response, sizeof(response), 0);
        printf("\n❌ VERIFICATION FAILED! Invalid Key. [TX]: 7F 35 (Negative Response)\n");
    }
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    // 1. Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // 2. Reuse address
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // 3. Bind
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // 4. Listen
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    printf("--- UDS SERVER (ECU) Ready. Listening on port %d ---\n", PORT);

    // 5. Accept a single client for this demo
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
        perror("accept");
        exit(EXIT_FAILURE);
    }

    handle_client(new_socket);

    close(new_socket);
    close(server_fd);
    return 0;
}

