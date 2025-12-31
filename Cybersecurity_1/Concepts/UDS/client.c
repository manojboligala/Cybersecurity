#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "uds_crypto.h"

// Use the shared utils print function
extern void print_hex(const char* label, const uint8_t* buf, size_t len);
extern int calculate_cmac(const uint8_t* key, const uint8_t* challenge, const uint8_t* seed, uint8_t* response);

// Helper to read a line safely
void read_input(char* buffer, size_t size) {
    if (fgets(buffer, size, stdin) != NULL) {
        size_t len = strlen(buffer);
        if (len > 0 && buffer[len - 1] == '\n') {
            buffer[len - 1] = '\0';
        }
    }
}

// Convert user hex string to bytes
int hexstr_to_bytes(const char* hexstr, uint8_t* bytes, size_t expected_len) {
    size_t len = strlen(hexstr);
    if (len != expected_len * 2) return 0;
    for (size_t i = 0; i < expected_len; i++) {
        if (sscanf(hexstr + 2*i, "%2hhx", &bytes[i]) != 1) return 0;
    }
    return 1;
}

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    uds_message_t request, response;
    char user_key_hex[RESPONSE_SIZE_BYTES*2 + 1];

    printf("========================================================\n");
    printf(" UDS Security Access Client: Diagnostic Tool Simulator\n");
    printf("========================================================\n");

    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, IP_ADDRESS, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address / Address not supported");
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection Failed");
        close(sock);
        return -1;
    }

    printf("--- UDS CLIENT Connected to ECU ---\n");
    print_hex("Client Symmetric Key (K)", SYMMETRIC_KEY, KEY_SIZE_BYTES);

    // --- Step 1: Request Seed (27 01) ---
    char user_cmd[10];
    printf("\n[CLIENT]: Enter UDS command (e.g., '27 01') to request seed: ");
    read_input(user_cmd, sizeof(user_cmd));

    if (strcmp(user_cmd, "27 01") != 0) {
        printf("❌ Invalid command. Exiting.\n");
        close(sock);
        return 1;
    }

    request.command = UDS_REQ_SEED_2701;
    send(sock, &request, sizeof(request), 0);
    printf("  [TX]: Sent Request Seed (27 01)\n");

    // --- Step 2: Receive Seed (67 01) ---
    read(sock, &response, sizeof(response));
    if (response.command != UDS_RES_SEED_6701) {
        printf("❌ Failed to receive seed response. Exiting.\n");
        close(sock);
        return 1;
    }

    print_hex("  [RX]: Received Seed (C)", response.data, SEED_SIZE_BYTES);

    // --- Step 3: Ask user to enter calculated key manually ---
    printf("\n[CLIENT]: Enter the calculated key (hex, 32 characters) manually: ");
    read_input(user_key_hex, sizeof(user_key_hex));

    uint8_t user_key[RESPONSE_SIZE_BYTES];
    if (!hexstr_to_bytes(user_key_hex, user_key, RESPONSE_SIZE_BYTES)) {
        printf("❌ Invalid key format. Exiting.\n");
        close(sock);
        return 1;
    }

    // --- Step 4: Send Key (27 02) ---
    request.command = UDS_REQ_KEY_2702;
    memcpy(request.data, user_key, RESPONSE_SIZE_BYTES);
    send(sock, &request, sizeof(request), 0);
    printf("  [TX]: Sent User Key (27 02) for verification\n");

    // --- Step 5: Receive Server Verification ---
    read(sock, &response, sizeof(response));
    if (response.command == UDS_RES_PASS_6702) {
        printf("\n✅ ACCESS GRANTED! Server responded with 67 02.\n");
    } else if (response.command == UDS_RES_FAIL_7F35) {
        printf("\n❌ ACCESS DENIED! Server responded with 7F 35 (Invalid Key).\n");
    } else {
        printf("\n⚠️ Unknown response from server.\n");
    }

    close(sock);
    return 0;
}

