# Compiler and Flags
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g
# Linker flags: -lcrypto is required for OpenSSL functions (CMAC, RAND_bytes)
LDLIBS = -lcrypto

# Source and Object Files
SERVER_SRC = server.c
CLIENT_SRC = client.c
UTILS_SRC = utils.c
# Both executables depend on utils.o, which is built from utils.c
COMMON_OBJ = $(UTILS_SRC:.c=.o) 

SERVER_EXEC = uds_server
CLIENT_EXEC = uds_client

.PHONY: all clean

# Default target: builds both the client and the server
all: $(SERVER_EXEC) $(CLIENT_EXEC)

# --- Server Compilation ---
$(SERVER_EXEC): $(SERVER_SRC:.c=.o) $(COMMON_OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

# --- Client Compilation ---
$(CLIENT_EXEC): $(CLIENT_SRC:.c=.o) $(COMMON_OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

# --- Compilation Rules for Object Files ---
# Rule for compiling the server and client object files
%.o: %.c uds_crypto.h
	$(CC) $(CFLAGS) -c $< -o $@

# Rule for compiling the utility object file (needs the header)
$(COMMON_OBJ): $(UTILS_SRC) uds_crypto.h
	$(CC) $(CFLAGS) -c $< -o $@

# Target to clean up generated files
clean:
	rm -f $(SERVER_EXEC) $(CLIENT_EXEC) *.o
