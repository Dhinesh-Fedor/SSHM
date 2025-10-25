CC       := gcc
CFLAGS   := -Wall -Wextra -pedantic -O2 -fPIC -Iinclude
LDFLAGS  := -lsodium -lpthread

SRC_DIR      := src
INC_DIR      := include
BUILD_DIR    := build
OBJ_DIR      := $(BUILD_DIR)/obj
LIB_DIR      := $(BUILD_DIR)/lib
BIN_DIR      := $(BUILD_DIR)/bin
CLI_DIR      := cli

STATIC_LIB  := $(LIB_DIR)/libsshm.a
SHARED_LIB  := $(LIB_DIR)/libsshm.so
CLI_BIN     := $(BIN_DIR)/sshmctl
DAEMON_BIN  := $(BIN_DIR)/sshm_daemon

SRC_FILES  := $(wildcard $(SRC_DIR)/*.c)
OBJ_FILES  := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRC_FILES))

all: dirs $(STATIC_LIB) $(SHARED_LIB) $(CLI_BIN) $(DAEMON_BIN)

dirs:
	@mkdir -p $(OBJ_DIR) $(LIB_DIR) $(BIN_DIR)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(STATIC_LIB): $(OBJ_FILES)
	ar rcs $@ $^

$(SHARED_LIB): $(OBJ_FILES)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# CLI target
$(CLI_BIN): $(CLI_DIR)/sshmctl.c $(STATIC_LIB)
	$(CC) $(CFLAGS) -o $@ $< -I$(INC_DIR) -L$(LIB_DIR) -lsshm $(LDFLAGS)

# Daemon target
$(DAEMON_BIN): $(SRC_DIR)/sshm_daemon.c $(STATIC_LIB)
	$(CC) $(CFLAGS) -o $@ $< -I$(INC_DIR) -L$(LIB_DIR) -lsshm $(LDFLAGS)

clean:
	rm -rf $(OBJ_DIR) $(LIB_DIR) $(BIN_DIR)

.PHONY: all dirs clean
