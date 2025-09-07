# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -Isrc/include -fPIC

# Folders
SRC = src/lib
OBJ = build/obj
BIN = build/bin

# Sources and objects
SRCS = $(wildcard $(SRC)/*.c)
OBJS = $(SRCS:$(SRC)/%.c=$(OBJ)/%.o)

# Library name
STATIC_LIB = $(BIN)/libsshm.a
SHARED_LIB = $(BIN)/libsshm.so

# Default: build both libs
all: $(STATIC_LIB) $(SHARED_LIB)

# Static library
$(STATIC_LIB): $(OBJS)
	@mkdir -p $(BIN)
	ar rcs $@ $^

# Shared library
$(SHARED_LIB): $(OBJS)
	@mkdir -p $(BIN)
	$(CC) -shared -o $@ $^

# Compile each .c into .o
$(OBJ)/%.o: $(SRC)/%.c
	@mkdir -p $(OBJ)
	$(CC) $(CFLAGS) -c $< -o $@

# Clean
clean:
	rm -rf $(OBJ) $(BIN)

