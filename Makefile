CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -O2

SRC_DIR := src
BIN_DIR := bin

TARGET := $(BIN_DIR)/dumbski
SRC := $(SRC_DIR)/main.c

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	LDLIBS += -lcrypto
endif

.PHONY: all clean run

all: $(TARGET)


.PHONY: check-linux
check-linux:
	@if [ "$(UNAME_S)" != "Linux" ]; then \
		echo "Error: this project is Linux-only (needs OpenSSL headers + libcrypto)."; \
		exit 2; \
	fi

$(TARGET): check-linux $(SRC) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

clean:
	rm -rf $(BIN_DIR) *.dSYM

run: $(TARGET)
	./$(TARGET) $(ARGS)
