CC ?= gcc

# Include root (for handshake.h) and avx2 (for api.h, params.h, etc.)
INCLUDES = -I. -Iavx2 -Iavx2/keccak4x

# Compiler and Linker flags
CFLAGS = -O3 -mavx2 -msse2avx -march=native -no-pie -fomit-frame-pointer \
         -Wall -Wextra -DNEWHOPE_N=1024 $(INCLUDES)
LDFLAGS = -Wl,-z,noexecstack

# NewHope AVX2 Source Files
NH_DIR = avx2
NH_SRCS = $(NH_DIR)/poly.c \
          $(NH_DIR)/reduce.c \
          $(NH_DIR)/fips202.c \
          $(NH_DIR)/verify.c \
          $(NH_DIR)/cpapke.c \
          $(NH_DIR)/ntt_double.s \
          $(NH_DIR)/ntt.c \
          $(NH_DIR)/precomp.c \
          $(NH_DIR)/fips202x4.c \
          $(NH_DIR)/ccakem.c \
          $(NH_DIR)/randombytes.c

# Precompiled Keccak SIMD object
KECCAK_OBJ = $(NH_DIR)/keccak4x/KeccakP-1600-times4-SIMD256.o

# Common handshake implementation
COMMON_SRCS = handshake.c $(NH_SRCS) $(KECCAK_OBJ)

.PHONY: all clean ensure_symlink

all: ensure_symlink $(KECCAK_OBJ) server client

# Ensure avx2/api.h points to avx2/ccakem.h
ensure_symlink:
	@if [ ! -L $(NH_DIR)/api.h ] && [ ! -f $(NH_DIR)/api.h ]; then \
		ln -sf ccakem.h $(NH_DIR)/api.h; \
	fi

# Rule to compile the Keccak AVX2 SIMD object if missing
$(KECCAK_OBJ): $(NH_DIR)/keccak4x/KeccakP-1600-times4-SIMD256.c
	$(CC) $(CFLAGS) -c $< -o $@

# Build Server
server: server.c $(COMMON_SRCS)
	$(CC) $(CFLAGS) server.c handshake.c $(NH_SRCS) $(KECCAK_OBJ) $(LDFLAGS) -o $@

# Build Client
client: client.c $(COMMON_SRCS)
	$(CC) $(CFLAGS) client.c handshake.c $(NH_SRCS) $(KECCAK_OBJ) $(LDFLAGS) -o $@

clean:
	rm -f server client $(KECCAK_OBJ) $(NH_DIR)/api.h
