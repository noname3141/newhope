#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include <stddef.h>
#include <stdint.h>
#include "api.h" // From NewHope (defines CRYPTO_* constants)

#define MSG_TYPE_PUBLIC_KEY  0x01
#define MSG_TYPE_CIPHERTEXT  0x02
#define MSG_TYPE_SUCCESS     0x03

#pragma pack(push, 1)
typedef struct {
    uint8_t  type;
    uint32_t length;
} frame_header_t;
#pragma pack(pop)

typedef struct {
    int socket_fd;
    uint8_t shared_secret[CRYPTO_BYTES];
} pqc_conn_t;

// API
pqc_conn_t* pqc_listen_and_accept(int port);
pqc_conn_t* pqc_connect(const char *ip, int port);
void        pqc_close(pqc_conn_t *conn);

// Wire helpers
int send_exact(int fd, const void *buf, size_t total_bytes);
int recv_exact(int fd, void *buf, size_t total_bytes);

#endif
