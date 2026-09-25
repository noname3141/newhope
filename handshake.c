#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "handshake.h"

int send_exact(int fd, const void *buf, size_t total_bytes) {
    size_t sent = 0;
    const uint8_t *p = (const uint8_t *)buf;
    while (sent < total_bytes) {
        ssize_t n = write(fd, p + sent, total_bytes - sent);
        if (n <= 0) return -1;
        sent += n;
    }
    return 0;
}

int recv_exact(int fd, void *buf, size_t total_bytes) {
    size_t received = 0;
    uint8_t *p = (uint8_t *)buf;
    while (received < total_bytes) {
        ssize_t n = read(fd, p + received, total_bytes - received);
        if (n <= 0) return -1;
        received += n;
    }
    return 0;
}

static int send_frame(int fd, uint8_t type, const void *payload, uint32_t len) {
    frame_header_t hdr;
    hdr.type = type;
    hdr.length = htonl(len);
    if (send_exact(fd, &hdr, sizeof(hdr)) != 0) return -1;
    if (len > 0 && send_exact(fd, payload, len) != 0) return -1;
    return 0;
}

static int recv_frame(int fd, uint8_t expected_type, void *payload, uint32_t expected_len) {
    frame_header_t hdr;
    if (recv_exact(fd, &hdr, sizeof(hdr)) != 0) return -1;
    if (hdr.type != expected_type || ntohl(hdr.length) != expected_len) return -1;
    if (expected_len > 0 && recv_exact(fd, payload, expected_len) != 0) return -1;
    return 0;
}

pqc_conn_t* pqc_listen_and_accept(int port) {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 || listen(server_fd, 1) < 0) {
        close(server_fd);
        return NULL;
    }

    printf("[Server] Awaiting incoming connection on port %d...\n", port);
    int client_fd = accept(server_fd, NULL, NULL);
    close(server_fd);
    if (client_fd < 0) return NULL;

    // --- NewHope Handshake ---
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];

    // 1. Generate keypair
    crypto_kem_keypair(pk, sk);

    // 2. Transmit public key
    if (send_frame(client_fd, MSG_TYPE_PUBLIC_KEY, pk, CRYPTO_PUBLICKEYBYTES) != 0) {
        close(client_fd);
        return NULL;
    }

    // 3. Receive ciphertext
    if (recv_frame(client_fd, MSG_TYPE_CIPHERTEXT, ct, CRYPTO_CIPHERTEXTBYTES) != 0) {
        close(client_fd);
        return NULL;
    }

    pqc_conn_t *conn = malloc(sizeof(pqc_conn_t));
    conn->socket_fd = client_fd;

    // 4. Decapsulate to recover shared secret
    crypto_kem_dec(conn->shared_secret, ct, sk);

    // Secure erasure of secret key from stack
    memset(sk, 0, sizeof(sk));

    // Send confirmation signal
    send_frame(client_fd, MSG_TYPE_SUCCESS, NULL, 0);

    return conn;
}

pqc_conn_t* pqc_connect(const char *ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return NULL;
    }

    // --- NewHope Handshake ---
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];

    pqc_conn_t *conn = malloc(sizeof(pqc_conn_t));
    conn->socket_fd = sock;

    // 1. Receive server public key
    if (recv_frame(sock, MSG_TYPE_PUBLIC_KEY, pk, CRYPTO_PUBLICKEYBYTES) != 0) {
        close(sock);
        free(conn);
        return NULL;
    }

    // 2. Encapsulate shared secret
    crypto_kem_enc(ct, conn->shared_secret, pk);

    // 3. Transmit ciphertext back to server
    if (send_frame(sock, MSG_TYPE_CIPHERTEXT, ct, CRYPTO_CIPHERTEXTBYTES) != 0) {
        close(sock);
        free(conn);
        return NULL;
    }

    // 4. Await confirmation signal
    if (recv_frame(sock, MSG_TYPE_SUCCESS, NULL, 0) != 0) {
        close(sock);
        free(conn);
        return NULL;
    }

    return conn;
}

void pqc_close(pqc_conn_t *conn) {
    if (!conn) return;
    if (conn->socket_fd >= 0) close(conn->socket_fd);
    memset(conn->shared_secret, 0, sizeof(conn->shared_secret));
    free(conn);
}
