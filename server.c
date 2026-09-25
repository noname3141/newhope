#include <stdio.h>
#include "handshake.h"

int main() {
    pqc_conn_t *conn = pqc_listen_and_accept(8080);
    if (!conn) {
        fprintf(stderr, "Handshake failed.\n");
        return 1;
    }

    printf("[Server] Handshake completed successfully!\n");
    printf("[Server] Established Shared Secret: ");
    for (int i = 0; i < CRYPTO_BYTES; i++) {
        printf("%02x", conn->shared_secret[i]);
    }
    printf("\n");

    pqc_close(conn);
    return 0;
}
