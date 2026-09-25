#include <stdio.h>
#include "handshake.h"

int main(int argc, char **argv) {
    const char *target_ip = (argc > 1) ? argv[1] : "127.0.0.1";

    printf("[Client] Connecting to %s:8080...\n", target_ip);
    pqc_conn_t *conn = pqc_connect(target_ip, 8080);
    if (!conn) {
        fprintf(stderr, "Handshake failed.\n");
        return 1;
    }

    printf("[Client] Handshake completed successfully!\n");
    printf("[Client] Established Shared Secret: ");
    for (int i = 0; i < CRYPTO_BYTES; i++) {
        printf("%02x", conn->shared_secret[i]);
    }
    printf("\n");

    pqc_close(conn);
    return 0;
}
