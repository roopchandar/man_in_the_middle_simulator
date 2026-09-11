/*
 * receiver.c
 * CLI Stop-and-Wait ARQ receiver.
 *
 * Listens on:
 *   127.0.0.1:5001
 *
 * The receiver validates checksum and sequence number, delivers valid
 * in-order DATA, and ACKs the last accepted sequence for duplicates/corrupt
 * frames.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define LISTEN_IP "127.0.0.1"
#define LISTEN_PORT 5001
#define MAX_DATA 1023

#define TYPE_DATA 1u
#define TYPE_ACK  2u

typedef struct {
    uint32_t type;
    uint32_t sequence;
    uint32_t length;
    uint32_t checksum;
} FrameHeader;

static uint32_t checksum_bytes(const unsigned char *data, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i < len; ++i)
        sum = (sum + data[i]) & 0xFFFFFFFFu;
    return sum;
}

static int send_all(int fd, const void *buf, size_t len) {
    const unsigned char *p = buf;
    while (len) {
        ssize_t n = send(fd, p, len, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int recv_all(int fd, void *buf, size_t len) {
    unsigned char *p = buf;
    while (len) {
        ssize_t n = recv(fd, p, len, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return 0;
        p += n;
        len -= (size_t)n;
    }
    return 1;
}

static int create_listener(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("receiver: socket");
        return -1;
    }

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LISTEN_PORT);
    inet_pton(AF_INET, LISTEN_IP, &addr.sin_addr);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("receiver: bind");
        close(fd);
        return -1;
    }

    if (listen(fd, 5) < 0) {
        perror("receiver: listen");
        close(fd);
        return -1;
    }

    return fd;
}

static int send_ack(int fd, uint32_t seq) {
    FrameHeader ack = {
        htonl(TYPE_ACK),
        htonl(seq),
        htonl(0),
        htonl(0)
    };
    return send_all(fd, &ack, sizeof(ack));
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("=== STOP-AND-WAIT ARQ RECEIVER ===\n");

    int listenfd = create_listener();
    if (listenfd < 0) return EXIT_FAILURE;

    printf("[RECEIVER] Listening on %s:%d\n", LISTEN_IP, LISTEN_PORT);

    uint32_t expected_seq = 0;
    uint32_t last_accepted = 1; /* previous value when expected_seq starts at 0 */

    while (1) {
        struct sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);

        printf("[RECEIVER] Waiting for attacker connection...\n");
        int fd = accept(listenfd, (struct sockaddr *)&peer, &peer_len);
        if (fd < 0) {
            if (errno == EINTR) continue;
            perror("receiver: accept");
            break;
        }

        printf("[RECEIVER] Attacker connected.\n");

        while (1) {
            FrameHeader wire;
            int rr = recv_all(fd, &wire, sizeof(wire));
            if (rr <= 0) {
                printf("[RECEIVER] Attacker disconnected.\n");
                close(fd);
                break;
            }

            uint32_t type = ntohl(wire.type);
            uint32_t seq = ntohl(wire.sequence);
            uint32_t len = ntohl(wire.length);
            uint32_t received_checksum = ntohl(wire.checksum);

            if (type != TYPE_DATA || len > MAX_DATA) {
                printf("[RECEIVER] Malformed frame discarded.\n");
                close(fd);
                break;
            }

            unsigned char data[MAX_DATA + 1];
            if (recv_all(fd, data, len) <= 0) {
                printf("[RECEIVER] Connection lost while receiving DATA.\n");
                close(fd);
                break;
            }
            data[len] = '\0';

            uint32_t calculated = checksum_bytes(data, len);

            printf("\n[RECEIVER] DATA RECEIVED\n");
            printf("  Sequence          : %u\n", seq);
            printf("  Data              : %s\n", data);
            printf("  Received checksum : %u\n", received_checksum);
            printf("  Calculated checksum: %u\n", calculated);

            if (received_checksum != calculated) {
                printf("  Result            : CHECKSUM MISMATCH -> DISCARD\n");
                printf("  Sending ACK       : %u (last accepted)\n", last_accepted);
                if (send_ack(fd, last_accepted) < 0) {
                    close(fd);
                    break;
                }
                continue;
            }

            if (seq != expected_seq) {
                printf("  Result            : DUPLICATE/OUT-OF-ORDER -> DISCARD\n");
                printf("  Sending ACK       : %u (last accepted)\n", last_accepted);
                if (send_ack(fd, last_accepted) < 0) {
                    close(fd);
                    break;
                }
                continue;
            }

            printf("  Result            : VALID -> DELIVERED\n");
            printf("  Delivered message : %s\n", data);

            last_accepted = expected_seq;
            expected_seq = (expected_seq + 1) % 2;

            printf("  Sending ACK       : %u\n", last_accepted);
            if (send_ack(fd, last_accepted) < 0) {
                close(fd);
                break;
            }
        }
    }

    close(listenfd);
    return EXIT_SUCCESS;
}
