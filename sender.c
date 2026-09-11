/*
 * sender.c
 * CLI Stop-and-Wait ARQ sender.
 *
 * Network:
 *   sender -> attacker : 127.0.0.1:5000
 *   ACKs  <- attacker  : same TCP connection
 *
 * Usage:
 *   ./sender
 * Then type messages at the prompt.
 *
 * Commands:
 *   /quit
 *   /reconnect
 *
 * The sender constructs DATA frames and performs the ARQ/retransmission.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#define ATTACKER_IP "127.0.0.1"
#define ATTACKER_PORT 5000
#define MAX_DATA 1023
#define ACK_TIMEOUT_SEC 2
#define MAX_ATTEMPTS 10

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

static int connect_attacker(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("sender: socket");
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(ATTACKER_PORT);
    inet_pton(AF_INET, ATTACKER_IP, &addr.sin_addr);

    for (int attempt = 1; attempt <= 10; ++attempt) {
        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            printf("[SENDER] Connected to attacker at %s:%d\n",
                   ATTACKER_IP, ATTACKER_PORT);
            fflush(stdout);
            return fd;
        }

        if (attempt == 10) break;
        printf("[SENDER] Attacker not ready; retrying (%d/10)...\n", attempt);
        fflush(stdout);
        sleep(1);
    }

    perror("sender: connect");
    close(fd);
    return -1;
}

static int wait_for_ack(int fd, uint32_t expected_seq) {
    fd_set readfds;
    struct timeval tv;

    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);
    tv.tv_sec = ACK_TIMEOUT_SEC;
    tv.tv_usec = 0;

    int rc = select(fd + 1, &readfds, NULL, NULL, &tv);
    if (rc == 0) return 0;       /* timeout */
    if (rc < 0) {
        if (errno == EINTR) return 0;
        return -1;
    }

    FrameHeader h;
    int rr = recv_all(fd, &h, sizeof(h));
    if (rr <= 0) return -1;

    uint32_t type = ntohl(h.type);
    uint32_t seq  = ntohl(h.sequence);
    uint32_t len  = ntohl(h.length);

    if (len > 0) {
        unsigned char discard[MAX_DATA];
        if (len > MAX_DATA) return -1;
        if (recv_all(fd, discard, len) <= 0) return -1;
    }

    if (type == TYPE_ACK && seq == expected_seq) {
        return 1;
    }

    printf("[SENDER] Ignoring unexpected ACK/frame (type=%u seq=%u)\n",
           type, seq);
    fflush(stdout);
    return 0;
}

static int send_message(int *sockfd, uint32_t seq, const char *message) {
    size_t len = strlen(message);
    if (len == 0) {
        printf("[SENDER] Empty message ignored.\n");
        return 1;
    }
    if (len > MAX_DATA) {
        printf("[SENDER] Message too long. Maximum is %d bytes.\n", MAX_DATA);
        return 1;
    }

    uint32_t checksum = checksum_bytes((const unsigned char *)message, len);

    FrameHeader h;
    h.type = htonl(TYPE_DATA);
    h.sequence = htonl(seq);
    h.length = htonl((uint32_t)len);
    h.checksum = htonl(checksum);

    for (int attempt = 1; attempt <= MAX_ATTEMPTS; ++attempt) {
        if (*sockfd < 0) {
            *sockfd = connect_attacker();
            if (*sockfd < 0) return 0;
        }

        printf("\n[SENDER] DATA seq=%u attempt=%d\n", seq, attempt);
        printf("[SENDER]   Data     : %s\n", message);
        printf("[SENDER]   Checksum : %u\n", checksum);
        fflush(stdout);

        if (send_all(*sockfd, &h, sizeof(h)) < 0 ||
            send_all(*sockfd, message, len) < 0) {
            printf("[SENDER] Send failed. Reconnecting...\n");
            close(*sockfd);
            *sockfd = -1;
            continue;
        }

        int ack = wait_for_ack(*sockfd, seq);
        if (ack == 1) {
            printf("[SENDER] ACK %u received. Delivery complete.\n", seq);
            fflush(stdout);
            return 1;
        }

        if (ack == 0) {
            printf("[SENDER] ACK timeout/unexpected ACK. Retransmitting...\n");
        } else {
            printf("[SENDER] Connection lost while waiting for ACK. Reconnecting...\n");
            close(*sockfd);
            *sockfd = -1;
        }
        fflush(stdout);
    }

    printf("[SENDER] Maximum attempts reached. Message failed.\n");
    fflush(stdout);
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("=== STOP-AND-WAIT ARQ SENDER ===\n");
    printf("Attacker: %s:%d\n", ATTACKER_IP, ATTACKER_PORT);
    printf("Type a message and press Enter. /quit exits.\n\n");

    int sockfd = connect_attacker();
    uint32_t sequence = 0;
    char input[MAX_DATA + 2];

    while (1) {
        printf("sender> ");
        if (!fgets(input, sizeof(input), stdin))
            break;

        input[strcspn(input, "\r\n")] = '\0';

        if (strcmp(input, "/quit") == 0)
            break;

        if (strcmp(input, "/reconnect") == 0) {
            if (sockfd >= 0) close(sockfd);
            sockfd = connect_attacker();
            continue;
        }

        if (send_message(&sockfd, sequence, input))
            sequence = (sequence + 1) % 2;
    }

    if (sockfd >= 0) close(sockfd);
    printf("\n[SENDER] Stopped.\n");
    return 0;
}
