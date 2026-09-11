/*
 * attacker.c
 * CLI Man-in-the-Middle for:
 *
 *   sender <-> attacker <-> receiver
 *
 * Sender connects to attacker:5000.
 * Attacker connects to receiver:5001.
 *
 * Attack selection is entered at the attacker CLI while the network
 * forwarding threads continue running.
 *
 * Modes:
 *   0  NO ATTACK
 *   1  DROP DATA
 *   2  DELAY DATA
 *   3  DUPLICATE DATA
 *   4  MODIFY DATA
 *   5  DROP ACK
 *   6  RANDOM ATTACK
 *   7  MULTIPLE ATTACKS
 *
 * Multiple attack command example:
 *   multi 4 5
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define LISTEN_IP "127.0.0.1"
#define LISTEN_PORT 5000

#define RECEIVER_IP "127.0.0.1"
#define RECEIVER_PORT 5001

#define MAX_DATA 1023
#define TYPE_DATA 1u
#define TYPE_ACK  2u

typedef struct {
    uint32_t type;
    uint32_t sequence;
    uint32_t length;
    uint32_t checksum;
} FrameHeader;

typedef struct {
    uint32_t type;
    uint32_t sequence;
    uint32_t length;
    uint32_t checksum;
    unsigned char data[MAX_DATA];
} Packet;

typedef struct {
    int sender_fd;
    int receiver_fd;
} RelayArgs;

static pthread_mutex_t state_mutex = PTHREAD_MUTEX_INITIALIZER;
static int attack_mode = 0;
static int multi_modes[8] = {0};
static unsigned int delay_ms = 1500;
static volatile int running = 1;

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
        perror("attacker: socket");
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
        perror("attacker: bind");
        close(fd);
        return -1;
    }

    if (listen(fd, 5) < 0) {
        perror("attacker: listen");
        close(fd);
        return -1;
    }

    return fd;
}

static int connect_receiver(void) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(RECEIVER_PORT);
    inet_pton(AF_INET, RECEIVER_IP, &addr.sin_addr);

    for (int attempt = 1; attempt <= 30; ++attempt) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            perror("attacker: socket");
            return -1;
        }

        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            printf("[ATTACKER] Connected to receiver at %s:%d\n",
                   RECEIVER_IP, RECEIVER_PORT);
            return fd;
        }

        close(fd);
        if (attempt == 30) break;

        printf("[ATTACKER] Receiver not ready; retrying (%d/30)...\n", attempt);
        sleep(1);
    }

    fprintf(stderr, "[ATTACKER] Could not connect to receiver.\n");
    return -1;
}

static void get_attack_state(int *mode, int modes[8], unsigned int *delay) {
    pthread_mutex_lock(&state_mutex);
    *mode = attack_mode;
    memcpy(modes, multi_modes, sizeof(multi_modes));
    *delay = delay_ms;
    pthread_mutex_unlock(&state_mutex);
}

static void print_help(void) {
    printf("\nCommands:\n");
    printf("  attack 0  - No attack\n");
    printf("  attack 1  - Drop DATA\n");
    printf("  attack 2  - Delay DATA\n");
    printf("  attack 3  - Duplicate DATA\n");
    printf("  attack 4  - Modify DATA\n");
    printf("  attack 5  - Drop ACK\n");
    printf("  attack 6  - Random attack\n");
    printf("  attack 7  - Multiple attacks\n");
    printf("  delay N   - Delay DATA by N milliseconds\n");
    printf("  multi A B - Enable attack numbers A and B (0-6)\n");
    printf("  status    - Show current configuration\n");
    printf("  help\n");
    printf("  quit\n\n");
}

static void *control_thread(void *unused) {
    (void)unused;
    char line[256];

    print_help();

    while (running && fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\r\n")] = '\0';

        int n;
        if (sscanf(line, "attack %d", &n) == 1) {
            if (n < 0 || n > 7) {
                printf("[ATTACKER] Invalid attack number.\n");
                continue;
            }

            pthread_mutex_lock(&state_mutex);
            attack_mode = n;
            if (n != 7) memset(multi_modes, 0, sizeof(multi_modes));
            pthread_mutex_unlock(&state_mutex);

            printf("[ATTACKER] Attack mode = %d\n", n);
        } else if (sscanf(line, "delay %u", &n) == 1) {
            pthread_mutex_lock(&state_mutex);
            delay_ms = (unsigned int)n;
            pthread_mutex_unlock(&state_mutex);
            printf("[ATTACKER] Delay = %u ms\n", delay_ms);
        } else if (strncmp(line, "multi ", 6) == 0) {
            memset(multi_modes, 0, sizeof(multi_modes));
            char *p = line + 6;
            int a, b;
            if (sscanf(p, "%d %d", &a, &b) >= 1 &&
                a >= 0 && a <= 6) {
                multi_modes[a] = 1;
                if (sscanf(p, "%d %d", &a, &b) == 2 &&
                    b >= 0 && b <= 6)
                    multi_modes[b] = 1;

                pthread_mutex_lock(&state_mutex);
                attack_mode = 7;
                pthread_mutex_unlock(&state_mutex);

                printf("[ATTACKER] Multiple attacks enabled.\n");
            } else {
                printf("[ATTACKER] Usage: multi A B\n");
            }
        } else if (strcmp(line, "status") == 0) {
            int mode, modes[8];
            unsigned int d;
            get_attack_state(&mode, modes, &d);
            printf("[ATTACKER] Mode=%d Delay=%u ms Multiple:",
                   mode, d);
            for (int i = 0; i < 8; ++i)
                if (modes[i]) printf(" %d", i);
            printf("\n");
        } else if (strcmp(line, "help") == 0) {
            print_help();
        } else if (strcmp(line, "quit") == 0) {
            running = 0;
            break;
        } else if (*line != '\0') {
            printf("[ATTACKER] Unknown command. Type 'help'.\n");
        }
    }

    running = 0;
    return NULL;
}

static void apply_modify(Packet *p) {
    if (p->length == 0) return;
    p->data[0] = (p->data[0] == 'X') ? 'x' : 'X';
    /* Deliberately retain the original checksum to demonstrate detection. */
}

static int forward_packet(int fd, const Packet *p) {
    FrameHeader h = {
        htonl(p->type),
        htonl(p->sequence),
        htonl(p->length),
        htonl(p->checksum)
    };

    if (send_all(fd, &h, sizeof(h)) < 0) return -1;
    if (p->length && send_all(fd, p->data, p->length) < 0) return -1;
    return 0;
}

static int random_attack(void) {
    return rand() % 6 + 1; /* 1..6 */
}

static int process_data(Packet *p, int receiver_fd, int mode, int modes[8],
                        unsigned int delay) {
    int do_drop = 0, do_delay = 0, do_duplicate = 0, do_modify = 0;

    if (mode == 6) {
        int r = random_attack();
        printf("[ATTACKER] Random attack selected: %d\n", r);
        mode = r;
    }

    if (mode == 1) do_drop = 1;
    if (mode == 2) do_delay = 1;
    if (mode == 3) do_duplicate = 1;
    if (mode == 4) do_modify = 1;

    if (mode == 7) {
        do_drop = modes[1];
        do_delay = modes[2];
        do_duplicate = modes[3];
        do_modify = modes[4];
    }

    printf("\n[ATTACKER] DATA intercepted: seq=%u data=\"%.*s\"\n",
           p->sequence, (int)p->length, p->data);

    if (do_modify) {
        apply_modify(p);
        printf("[ATTACKER] DATA MODIFIED: \"%.*s\"\n",
               (int)p->length, p->data);
    }

    if (do_drop) {
        printf("[ATTACKER] DATA DROPPED.\n");
        return 0;
    }

    if (do_delay) {
        printf("[ATTACKER] DATA DELAYED by %u ms.\n", delay);
        usleep(delay * 1000u);
    }

    if (forward_packet(receiver_fd, p) < 0)
        return -1;

    printf("[ATTACKER] DATA FORWARDED: seq=%u\n", p->sequence);

    if (do_duplicate) {
        if (forward_packet(receiver_fd, p) < 0)
            return -1;
        printf("[ATTACKER] DATA DUPLICATED: seq=%u\n", p->sequence);
    }

    return 0;
}

static int process_ack(const Packet *p, int sender_fd, int mode, int modes[8]) {
    int drop = 0;

    if (mode == 6) {
        int r = random_attack();
        printf("[ATTACKER] Random attack selected for ACK: %d\n", r);
        if (r == 5) drop = 1;
    } else if (mode == 5) {
        drop = 1;
    } else if (mode == 7) {
        drop = modes[5];
    }

    printf("[ATTACKER] ACK intercepted: seq=%u\n", p->sequence);

    if (drop) {
        printf("[ATTACKER] ACK DROPPED: seq=%u\n", p->sequence);
        return 0;
    }

    if (forward_packet(sender_fd, p) < 0)
        return -1;

    printf("[ATTACKER] ACK FORWARDED: seq=%u\n", p->sequence);
    return 0;
}

static void *data_thread(void *arg) {
    RelayArgs *a = arg;
    while (running) {
        FrameHeader wire;
        int rr = recv_all(a->sender_fd, &wire, sizeof(wire));
        if (rr <= 0) {
            running = 0;
            break;
        }

        Packet p;
        p.type = ntohl(wire.type);
        p.sequence = ntohl(wire.sequence);
        p.length = ntohl(wire.length);
        p.checksum = ntohl(wire.checksum);

        if (p.length > MAX_DATA) {
            printf("[ATTACKER] Invalid DATA length. Closing sender connection.\n");
            running = 0;
            break;
        }

        if (p.length && recv_all(a->sender_fd, p.data, p.length) <= 0) {
            running = 0;
            break;
        }

        if (p.type != TYPE_DATA) {
            printf("[ATTACKER] Non-DATA frame from sender ignored.\n");
            continue;
        }

        int mode, modes[8];
        unsigned int delay;
        get_attack_state(&mode, modes, &delay);

        if (process_data(&p, a->receiver_fd, mode, modes, delay) < 0) {
            running = 0;
            break;
        }
    }
    return NULL;
}

static void *ack_thread(void *arg) {
    RelayArgs *a = arg;
    while (running) {
        FrameHeader wire;
        int rr = recv_all(a->receiver_fd, &wire, sizeof(wire));
        if (rr <= 0) {
            running = 0;
            break;
        }

        Packet p;
        p.type = ntohl(wire.type);
        p.sequence = ntohl(wire.sequence);
        p.length = ntohl(wire.length);
        p.checksum = ntohl(wire.checksum);

        if (p.length > MAX_DATA) {
            running = 0;
            break;
        }

        if (p.length && recv_all(a->receiver_fd, p.data, p.length) <= 0) {
            running = 0;
            break;
        }

        if (p.type != TYPE_ACK) {
            printf("[ATTACKER] Non-ACK frame from receiver ignored.\n");
            continue;
        }

        int mode, modes[8];
        unsigned int delay;
        get_attack_state(&mode, modes, &delay);
        (void)delay;

        if (process_ack(&p, a->sender_fd, mode, modes) < 0) {
            running = 0;
            break;
        }
    }
    return NULL;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    srand((unsigned int)(time(NULL) ^ getpid()));

    printf("=== MAN-IN-THE-MIDDLE ATTACKER ===\n");

    int listenfd = create_listener();
    if (listenfd < 0) return EXIT_FAILURE;

    printf("[ATTACKER] Listening for sender on %s:%d\n",
           LISTEN_IP, LISTEN_PORT);

    int receiver_fd = connect_receiver();
    if (receiver_fd < 0) {
        close(listenfd);
        return EXIT_FAILURE;
    }

    printf("[ATTACKER] Waiting for sender connection...\n");

    struct sockaddr_in peer;
    socklen_t peer_len = sizeof(peer);
    int sender_fd = accept(listenfd, (struct sockaddr *)&peer, &peer_len);
    if (sender_fd < 0) {
        perror("attacker: accept");
        close(receiver_fd);
        close(listenfd);
        return EXIT_FAILURE;
    }

    printf("[ATTACKER] Sender connected. MITM is active.\n");

    RelayArgs args = {sender_fd, receiver_fd};
    pthread_t data_tid, ack_tid, ctl_tid;

    if (pthread_create(&data_tid, NULL, data_thread, &args) != 0 ||
        pthread_create(&ack_tid, NULL, ack_thread, &args) != 0 ||
        pthread_create(&ctl_tid, NULL, control_thread, NULL) != 0) {
        fprintf(stderr, "[ATTACKER] Failed to create threads.\n");
        running = 0;
        close(sender_fd);
        close(receiver_fd);
        close(listenfd);
        return EXIT_FAILURE;
    }

    pthread_join(data_tid, NULL);
    running = 0;
    shutdown(sender_fd, SHUT_RDWR);
    shutdown(receiver_fd, SHUT_RDWR);
    pthread_join(ack_tid, NULL);
    pthread_cancel(ctl_tid);
    pthread_join(ctl_tid, NULL);

    close(sender_fd);
    close(receiver_fd);
    close(listenfd);

    printf("[ATTACKER] Stopped.\n");
    return EXIT_SUCCESS;
}
