/*
 * receiver.c  (Windows / Winsock2 port)
 * Man-in-the-Middle Simulator - Receiver
 *
 * Listens for DATA frames from attacker.c.
 * Validates checksum and sequence number.
 * Sends ACKs back to attacker.c.
 * Implements Stop-and-Wait ARQ receiver side.
 * Emits EVENT| lines to stdout.
 *
 * Ports:
 *   Receiver listens  on RECEIVER_DATA_PORT (5002) — DATA from attacker
 *   Receiver connects to ATTACKER_ACK_PORT  (5003) — ACKs  to attacker
 */

#ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0601
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <windows.h>

/* ─── Port configuration ──────────────────────────────────────────────────── */
#define RECEIVER_DATA_PORT  5002
#define ATTACKER_ACK_HOST  "127.0.0.1"
#define ATTACKER_ACK_PORT   5003

/* ─── Protocol constants ──────────────────────────────────────────────────── */
#define MAX_DATA_LEN 1024
#define FRAME_DATA   0
#define FRAME_ACK    1

/* ─── Frame ───────────────────────────────────────────────────────────────── */
typedef struct {
    int          type;
    int          sequence;
    char         data[MAX_DATA_LEN];
    unsigned int checksum;
} Frame;

/* ─── Globals ─────────────────────────────────────────────────────────────── */
static SOCKET data_listen = INVALID_SOCKET;
static SOCKET data_sock   = INVALID_SOCKET;
static SOCKET ack_sock    = INVALID_SOCKET;

static int expected_seq      = 0;
static int frames_received   = 0;
static int valid_frames      = 0;
static int duplicate_frames  = 0;
static int corrupted_frames  = 0;
static int acks_sent         = 0;

/* ─── Checksum ────────────────────────────────────────────────────────────── */
static unsigned int compute_checksum(const char *data, int len)
{
    unsigned int sum = 0;
    for (int i = 0; i < len; i++)
        sum += (unsigned char)data[i];
    return sum;
}

/* ─── Emit ────────────────────────────────────────────────────────────────── */
static void emit(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
    fflush(stdout);
}

/* ─── Helpers ─────────────────────────────────────────────────────────────── */
static int recv_all(SOCKET fd, void *buf, size_t len)
{
    size_t got = 0;
    while (got < len) {
        int n = recv(fd, (char*)buf + got, (int)(len - got), 0);
        if (n <= 0) return -1;
        got += n;
    }
    return 0;
}

static int send_all(SOCKET fd, const void *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        int n = send(fd, (const char*)buf + sent, (int)(len - sent), 0);
        if (n <= 0) return -1;
        sent += n;
    }
    return 0;
}

/* ─── Send ACK ────────────────────────────────────────────────────────────── */
static int send_ack(int seq)
{
    Frame ack;
    memset(&ack, 0, sizeof(ack));
    ack.type     = FRAME_ACK;
    ack.sequence = seq;

    if (send_all(ack_sock, &ack, sizeof(Frame)) < 0) {
        emit("EVENT|RECEIVER|ERROR|msg=ACK send failed|seq=%d", seq);
        return -1;
    }
    acks_sent++;
    emit("EVENT|RECEIVER|ACK_SENT|seq=%d|acks_sent=%d", seq, acks_sent);
    return 0;
}

/* ─── Setup DATA listener ─────────────────────────────────────────────────── */
static SOCKET setup_data_listener(void)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(RECEIVER_DATA_PORT);

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(s); return INVALID_SOCKET;
    }
    if (listen(s, 1) == SOCKET_ERROR) {
        closesocket(s); return INVALID_SOCKET;
    }
    return s;
}

/* ─── Connect ACK path to attacker ──────────────────────────────────────── */
static SOCKET connect_ack_to_attacker(void)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(ATTACKER_ACK_PORT);
    inet_pton(AF_INET, ATTACKER_ACK_HOST, &addr.sin_addr);

    for (int i = 0; i < 20; i++) {
        if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == 0)
            return s;
        Sleep(500);
    }
    closesocket(s);
    return INVALID_SOCKET;
}

/* ─── Main receive loop ───────────────────────────────────────────────────── */
static void receive_loop(void)
{
    emit("EVENT|RECEIVER|READY");

    while (1) {
        Frame frame;
        memset(&frame, 0, sizeof(frame));
        if (recv_all(data_sock, &frame, sizeof(Frame)) < 0) {
            emit("EVENT|RECEIVER|ERROR|msg=Data receive failed|disconnected=1");
            break;
        }

        if (frame.type != FRAME_DATA) {
            emit("EVENT|RECEIVER|ERROR|msg=Unexpected frame type|type=%d", frame.type);
            continue;
        }

        frames_received++;

        unsigned int calc_cs = compute_checksum(frame.data, (int)strlen(frame.data));

        emit("EVENT|RECEIVER|DATA_RECEIVED|seq=%d|data=%s|recv_checksum=%u|calc_checksum=%u|expected_seq=%d",
             frame.sequence, frame.data, frame.checksum, calc_cs, expected_seq);

        /* Checksum validation */
        if (calc_cs != frame.checksum) {
            corrupted_frames++;
            emit("EVENT|RECEIVER|CHECKSUM_INVALID|seq=%d|recv_checksum=%u|calc_checksum=%u|corrupted=%d",
                 frame.sequence, frame.checksum, calc_cs, corrupted_frames);
            emit("EVENT|RECEIVER|FRAME_DISCARDED|seq=%d", frame.sequence);
            continue;
        }

        emit("EVENT|RECEIVER|CHECKSUM_VALID|seq=%d", frame.sequence);

        /* Duplicate detection */
        if (frame.sequence != expected_seq) {
            duplicate_frames++;
            emit("EVENT|RECEIVER|DUPLICATE|seq=%d|expected=%d|duplicates=%d",
                 frame.sequence, expected_seq, duplicate_frames);
            send_ack(frame.sequence);
            continue;
        }

        /* Valid new frame */
        valid_frames++;
        emit("EVENT|RECEIVER|VALID_SEQ|seq=%d", frame.sequence);
        emit("EVENT|RECEIVER|DELIVERED|seq=%d|data=%s|valid=%d|total=%d",
             frame.sequence, frame.data, valid_frames, frames_received);

        expected_seq = 1 - expected_seq;

        send_ack(frame.sequence);

        emit("EVENT|RECEIVER|STATS|received=%d|valid=%d|duplicate=%d|corrupted=%d|acks=%d|expected_seq=%d",
             frames_received, valid_frames, duplicate_frames, corrupted_frames,
             acks_sent, expected_seq);
    }
}

/* ─── Main ───────────────────────────────────────────────────────────────── */
int main(void)
{
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    setvbuf(stdout, NULL, _IOLBF, 0);
    emit("EVENT|RECEIVER|START");

    data_listen = setup_data_listener();
    if (data_listen == INVALID_SOCKET) {
        emit("EVENT|RECEIVER|ERROR|msg=Cannot create DATA listener");
        WSACleanup(); return 1;
    }
    emit("EVENT|RECEIVER|DATA_LISTEN|port=%d", RECEIVER_DATA_PORT);

    emit("EVENT|RECEIVER|CONNECTING_ACK|host=%s|port=%d",
         ATTACKER_ACK_HOST, ATTACKER_ACK_PORT);
    ack_sock = connect_ack_to_attacker();
    if (ack_sock == INVALID_SOCKET) {
        emit("EVENT|RECEIVER|ERROR|msg=Cannot connect ACK path to attacker");
        closesocket(data_listen);
        WSACleanup(); return 1;
    }
    emit("EVENT|RECEIVER|ACK_CONNECTED|port=%d", ATTACKER_ACK_PORT);

    emit("EVENT|RECEIVER|WAIT_DATA_CONNECTION");
    struct sockaddr_in cli;
    int clen = sizeof(cli);
    data_sock = accept(data_listen, (struct sockaddr*)&cli, &clen);
    if (data_sock == INVALID_SOCKET) {
        emit("EVENT|RECEIVER|ERROR|msg=Accept DATA connection failed");
        closesocket(ack_sock);
        closesocket(data_listen);
        WSACleanup(); return 1;
    }
    emit("EVENT|RECEIVER|DATA_CONNECTED");
    emit("EVENT|SYSTEM|READY|role=receiver");

    receive_loop();

    if (data_sock   != INVALID_SOCKET) closesocket(data_sock);
    if (ack_sock    != INVALID_SOCKET) closesocket(ack_sock);
    if (data_listen != INVALID_SOCKET) closesocket(data_listen);

    emit("EVENT|RECEIVER|SHUTDOWN");
    WSACleanup();
    return 0;
}
