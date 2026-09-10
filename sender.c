/*
 * sender.c  (Windows / Winsock2 port)
 * Man-in-the-Middle Simulator - Sender
 *
 * Connects to attacker.c, sends DATA frames, waits for ACKs.
 * Implements Stop-and-Wait ARQ with retransmission on timeout.
 * Reads SEND|message commands from stdin (or from GUI via pipe).
 * Emits EVENT| lines to stdout for GUI consumption.
 *
 * Network topology:
 *   sender.c --> attacker.c --> receiver.c
 *   sender.c <-- attacker.c <-- receiver.c
 *
 * Ports:
 *   Sender connects to ATTACKER_DATA_PORT (5001)  -- DATA out
 *   Sender listens  on SENDER_ACK_PORT   (5000)  -- ACK  in
 */

/* ── Windows / Winsock2 preamble ── */
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
#include <process.h>   /* _beginthreadex */
#include <windows.h>
#include <time.h>

/* ─── Port configuration ──────────────────────────────────────────────────── */
#define ATTACKER_DATA_HOST "127.0.0.1"
#define ATTACKER_DATA_PORT  5001
#define SENDER_ACK_PORT     5000

/* ─── Protocol constants ──────────────────────────────────────────────────── */
#define MAX_DATA_LEN    1024
#define ACK_TIMEOUT_SEC 3
#define MAX_RETRANSMIT  10

#define FRAME_DATA 0
#define FRAME_ACK  1

/* ─── Frame ───────────────────────────────────────────────────────────────── */
typedef struct {
    int          type;
    int          sequence;
    char         data[MAX_DATA_LEN];
    unsigned int checksum;
} Frame;

/* ─── Globals ─────────────────────────────────────────────────────────────── */
static SOCKET data_sock   = INVALID_SOCKET;
static SOCKET ack_listen  = INVALID_SOCKET;
static volatile SOCKET ack_sock = INVALID_SOCKET;

static CRITICAL_SECTION send_mutex;

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

/* ─── Setup ACK listener ──────────────────────────────────────────────────── */
static SOCKET setup_ack_listener(void)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(SENDER_ACK_PORT);

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(s); return INVALID_SOCKET;
    }
    if (listen(s, 1) == SOCKET_ERROR) {
        closesocket(s); return INVALID_SOCKET;
    }
    return s;
}

/* ─── Connect to attacker (DATA) ──────────────────────────────────────────── */
static SOCKET connect_to_attacker(void)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(ATTACKER_DATA_PORT);
    inet_pton(AF_INET, ATTACKER_DATA_HOST, &addr.sin_addr);

    for (int i = 0; i < 20; i++) {
        if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == 0)
            return s;
        Sleep(500);
    }
    closesocket(s);
    return INVALID_SOCKET;
}

/* ─── ACK accept thread ───────────────────────────────────────────────────── */
static unsigned __stdcall ack_accept_thread(void *arg)
{
    (void)arg;
    struct sockaddr_in cli;
    int clen = sizeof(cli);
    emit("EVENT|SENDER|ACK_LISTEN_START|port=%d", SENDER_ACK_PORT);
    SOCKET s = accept(ack_listen, (struct sockaddr*)&cli, &clen);
    if (s != INVALID_SOCKET) {
        ack_sock = s;
        emit("EVENT|SENDER|ACK_CONNECTED");
    } else {
        emit("EVENT|SENDER|ERROR|msg=ACK accept failed");
    }
    return 0;
}

/* ─── Wait for ACK with timeout ──────────────────────────────────────────── */
static int wait_for_ack(int expected_seq, int timeout_sec)
{
    if (ack_sock == INVALID_SOCKET) {
        emit("EVENT|SENDER|ERROR|msg=No ACK socket");
        return -1;
    }

    struct timeval tv;
    tv.tv_sec  = timeout_sec;
    tv.tv_usec = 0;

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(ack_sock, &rfds);

    int r = select(0, &rfds, NULL, NULL, &tv);  /* first arg ignored on Windows */
    if (r == 0)  return 0;
    if (r < 0)   return -1;

    Frame ack;
    memset(&ack, 0, sizeof(ack));
    if (recv_all(ack_sock, &ack, sizeof(Frame)) < 0)
        return -1;

    if (ack.type == FRAME_ACK && ack.sequence == expected_seq) {
        emit("EVENT|SENDER|ACK_RECEIVED|seq=%d", expected_seq);
        return 1;
    }
    emit("EVENT|SENDER|WRONG_ACK|expected=%d|got=%d", expected_seq, ack.sequence);
    return 0;
}

/* ─── Send one message (Stop-and-Wait ARQ) ───────────────────────────────── */
static void send_message(const char *message, int *seq)
{
    Frame frame;
    memset(&frame, 0, sizeof(frame));
    frame.type     = FRAME_DATA;
    frame.sequence = *seq;
    strncpy(frame.data, message, MAX_DATA_LEN - 1);
    frame.data[MAX_DATA_LEN - 1] = '\0';
    frame.checksum = compute_checksum(frame.data, (int)strlen(frame.data));

    int attempt = 0, ack_ok = 0;

    while (!ack_ok && attempt < MAX_RETRANSMIT) {
        attempt++;

        EnterCriticalSection(&send_mutex);
        int r = send_all(data_sock, &frame, sizeof(Frame));
        LeaveCriticalSection(&send_mutex);

        if (r < 0) { emit("EVENT|SENDER|ERROR|msg=Send failed"); break; }

        emit("EVENT|SENDER|DATA_SENT|seq=%d|data=%s|checksum=%u",
             frame.sequence, frame.data, frame.checksum);
        emit("EVENT|SENDER|WAIT_ACK|seq=%d|attempt=%d", frame.sequence, attempt);

        int res = wait_for_ack(frame.sequence, ACK_TIMEOUT_SEC);

        if (res == 1) {
            ack_ok = 1;
            emit("EVENT|SENDER|ACK_OK|seq=%d", frame.sequence);
            *seq = 1 - *seq;
        } else if (res == 0) {
            emit("EVENT|SENDER|ACK_TIMEOUT|seq=%d", frame.sequence);
            if (attempt < MAX_RETRANSMIT)
                emit("EVENT|SENDER|RETRANSMIT|seq=%d|attempt=%d",
                     frame.sequence, attempt + 1);
        } else {
            emit("EVENT|SENDER|ERROR|msg=ACK receive error");
            break;
        }
    }
    if (!ack_ok)
        emit("EVENT|SENDER|MAX_RETRANSMIT|seq=%d", frame.sequence);
}

/* ─── Stdin loop ──────────────────────────────────────────────────────────── */
static void stdin_loop(void)
{
    char line[MAX_DATA_LEN + 32];
    int  seq = 0;

    emit("EVENT|SENDER|READY");

    while (fgets(line, sizeof(line), stdin)) {
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') line[--len] = '\0';
        if (len > 0 && line[len-1] == '\r') line[--len] = '\0';

        if (strncmp(line, "SEND|", 5) == 0) {
            const char *msg = line + 5;
            emit("EVENT|SENDER|MSG_RECEIVED|data=%s", msg);
            send_message(msg, &seq);
        } else if (strcmp(line, "QUIT") == 0 || strcmp(line, "EXIT") == 0) {
            break;
        }
    }
    emit("EVENT|SENDER|SHUTDOWN");
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

    InitializeCriticalSection(&send_mutex);

    emit("EVENT|SENDER|START");

    ack_listen = setup_ack_listener();
    if (ack_listen == INVALID_SOCKET) {
        emit("EVENT|SENDER|ERROR|msg=Cannot create ACK listener");
        WSACleanup();
        return 1;
    }

    HANDLE thr = (HANDLE)_beginthreadex(NULL, 0, ack_accept_thread, NULL, 0, NULL);
    if (thr) CloseHandle(thr);

    emit("EVENT|SENDER|CONNECTING|host=%s|port=%d",
         ATTACKER_DATA_HOST, ATTACKER_DATA_PORT);
    data_sock = connect_to_attacker();
    if (data_sock == INVALID_SOCKET) {
        emit("EVENT|SENDER|ERROR|msg=Cannot connect to attacker");
        closesocket(ack_listen);
        WSACleanup();
        return 1;
    }
    emit("EVENT|SENDER|DATA_CONNECTED|port=%d", ATTACKER_DATA_PORT);

    /* Wait up to 10 s for the ACK connection */
    for (int i = 0; i < 20 && ack_sock == INVALID_SOCKET; i++)
        Sleep(500);

    if (ack_sock == INVALID_SOCKET)
        emit("EVENT|SENDER|ERROR|msg=ACK connection not established");

    emit("EVENT|SYSTEM|READY|role=sender");

    stdin_loop();

    if (data_sock  != INVALID_SOCKET) closesocket(data_sock);
    if (ack_sock   != INVALID_SOCKET) closesocket(ack_sock);
    if (ack_listen != INVALID_SOCKET) closesocket(ack_listen);

    DeleteCriticalSection(&send_mutex);
    WSACleanup();
    return 0;
}
