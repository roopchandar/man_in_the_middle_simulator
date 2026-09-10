/*
 * attacker.c  (Windows / Winsock2 port)
 * Man-in-the-Middle Simulator - Attacker (MITM)
 *
 * Relays frames between sender.c and receiver.c.
 * Supports 8 attack modes.  Receives control commands from Python GUI.
 * Emits EVENT| lines to stdout.
 *
 * Port layout:
 *   sender.c   → connects to → ATTACKER_DATA_PORT (5001)
 *   receiver.c → connects to → ATTACKER_ACK_PORT  (5003)
 *   attacker   → connects to → RECEIVER_DATA_PORT (5002)
 *   attacker   → connects to → SENDER_ACK_PORT    (5000)
 *   Python GUI → connects to → CONTROL_PORT       (5100)
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
#include <process.h>
#include <time.h>

/* ─── Ports ───────────────────────────────────────────────────────────────── */
#define ATTACKER_DATA_PORT  5001
#define ATTACKER_ACK_PORT   5003
#define RECEIVER_DATA_HOST "127.0.0.1"
#define RECEIVER_DATA_PORT  5002
#define SENDER_ACK_HOST    "127.0.0.1"
#define SENDER_ACK_PORT     5000
#define CONTROL_PORT        5100

/* ─── Protocol ────────────────────────────────────────────────────────────── */
#define MAX_DATA_LEN 1024
#define FRAME_DATA   0
#define FRAME_ACK    1

/* ─── Attack modes ────────────────────────────────────────────────────────── */
#define ATTACK_NONE      0
#define ATTACK_DROP_DATA 1
#define ATTACK_DELAY     2
#define ATTACK_DUPLICATE 3
#define ATTACK_MODIFY    4
#define ATTACK_DROP_ACK  5
#define ATTACK_RANDOM    6
#define ATTACK_MULTI     7

#define MULTI_DROP_DATA  (1 << 0)
#define MULTI_DELAY      (1 << 1)
#define MULTI_DUPLICATE  (1 << 2)
#define MULTI_MODIFY     (1 << 3)
#define MULTI_DROP_ACK   (1 << 4)

/* ─── Frame ───────────────────────────────────────────────────────────────── */
typedef struct {
    int          type;
    int          sequence;
    char         data[MAX_DATA_LEN];
    unsigned int checksum;
} Frame;

/* ─── Globals ─────────────────────────────────────────────────────────────── */
static SOCKET data_listen        = INVALID_SOCKET;
static SOCKET ack_listen         = INVALID_SOCKET;
static SOCKET ctrl_listen        = INVALID_SOCKET;
static SOCKET sender_data_sock   = INVALID_SOCKET;
static SOCKET receiver_ack_sock  = INVALID_SOCKET;
static SOCKET to_receiver_sock   = INVALID_SOCKET;
static SOCKET to_sender_ack_sock = INVALID_SOCKET;

static CRITICAL_SECTION attack_mutex;
static int current_attack = ATTACK_NONE;
static int multi_mask     = 0;
static int delay_ms       = 2000;

static CRITICAL_SECTION stats_mutex;
static int stat_intercepted = 0;
static int stat_forwarded   = 0;
static int stat_dropped     = 0;
static int stat_modified    = 0;
static int stat_duplicated  = 0;
static int stat_ack_dropped = 0;

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

/* ─── Stats ───────────────────────────────────────────────────────────────── */
static void emit_stats(void)
{
    EnterCriticalSection(&stats_mutex);
    emit("EVENT|ATTACKER|STATS|intercepted=%d|forwarded=%d|dropped=%d|modified=%d|duplicated=%d|ack_dropped=%d",
         stat_intercepted, stat_forwarded, stat_dropped,
         stat_modified, stat_duplicated, stat_ack_dropped);
    LeaveCriticalSection(&stats_mutex);
}

/* ─── Attack helpers ──────────────────────────────────────────────────────── */
static const char *attack_name(int a)
{
    switch (a) {
        case ATTACK_NONE:      return "NO_ATTACK";
        case ATTACK_DROP_DATA: return "DROP_DATA";
        case ATTACK_DELAY:     return "DELAY_DATA";
        case ATTACK_DUPLICATE: return "DUPLICATE";
        case ATTACK_MODIFY:    return "MODIFY_DATA";
        case ATTACK_DROP_ACK:  return "DROP_ACK";
        case ATTACK_RANDOM:    return "RANDOM";
        case ATTACK_MULTI:     return "MULTIPLE";
        default:               return "UNKNOWN";
    }
}

static void apply_modify(Frame *f)
{
    if (strlen(f->data) > 0)
        f->data[0] = (f->data[0] == 'X') ? 'Y' : 'X';
}

static void forward_data(Frame *f)
{
    if (send_all(to_receiver_sock, f, sizeof(Frame)) < 0)
        emit("EVENT|ATTACKER|ERROR|msg=Forward to receiver failed");
}

static void forward_ack(Frame *f)
{
    if (send_all(to_sender_ack_sock, f, sizeof(Frame)) < 0)
        emit("EVENT|ATTACKER|ERROR|msg=Forward ACK to sender failed");
}

/* ─── Process DATA frame ──────────────────────────────────────────────────── */
static void process_data_frame(Frame *frame)
{
    EnterCriticalSection(&stats_mutex);
    stat_intercepted++;
    LeaveCriticalSection(&stats_mutex);

    EnterCriticalSection(&attack_mutex);
    int attack = current_attack;
    int multi  = multi_mask;
    int dly    = delay_ms;
    LeaveCriticalSection(&attack_mutex);

    emit("EVENT|ATTACKER|DATA_RECEIVED|seq=%d|attack=%s",
         frame->sequence, attack_name(attack));

    if (attack == ATTACK_RANDOM) {
        attack = (rand() % 5) + 1;
        emit("EVENT|ATTACKER|RANDOM_RESOLVED|resolved=%s", attack_name(attack));
    }

    if (attack == ATTACK_DROP_DATA) {
        EnterCriticalSection(&stats_mutex); stat_dropped++; LeaveCriticalSection(&stats_mutex);
        emit("EVENT|ATTACKER|DATA_DROPPED|seq=%d", frame->sequence);
        emit_stats(); return;
    }

    if (attack == ATTACK_DELAY) {
        emit("EVENT|ATTACKER|DATA_DELAYED|seq=%d|delay=%d", frame->sequence, dly);
        Sleep(dly);
        forward_data(frame);
        EnterCriticalSection(&stats_mutex); stat_forwarded++; LeaveCriticalSection(&stats_mutex);
        emit("EVENT|ATTACKER|DATA_FORWARDED|seq=%d", frame->sequence);
        emit_stats(); return;
    }

    if (attack == ATTACK_DUPLICATE) {
        forward_data(frame);
        Sleep(50);
        forward_data(frame);
        EnterCriticalSection(&stats_mutex);
        stat_forwarded++; stat_duplicated++;
        LeaveCriticalSection(&stats_mutex);
        emit("EVENT|ATTACKER|DATA_DUPLICATED|seq=%d", frame->sequence);
        emit_stats(); return;
    }

    if (attack == ATTACK_MODIFY) {
        apply_modify(frame);
        forward_data(frame);
        EnterCriticalSection(&stats_mutex);
        stat_forwarded++; stat_modified++;
        LeaveCriticalSection(&stats_mutex);
        emit("EVENT|ATTACKER|DATA_MODIFIED|seq=%d", frame->sequence);
        emit_stats(); return;
    }

    if (attack == ATTACK_MULTI) {
        if (multi & MULTI_DROP_DATA) {
            EnterCriticalSection(&stats_mutex); stat_dropped++; LeaveCriticalSection(&stats_mutex);
            emit("EVENT|ATTACKER|DATA_DROPPED|seq=%d|mode=multi", frame->sequence);
            emit_stats(); return;
        }
        if (multi & MULTI_MODIFY) apply_modify(frame);
        if (multi & MULTI_DELAY) {
            emit("EVENT|ATTACKER|DATA_DELAYED|seq=%d|delay=%d|mode=multi", frame->sequence, dly);
            Sleep(dly);
        }
        forward_data(frame);
        if (multi & MULTI_DUPLICATE) {
            Sleep(50);
            forward_data(frame);
            EnterCriticalSection(&stats_mutex); stat_duplicated++; LeaveCriticalSection(&stats_mutex);
        }
        EnterCriticalSection(&stats_mutex);
        stat_forwarded++;
        if (multi & MULTI_MODIFY) stat_modified++;
        LeaveCriticalSection(&stats_mutex);
        emit("EVENT|ATTACKER|DATA_FORWARDED|seq=%d|mode=multi", frame->sequence);
        emit_stats(); return;
    }

    /* ATTACK_NONE / default */
    forward_data(frame);
    EnterCriticalSection(&stats_mutex); stat_forwarded++; LeaveCriticalSection(&stats_mutex);
    emit("EVENT|ATTACKER|DATA_FORWARDED|seq=%d", frame->sequence);
    emit_stats();
}

/* ─── Process ACK frame ───────────────────────────────────────────────────── */
static void process_ack_frame(Frame *frame)
{
    EnterCriticalSection(&attack_mutex);
    int attack = current_attack;
    int multi  = multi_mask;
    LeaveCriticalSection(&attack_mutex);

    emit("EVENT|ATTACKER|ACK_RECEIVED|seq=%d|attack=%s",
         frame->sequence, attack_name(attack));

    int drop_ack = (attack == ATTACK_DROP_ACK);
    if (attack == ATTACK_MULTI && (multi & MULTI_DROP_ACK)) drop_ack = 1;
    if (attack == ATTACK_RANDOM && (rand() % 2 == 0))       drop_ack = 1;

    if (drop_ack) {
        EnterCriticalSection(&stats_mutex); stat_ack_dropped++; LeaveCriticalSection(&stats_mutex);
        emit("EVENT|ATTACKER|ACK_DROPPED|seq=%d", frame->sequence);
        emit_stats(); return;
    }

    forward_ack(frame);
    emit("EVENT|ATTACKER|ACK_FORWARDED|seq=%d", frame->sequence);
    emit_stats();
}

/* ─── Thread: DATA forwarding ─────────────────────────────────────────────── */
static unsigned __stdcall data_thread(void *arg)
{
    (void)arg;
    emit("EVENT|ATTACKER|DATA_THREAD_START");
    while (1) {
        Frame frame;
        memset(&frame, 0, sizeof(frame));
        if (recv_all(sender_data_sock, &frame, sizeof(Frame)) < 0) {
            emit("EVENT|ATTACKER|ERROR|msg=Sender disconnected");
            break;
        }
        process_data_frame(&frame);
    }
    return 0;
}

/* ─── Thread: ACK forwarding ──────────────────────────────────────────────── */
static unsigned __stdcall ack_thread(void *arg)
{
    (void)arg;
    emit("EVENT|ATTACKER|ACK_THREAD_START");
    while (1) {
        Frame frame;
        memset(&frame, 0, sizeof(frame));
        if (recv_all(receiver_ack_sock, &frame, sizeof(Frame)) < 0) {
            emit("EVENT|ATTACKER|ERROR|msg=Receiver ACK disconnected");
            break;
        }
        process_ack_frame(&frame);
    }
    return 0;
}

/* ─── Apply control command ───────────────────────────────────────────────── */
static void apply_control_command(const char *cmd)
{
    emit("EVENT|ATTACKER|CONTROL_CMD|cmd=%s", cmd);

    if (strncmp(cmd, "SET_ATTACK|", 11) == 0) {
        int mode = atoi(cmd + 11);
        EnterCriticalSection(&attack_mutex);
        current_attack = mode;
        if (mode != ATTACK_MULTI) multi_mask = 0;
        LeaveCriticalSection(&attack_mutex);
        emit("EVENT|ATTACKER|ATTACK_SET|mode=%d|name=%s", mode, attack_name(mode));

    } else if (strncmp(cmd, "SET_DELAY|", 10) == 0) {
        int ms = atoi(cmd + 10);
        if (ms < 0) ms = 0;
        EnterCriticalSection(&attack_mutex);
        delay_ms = ms;
        LeaveCriticalSection(&attack_mutex);
        emit("EVENT|ATTACKER|DELAY_SET|ms=%d", ms);

    } else if (strncmp(cmd, "SET_ATTACKS|", 12) == 0) {
        const char *list = cmd + 12;
        int mask = 0;
        if (strstr(list, "DROP_DATA"))  mask |= MULTI_DROP_DATA;
        if (strstr(list, "DELAY"))      mask |= MULTI_DELAY;
        if (strstr(list, "DUPLICATE"))  mask |= MULTI_DUPLICATE;
        if (strstr(list, "MODIFY"))     mask |= MULTI_MODIFY;
        if (strstr(list, "DROP_ACK"))   mask |= MULTI_DROP_ACK;
        EnterCriticalSection(&attack_mutex);
        current_attack = ATTACK_MULTI;
        multi_mask = mask;
        LeaveCriticalSection(&attack_mutex);
        emit("EVENT|ATTACKER|MULTI_ATTACK_SET|mask=%d|list=%s", mask, list);

    } else {
        emit("EVENT|ATTACKER|UNKNOWN_CMD|cmd=%s", cmd);
    }
}

/* ─── Thread: control listener ────────────────────────────────────────────── */
static unsigned __stdcall control_thread(void *arg)
{
    (void)arg;
    emit("EVENT|ATTACKER|CONTROL_LISTEN|port=%d", CONTROL_PORT);

    while (1) {
        struct sockaddr_in cli;
        int clen = sizeof(cli);
        SOCKET csock = accept(ctrl_listen, (struct sockaddr*)&cli, &clen);
        if (csock == INVALID_SOCKET) {
            emit("EVENT|ATTACKER|CONTROL_ACCEPT_ERR");
            continue;
        }
        emit("EVENT|ATTACKER|CONTROL_CONNECTED");

        char buf[512];
        int  pos = 0;
        char c;
        while (recv(csock, &c, 1, 0) > 0) {
            if (c == '\n') {
                buf[pos] = '\0';
                if (pos > 0) {
                    if (buf[pos-1] == '\r') buf[--pos] = '\0';
                    apply_control_command(buf);
                }
                pos = 0;
            } else if (pos < (int)sizeof(buf) - 1) {
                buf[pos++] = c;
            }
        }
        emit("EVENT|ATTACKER|CONTROL_DISCONNECTED");
        closesocket(csock);
    }
    return 0;
}

/* ─── Create listener ────────────────────────────────────────────────────── */
static SOCKET make_listener(int port)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(s); return INVALID_SOCKET;
    }
    if (listen(s, 2) == SOCKET_ERROR) {
        closesocket(s); return INVALID_SOCKET;
    }
    return s;
}

/* ─── Connect to host:port (with retry) ──────────────────────────────────── */
static SOCKET connect_to(const char *host, int port)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    inet_pton(AF_INET, host, &addr.sin_addr);

    for (int i = 0; i < 20; i++) {
        if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == 0)
            return s;
        Sleep(500);
    }
    closesocket(s);
    return INVALID_SOCKET;
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
    srand((unsigned)time(NULL));

    InitializeCriticalSection(&attack_mutex);
    InitializeCriticalSection(&stats_mutex);

    emit("EVENT|ATTACKER|START");

    /* 1. Create listeners */
    data_listen = make_listener(ATTACKER_DATA_PORT);
    ack_listen  = make_listener(ATTACKER_ACK_PORT);
    ctrl_listen = make_listener(CONTROL_PORT);

    if (data_listen == INVALID_SOCKET ||
        ack_listen  == INVALID_SOCKET ||
        ctrl_listen == INVALID_SOCKET)
    {
        emit("EVENT|ATTACKER|ERROR|msg=Listener creation failed");
        WSACleanup(); return 1;
    }
    emit("EVENT|ATTACKER|LISTENERS_READY|data_port=%d|ack_port=%d|ctrl_port=%d",
         ATTACKER_DATA_PORT, ATTACKER_ACK_PORT, CONTROL_PORT);

    /* 2. Control thread */
    HANDLE ctrl_thr = (HANDLE)_beginthreadex(NULL, 0, control_thread, NULL, 0, NULL);
    if (ctrl_thr) CloseHandle(ctrl_thr);

    /* 3. Connect to receiver (DATA) and sender (ACK) */
    emit("EVENT|ATTACKER|CONNECTING_RECEIVER|host=%s|port=%d",
         RECEIVER_DATA_HOST, RECEIVER_DATA_PORT);
    to_receiver_sock = connect_to(RECEIVER_DATA_HOST, RECEIVER_DATA_PORT);
    if (to_receiver_sock == INVALID_SOCKET) {
        emit("EVENT|ATTACKER|ERROR|msg=Cannot connect to receiver");
        WSACleanup(); return 1;
    }
    emit("EVENT|ATTACKER|RECEIVER_CONNECTED");

    emit("EVENT|ATTACKER|CONNECTING_SENDER_ACK|host=%s|port=%d",
         SENDER_ACK_HOST, SENDER_ACK_PORT);
    to_sender_ack_sock = connect_to(SENDER_ACK_HOST, SENDER_ACK_PORT);
    if (to_sender_ack_sock == INVALID_SOCKET) {
        emit("EVENT|ATTACKER|ERROR|msg=Cannot connect to sender ACK port");
        WSACleanup(); return 1;
    }
    emit("EVENT|ATTACKER|SENDER_ACK_CONNECTED");

    /* 4. Accept connections from sender (DATA) and receiver (ACK) */
    emit("EVENT|ATTACKER|WAIT_SENDER_DATA");
    struct sockaddr_in cli;
    int clen = sizeof(cli);
    sender_data_sock = accept(data_listen, (struct sockaddr*)&cli, &clen);
    if (sender_data_sock == INVALID_SOCKET) {
        emit("EVENT|ATTACKER|ERROR|msg=Accept sender DATA failed");
        WSACleanup(); return 1;
    }
    emit("EVENT|ATTACKER|SENDER_DATA_ACCEPTED");

    emit("EVENT|ATTACKER|WAIT_RECEIVER_ACK");
    receiver_ack_sock = accept(ack_listen, (struct sockaddr*)&cli, &clen);
    if (receiver_ack_sock == INVALID_SOCKET) {
        emit("EVENT|ATTACKER|ERROR|msg=Accept receiver ACK failed");
        WSACleanup(); return 1;
    }
    emit("EVENT|ATTACKER|RECEIVER_ACK_ACCEPTED");

    emit("EVENT|SYSTEM|READY|role=attacker");

    /* 5. Start DATA and ACK forwarding threads */
    HANDLE dthr = (HANDLE)_beginthreadex(NULL, 0, data_thread, NULL, 0, NULL);
    HANDLE athr = (HANDLE)_beginthreadex(NULL, 0, ack_thread,  NULL, 0, NULL);

    WaitForSingleObject(dthr, INFINITE);
    WaitForSingleObject(athr, INFINITE);
    CloseHandle(dthr);
    CloseHandle(athr);

    closesocket(sender_data_sock);
    closesocket(receiver_ack_sock);
    closesocket(to_receiver_sock);
    closesocket(to_sender_ack_sock);
    closesocket(data_listen);
    closesocket(ack_listen);
    closesocket(ctrl_listen);

    DeleteCriticalSection(&attack_mutex);
    DeleteCriticalSection(&stats_mutex);

    emit("EVENT|ATTACKER|SHUTDOWN");
    WSACleanup();
    return 0;
}
