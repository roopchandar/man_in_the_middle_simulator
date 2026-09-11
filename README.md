# Man-in-the-Middle Network Attack Simulator

A lab demonstration of Stop-and-Wait ARQ with a Man-in-the-Middle attacker, implemented in C with a Python Tkinter GUI.

---

## 1. Project Objective

Simulate a three-machine communication system:

```
SENDER  ──TCP──▶  ATTACKER  ──TCP──▶  RECEIVER
SENDER  ◀──TCP──  ATTACKER  ◀──TCP──  RECEIVER  (ACK path)
```

The attacker intercepts every frame and can drop, delay, duplicate, or modify it. The Python GUI visualises the process on three separate screens without implementing any protocol logic.

---

## 2. Architecture

```
network_attack_demo/
├── sender.c      — Stop-and-Wait sender, reads SEND| commands from stdin
├── attacker.c    — MITM relay with 8 attack modes and a TCP control port
├── receiver.c    — Validates checksum/sequence, sends ACKs
└── README.md
```

---

## 3. Three C Programs

| Program | Role |
|---------|------|
| `sender.c` | Builds DATA frames, calculates checksum, implements Stop-and-Wait ARQ |
| `attacker.c` | Relays frames between sender and receiver; applies configurable attacks |
| `receiver.c` | Validates checksum and sequence; sends ACKs; detects duplicates |

---



## 4. Port Layout

| Connection | Direction | Port |
|-----------|-----------|------|
| sender → attacker (DATA) | sender connects | 5001 |
| attacker → receiver (DATA) | attacker connects | 5002 |
| receiver → attacker (ACK) | receiver connects | 5003 |
| attacker → sender (ACK) | attacker connects | 5000 |
| GUI → attacker (control) | GUI connects | 5100 |
| sender listens for ACK | sender listens | 5000 |
| receiver listens for DATA | receiver listens | 5002 |
| attacker data listener | attacker listens | 5001 |
| attacker ACK listener | attacker listens | 5003 |
| attacker control listener | attacker listens | 5100 |

**Start order** (important — binds ports before connections):
1. receiver
2. attacker
3. sender

---

## 6. Frame Format

```c
typedef struct {
    int  type;           // FRAME_DATA=0 or FRAME_ACK=1
    int  sequence;       // 0 or 1 (Stop-and-Wait alternating bit)
    char data[1024];     // payload (DATA frames only)
    unsigned int checksum; // sum of bytes in data[]
} Frame;
```

Frames are sent as raw binary structs over TCP.

---

## 7. Checksum

Simple byte-sum checksum computed in C:

```c
unsigned int compute_checksum(const char *data, int len) {
    unsigned int sum = 0;
    for (int i = 0; i < len; i++)
        sum += (unsigned char)data[i];
    return sum;
}
```

- **Sender** calculates checksum before sending.
- **Attacker** (Modify Data) changes `data[0]` without recalculating.
- **Receiver** recalculates and compares; discards on mismatch.
- **Python GUI never calculates checksums.**

---

## 8. Stop-and-Wait ARQ

Implemented entirely in C:

**Sender:**
1. Build DATA frame with sequence number and checksum
2. Send frame to attacker
3. Wait for ACK (3-second timeout)
4. On timeout: retransmit (up to 10 attempts)
5. On correct ACK: toggle sequence 0↔1, send next message

**Receiver:**
1. Receive DATA frame
2. Validate checksum → discard on mismatch (no ACK)
3. Check sequence number → send duplicate ACK if already seen
4. Deliver to application, toggle expected sequence
5. Send ACK

---

## 9. Attack Mechanisms

| # | Mode | attacker.c Behaviour |
|---|------|----------------------|
| 0 | No Attack | Forward frame unchanged |
| 1 | Drop Data | Discard DATA; no forward to receiver |
| 2 | Delay Data | Sleep N ms then forward |
| 3 | Duplicate Data | Forward frame twice |
| 4 | Modify Data | Change `data[0]`, do NOT recalculate checksum |
| 5 | Drop ACK | Discard ACK; do NOT forward to sender |
| 6 | Random Attack | Randomly selects attack 1–5 per frame |
| 7 | Multiple Attacks | Apply bitmask combination of selected attacks |

**Expected Results:**

| Attack | Expected Result |
|--------|----------------|
| No Attack | Normal delivery |
| Drop Data | Timeout + retransmission by sender |
| Delay Data | Delayed delivery; may trigger timeout |
| Duplicate Data | Receiver detects duplicate; sends dup ACK |
| Modify Data | Checksum mismatch; frame discarded |
| Drop ACK | Timeout + retransmission by sender |
| Random Attack | Random attack behaviour per frame |
| Multiple Attacks | Combination of selected attack effects |

---
