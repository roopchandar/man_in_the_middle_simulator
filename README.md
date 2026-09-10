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
├── gui.py        — Tkinter 3-screen GUI, process controller, event parser
├── Makefile
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

## 4. Three GUI Screens

| Screen | Title | Purpose |
|--------|-------|---------|
| Screen 1 | SENDER MACHINE | Message input, frame visualiser, retransmission view |
| Screen 2 | ATTACKER / MITM | Attack selector, flow visualiser, statistics |
| Screen 3 | RECEIVER MACHINE | Frame validation, delivered messages, statistics |

---

## 5. Port Layout

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

## 10. Python ↔ C Communication

### GUI → attacker.c (TCP control on port 5100)

```
SET_ATTACK|0           # No attack
SET_ATTACK|1           # Drop Data
SET_ATTACK|2           # Delay Data
SET_ATTACK|3           # Duplicate Data
SET_ATTACK|4           # Modify Data
SET_ATTACK|5           # Drop ACK
SET_ATTACK|6           # Random
SET_ATTACK|7           # Multiple
SET_DELAY|2000         # Set delay ms
SET_ATTACKS|DROP_DATA,MODIFY_DATA,DROP_ACK   # Multi bitmask
```

### GUI → sender.c (stdin pipe)

```
SEND|Hello World       # Send a message
QUIT                   # Shutdown sender
```

### C → GUI (stdout pipe, EVENT| protocol)

```
EVENT|SYSTEM|READY|role=sender
EVENT|SENDER|DATA_SENT|seq=0|data=Hello World|checksum=1116
EVENT|SENDER|WAIT_ACK|seq=0|attempt=1
EVENT|SENDER|ACK_TIMEOUT|seq=0
EVENT|SENDER|RETRANSMIT|seq=0|attempt=2
EVENT|SENDER|ACK_RECEIVED|seq=0
EVENT|ATTACKER|DATA_RECEIVED|seq=0|attack=NO_ATTACK
EVENT|ATTACKER|DATA_FORWARDED|seq=0
EVENT|ATTACKER|DATA_DROPPED|seq=0
EVENT|ATTACKER|DATA_DELAYED|seq=0|delay=2000
EVENT|ATTACKER|DATA_DUPLICATED|seq=0
EVENT|ATTACKER|DATA_MODIFIED|seq=0
EVENT|ATTACKER|ACK_RECEIVED|seq=0
EVENT|ATTACKER|ACK_DROPPED|seq=0
EVENT|ATTACKER|ACK_FORWARDED|seq=0
EVENT|ATTACKER|STATS|intercepted=5|forwarded=4|dropped=1|...
EVENT|RECEIVER|DATA_RECEIVED|seq=0|data=Hello World|recv_checksum=1116|calc_checksum=1116
EVENT|RECEIVER|CHECKSUM_VALID|seq=0
EVENT|RECEIVER|CHECKSUM_INVALID|seq=0|recv_checksum=1116|calc_checksum=1138
EVENT|RECEIVER|DUPLICATE|seq=1|expected=0
EVENT|RECEIVER|DELIVERED|seq=0|data=Hello World
EVENT|RECEIVER|ACK_SENT|seq=0
EVENT|RECEIVER|STATS|received=5|valid=4|duplicate=1|corrupted=0|acks=4|expected_seq=0
```

---

## 11. Compilation

```bash
make          # build sender, attacker, receiver
make clean    # remove binaries
```

Manual:
```bash
gcc -Wall -g -pthread -o sender   sender.c
gcc -Wall -g -pthread -o attacker attacker.c
gcc -Wall -g -pthread -o receiver receiver.c
```

---

## 12. Running

### With GUI (recommended)
```bash
python3 gui.py
```
Then click **START SYSTEM**.

### Without GUI (terminal mode)
```bash
# Terminal 1
./receiver

# Terminal 2
./attacker

# Terminal 3
./sender
# Type: SEND|Hello World<Enter>
```

---

## 13. Step-by-Step Test Procedure

1. Run `python3 gui.py`
2. Click **▶ START SYSTEM** — three C processes start
3. Go to **SENDER** tab → enter `Hello World` → click **SEND MESSAGE**
4. Observe EVENT LOG: DATA_SENT → WAIT_ACK → ACK_RECEIVED
5. Go to **ATTACKER** tab → select **Drop Data** → click **APPLY ATTACK**
6. Back to SENDER → send another message
7. Observe: ACK TIMEOUT → RETRANSMITTING (attacker dropped the frame)
8. On ATTACKER tab: flow shows `DATA DROPPED (X)`
9. Select **No Attack** → APPLY → sender retransmit eventually succeeds
10. Go to **RECEIVER** tab → see delivered messages list growing
11. Test **Modify Data** → RECEIVER shows CHECKSUM MISMATCH
12. Test **Duplicate Data** → RECEIVER shows DUPLICATE FRAME warning
13. Test **Multiple Attacks** → check Drop ACK + Modify Data combos
14. Click **■ STOP SYSTEM** to terminate all C processes

---

## 14. System Requirements

- Linux (Ubuntu/Debian/Fedora/Arch or WSL on Windows)
- GCC with pthread support
- Python 3.7+ with Tkinter (`sudo apt install python3-tk` if missing)
