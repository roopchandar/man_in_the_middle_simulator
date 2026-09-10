"""
gui.py — Man-in-the-Middle Simulator GUI
Python is ONLY the GUI / process controller / event visualiser.
All protocol logic, checksums, attacks, and ARQ live in C.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, font as tkfont
import subprocess, threading, queue, socket, os, sys, time, platform

# ── Build helper ──────────────────────────────────────────────────────────────
IS_WIN = platform.system() == "Windows"
SENDER_EXE   = "./sender.exe"   if IS_WIN else "./sender"
ATTACKER_EXE = "./attacker.exe" if IS_WIN else "./attacker"
RECEIVER_EXE = "./receiver.exe" if IS_WIN else "./receiver"

CTRL_HOST = "127.0.0.1"
CTRL_PORT = 5100

# ── Colour palette ────────────────────────────────────────────────────────────
BG      = "#0d1117"
PANEL   = "#161b22"
BORDER  = "#30363d"
ACCENT  = "#58a6ff"
GREEN   = "#3fb950"
RED     = "#f85149"
YELLOW  = "#d29922"
PURPLE  = "#bc8cff"
TEXT    = "#e6edf3"
SUBTEXT = "#8b949e"
MONO    = "Courier"

# ── Utilities ─────────────────────────────────────────────────────────────────
def make_frame(parent, **kw):
    kw.setdefault("bg", PANEL)
    kw.setdefault("relief", "flat")
    return tk.Frame(parent, **kw)

def label(parent, text, color=TEXT, size=10, bold=False, **kw):
    kw.setdefault("bg", PANEL)
    weight = "bold" if bold else "normal"
    return tk.Label(parent, text=text, fg=color, font=(MONO, size, weight), **kw)

def btn(parent, text, cmd, color=ACCENT, **kw):
    b = tk.Button(parent, text=text, command=cmd,
                  bg=color, fg=BG, activebackground=TEXT,
                  activeforeground=BG, relief="flat", cursor="hand2",
                  font=(MONO, 9, "bold"), padx=10, pady=4, **kw)
    b.bind("<Enter>", lambda e: b.config(bg=TEXT))
    b.bind("<Leave>", lambda e: b.config(bg=color))
    return b

def log_append(widget, text, tag="normal"):
    widget.config(state="normal")
    widget.insert("end", text + "\n", tag)
    widget.see("end")
    widget.config(state="disabled")


# ══════════════════════════════════════════════════════════════════════════════
# Process manager — launches C programs and reads their stdout asynchronously
# ══════════════════════════════════════════════════════════════════════════════
class ProcessManager:
    def __init__(self, event_queue: queue.Queue):
        self.q = event_queue
        self.procs = {}          # role -> Popen
        self.threads = {}        # role -> reader thread
        self._ctrl_sock = None   # TCP socket to attacker control port
        self._ctrl_lock = threading.Lock()

    # ── Start / Stop ──────────────────────────────────────────────────────────
    def start_all(self):
        """Start receiver → attacker → sender (order matters for port binding)."""
        try:
            self._start("receiver", RECEIVER_EXE)
            time.sleep(0.4)
            self._start("attacker", ATTACKER_EXE)
            time.sleep(0.6)
            self._start("sender",   SENDER_EXE)
            time.sleep(0.8)
            self._connect_ctrl()
        except Exception as e:
            self.q.put(("ERROR", "SYSTEM", f"Start failed: {e}"))

    def stop_all(self):
        self._disconnect_ctrl()
        for role, p in list(self.procs.items()):
            try:
                p.terminate()
                p.wait(timeout=2)
            except Exception:
                try: p.kill()
                except Exception: pass
        self.procs.clear()
        self.q.put(("STOPPED", "SYSTEM", ""))

    def _start(self, role, exe):
        if not os.path.isfile(exe.lstrip("./")):
            # Try without ./
            bare = exe.replace("./", "")
            if os.path.isfile(bare):
                exe = bare
        p = subprocess.Popen(
            exe, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, bufsize=1, text=True,
            shell=False
        )
        self.procs[role] = p
        t = threading.Thread(target=self._reader, args=(role, p), daemon=True)
        t.start()
        self.threads[role] = t
        self.q.put(("STARTED", role, ""))

    def _reader(self, role, proc):
        try:
            for line in proc.stdout:
                line = line.rstrip()
                if line:
                    self.q.put(("LINE", role, line))
        except Exception:
            pass
        self.q.put(("EXITED", role, ""))

    # ── Control socket to attacker ────────────────────────────────────────────
    def _connect_ctrl(self):
        for _ in range(20):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((CTRL_HOST, CTRL_PORT))
                self._ctrl_sock = s
                self.q.put(("LINE", "attacker", "EVENT|ATTACKER|CTRL_GUI_CONNECTED"))
                return
            except OSError:
                time.sleep(0.5)
        self.q.put(("ERROR", "attacker", "Cannot connect to attacker control port"))

    def _disconnect_ctrl(self):
        with self._ctrl_lock:
            if self._ctrl_sock:
                try: self._ctrl_sock.close()
                except Exception: pass
                self._ctrl_sock = None

    def send_ctrl(self, cmd: str):
        with self._ctrl_lock:
            if self._ctrl_sock:
                try:
                    self._ctrl_sock.sendall((cmd + "\n").encode())
                except Exception as e:
                    self.q.put(("ERROR", "attacker", f"Ctrl send failed: {e}"))

    def send_to_sender(self, cmd: str):
        p = self.procs.get("sender")
        if p and p.stdin:
            try:
                p.stdin.write(cmd + "\n")
                p.stdin.flush()
            except Exception as e:
                self.q.put(("ERROR", "sender", f"Stdin write failed: {e}"))

    def running(self, role):
        p = self.procs.get(role)
        return p is not None and p.poll() is None


# ══════════════════════════════════════════════════════════════════════════════
# Sender Screen
# ══════════════════════════════════════════════════════════════════════════════
class SenderScreen(tk.Frame):
    def __init__(self, master, pm: ProcessManager, **kw):
        super().__init__(master, bg=BG, **kw)
        self.pm = pm
        self._build()

    def _build(self):
        # Title
        label(self, "🖥  SENDER MACHINE", color=ACCENT, size=14, bold=True,
              bg=BG).pack(pady=(12,4))

        # ── Message input ──
        inp_frame = make_frame(self, bg=BG)
        inp_frame.pack(fill="x", padx=20, pady=4)
        label(inp_frame, "Enter Message:", color=SUBTEXT, bg=BG).pack(anchor="w")
        row = make_frame(inp_frame, bg=BG)
        row.pack(fill="x", pady=4)
        self.msg_entry = tk.Entry(row, bg=PANEL, fg=TEXT, insertbackground=TEXT,
                                  relief="flat", font=(MONO, 10), bd=4)
        self.msg_entry.pack(side="left", fill="x", expand=True, ipady=4)
        self.msg_entry.insert(0, "Hello World")
        self.msg_entry.bind("<Return>", lambda e: self._send())
        btn(row, "SEND MESSAGE", self._send, color=GREEN).pack(side="left", padx=(8,0))

        # ── Status block ──
        sf = make_frame(self)
        sf.pack(fill="x", padx=20, pady=6)
        label(sf, "─── SENDER STATUS ───", color=SUBTEXT, size=9).pack(anchor="w")
        grid = make_frame(sf)
        grid.pack(fill="x", pady=4)
        self._sv = {}
        rows = [("Connection:", "● Disconnected", GREEN),
                ("Sequence:", "0", TEXT),
                ("Attempt:", "—", TEXT),
                ("Expected ACK:", "—", TEXT),
                ("Status:", "Idle", TEXT)]
        for i, (k, v, c) in enumerate(rows):
            label(grid, k, color=SUBTEXT, bg=PANEL).grid(row=i, column=0, sticky="w", padx=6, pady=2)
            lbl = label(grid, v, color=c, bg=PANEL)
            lbl.grid(row=i, column=1, sticky="w", padx=6)
            self._sv[k] = lbl

        # ── Frame visualiser ──
        fv = make_frame(self)
        fv.pack(fill="x", padx=20, pady=6)
        label(fv, "─── CURRENT FRAME ───", color=SUBTEXT, size=9).pack(anchor="w")
        self.frame_box = tk.Text(fv, height=7, bg="#0a0e14", fg=GREEN,
                                  font=(MONO, 9), relief="flat", state="disabled",
                                  padx=8, pady=6)
        self.frame_box.pack(fill="x")
        self._clear_frame_box()

        # ── Flow indicator ──
        self.flow_lbl = label(self, "  ", color=ACCENT, size=10, bg=BG)
        self.flow_lbl.pack(pady=2)

        # ── Event log ──
        el = make_frame(self, bg=BG)
        el.pack(fill="both", expand=True, padx=20, pady=6)
        label(el, "─── SENDER EVENT LOG ───", color=SUBTEXT, bg=BG, size=9).pack(anchor="w")
        self.log = scrolledtext.ScrolledText(el, height=10, bg=PANEL, fg=TEXT,
                                              font=(MONO, 8), state="disabled",
                                              relief="flat", padx=6, pady=4)
        self.log.tag_config("ok",      foreground=GREEN)
        self.log.tag_config("warn",    foreground=YELLOW)
        self.log.tag_config("err",     foreground=RED)
        self.log.tag_config("normal",  foreground=TEXT)
        self.log.pack(fill="both", expand=True)

    def _clear_frame_box(self):
        self.frame_box.config(state="normal")
        self.frame_box.delete("1.0", "end")
        self.frame_box.insert("end",
            "┌─────────────────────────────┐\n"
            "│ No frame yet                │\n"
            "└─────────────────────────────┘")
        self.frame_box.config(state="disabled")

    def _send(self):
        msg = self.msg_entry.get().strip()
        if msg:
            self.pm.send_to_sender(f"SEND|{msg}")
            log_append(self.log, f"→ SEND command issued: {msg}", "ok")

    def set_status(self, key, value, color=TEXT):
        lbl = self._sv.get(key + ":")
        if lbl:
            lbl.config(text=value, fg=color)

    def update_frame_box(self, seq, data, checksum):
        self.frame_box.config(state="normal")
        self.frame_box.delete("1.0", "end")
        self.frame_box.insert("end",
            f"┌─────────────────────────────┐\n"
            f"│ DATA FRAME                  │\n"
            f"│                             │\n"
            f"│ Sequence : {seq:<18} │\n"
            f"│ Data     : {data[:18]:<18} │\n"
            f"│ Checksum : {str(checksum):<18} │\n"
            f"└─────────────────────────────┘")
        self.frame_box.config(state="disabled")

    def set_flow(self, text, color=ACCENT):
        self.flow_lbl.config(text=text, fg=color)

    def handle_event(self, parts):
        # parts[0]=EVENT, parts[1]=SENDER, parts[2]=TYPE, parts[3..]=fields
        evt = parts[2] if len(parts) > 2 else ""
        fields = {k: v for p in parts[3:] if "=" in p for k, v in [p.split("=", 1)]}

        if evt == "READY":
            self.set_status("Connection:", "● Connected", GREEN)
            self.set_status("Status:", "Ready", GREEN)
            log_append(self.log, "✓ Sender ready", "ok")

        elif evt == "DATA_SENT":
            seq = fields.get("seq", "?")
            data = fields.get("data", "")
            chk  = fields.get("checksum", "?")
            self.set_status("Sequence:", seq)
            self.set_status("Expected ACK:", f"ACK {seq}")
            self.set_status("Status:", "Frame Sent — Waiting for ACK", YELLOW)
            self.update_frame_box(seq, data, chk)
            self.set_flow(f"  SENDER\n    |\n    | DATA seq={seq}\n    ▼\n  ATTACKER", ACCENT)
            log_append(self.log, f"DATA sent: seq={seq}  checksum={chk}", "ok")

        elif evt == "WAIT_ACK":
            seq = fields.get("seq","?"); att = fields.get("attempt","?")
            self.set_status("Attempt:", att, YELLOW)
            self.set_status("Status:", "Waiting for ACK...", YELLOW)
            log_append(self.log, f"Waiting for ACK {seq} (attempt {att})", "normal")

        elif evt == "ACK_TIMEOUT":
            seq = fields.get("seq","?")
            self.set_status("Status:", "⚠ ACK TIMEOUT", RED)
            self.set_flow(f"  ⚠ ACK TIMEOUT  seq={seq}", RED)
            log_append(self.log, f"⚠ ACK TIMEOUT  seq={seq}", "err")

        elif evt == "RETRANSMIT":
            seq = fields.get("seq","?"); att = fields.get("attempt","?")
            self.set_status("Status:", f"↻ Retransmitting (attempt {att})", YELLOW)
            self.set_status("Attempt:", att, YELLOW)
            self.set_flow(f"  ↻ RETRANSMIT seq={seq} attempt={att}", YELLOW)
            log_append(self.log, f"↻ Retransmitting seq={seq}  attempt={att}", "warn")

        elif evt in ("ACK_RECEIVED", "ACK_OK"):
            seq = fields.get("seq","?")
            self.set_status("Status:", "✓ ACK Received", GREEN)
            self.set_flow(f"  ATTACKER\n    |\n    | ACK {seq}\n    ▼\n  SENDER", GREEN)
            log_append(self.log, f"✓ ACK {seq} received — frame acknowledged", "ok")

        elif evt == "MAX_RETRANSMIT":
            log_append(self.log, "✗ Max retransmissions reached", "err")
            self.set_status("Status:", "✗ Max retransmissions", RED)

        elif evt == "ERROR":
            log_append(self.log, f"✗ ERROR: {fields.get('msg','')}", "err")

        elif evt == "SHUTDOWN":
            self.set_status("Connection:", "● Disconnected", RED)
            self.set_status("Status:", "Shutdown", RED)


# ══════════════════════════════════════════════════════════════════════════════
# Attacker Screen
# ══════════════════════════════════════════════════════════════════════════════
class AttackerScreen(tk.Frame):
    ATTACKS = [
        ("No Attack",       "SET_ATTACK|0"),
        ("Drop Data",       "SET_ATTACK|1"),
        ("Delay Data",      "SET_ATTACK|2"),
        ("Duplicate Data",  "SET_ATTACK|3"),
        ("Modify Data",     "SET_ATTACK|4"),
        ("Drop ACK",        "SET_ATTACK|5"),
        ("Random Attack",   "SET_ATTACK|6"),
        ("Multiple Attacks","SET_ATTACK|7"),
    ]

    def __init__(self, master, pm: ProcessManager, **kw):
        super().__init__(master, bg=BG, **kw)
        self.pm = pm
        self._multi_vars = {}
        self._build()

    def _build(self):
        label(self, "⚔  ATTACKER / MAN-IN-THE-MIDDLE", color=RED, size=14,
              bold=True, bg=BG).pack(pady=(12,4))

        # ── Attack selector ──
        ctrl = make_frame(self, bg=BG)
        ctrl.pack(fill="x", padx=20, pady=4)
        label(ctrl, "─── ATTACK CONTROL ───", color=SUBTEXT, bg=BG, size=9).pack(anchor="w")

        sel_row = make_frame(ctrl, bg=BG)
        sel_row.pack(fill="x", pady=4)
        label(sel_row, "Attack Type:", color=TEXT, bg=BG).pack(side="left", padx=(0,6))
        self.attack_var = tk.StringVar(value="No Attack")
        names = [a[0] for a in self.ATTACKS]
        dd = ttk.Combobox(sel_row, textvariable=self.attack_var, values=names,
                          state="readonly", width=22, font=(MONO, 9))
        dd.pack(side="left")
        dd.bind("<<ComboboxSelected>>", self._on_attack_change)

        # Delay input
        delay_row = make_frame(ctrl, bg=BG)
        delay_row.pack(fill="x", pady=2)
        label(delay_row, "Delay (ms):", color=SUBTEXT, bg=BG).pack(side="left", padx=(0,6))
        self.delay_var = tk.StringVar(value="2000")
        self.delay_entry = tk.Entry(delay_row, textvariable=self.delay_var, width=8,
                                    bg=PANEL, fg=TEXT, insertbackground=TEXT,
                                    relief="flat", font=(MONO, 9))
        self.delay_entry.pack(side="left")
        self.delay_frame = delay_row
        self.delay_frame.pack_forget()

        # Multi-attack checkboxes (hidden unless Multiple selected)
        self.multi_frame = make_frame(ctrl, bg=BG)
        multi_opts = ["Drop Data", "Delay Data", "Duplicate Data",
                      "Modify Data", "Drop ACK"]
        for opt in multi_opts:
            var = tk.BooleanVar()
            self._multi_vars[opt] = var
            cb = tk.Checkbutton(self.multi_frame, text=opt, variable=var,
                                 bg=BG, fg=TEXT, selectcolor=PANEL,
                                 activebackground=BG, activeforeground=ACCENT,
                                 font=(MONO, 9))
            cb.pack(anchor="w", padx=10)

        btn_row = make_frame(ctrl, bg=BG)
        btn_row.pack(pady=6)
        btn(btn_row, "APPLY ATTACK", self._apply_attack, color=RED).pack(side="left", padx=4)

        # ── Flow visualiser ──
        fv = make_frame(self)
        fv.pack(fill="x", padx=20, pady=6)
        label(fv, "─── ATTACK FLOW ───", color=SUBTEXT, size=9).pack(anchor="w")
        self.flow_box = tk.Text(fv, height=9, bg="#0a0e14", fg=YELLOW,
                                 font=(MONO, 9), relief="flat", state="disabled",
                                 padx=8, pady=6)
        self.flow_box.pack(fill="x")
        self._set_flow_text("  (no activity yet)")

        # ── Statistics ──
        sf = make_frame(self)
        sf.pack(fill="x", padx=20, pady=6)
        label(sf, "─── STATISTICS ───", color=SUBTEXT, size=9).pack(anchor="w")
        grid = make_frame(sf)
        grid.pack(fill="x", pady=2)
        self._stats = {}
        keys = ["Intercepted","Forwarded","Dropped","Modified","Duplicated","ACKs Dropped"]
        for i, k in enumerate(keys):
            label(grid, f"{k}:", color=SUBTEXT, bg=PANEL).grid(row=i, column=0, sticky="w", padx=6, pady=1)
            lv = label(grid, "0", color=TEXT, bg=PANEL)
            lv.grid(row=i, column=1, sticky="w", padx=6)
            self._stats[k] = lv

        # Current attack label
        self.cur_attack_lbl = label(sf, "Current: NO ATTACK", color=RED, size=9)
        self.cur_attack_lbl.pack(anchor="w", padx=6, pady=2)

        # ── Event log ──
        el = make_frame(self, bg=BG)
        el.pack(fill="both", expand=True, padx=20, pady=6)
        label(el, "─── ATTACKER EVENT LOG ───", color=SUBTEXT, bg=BG, size=9).pack(anchor="w")
        self.log = scrolledtext.ScrolledText(el, height=8, bg=PANEL, fg=TEXT,
                                              font=(MONO, 8), state="disabled",
                                              relief="flat", padx=6, pady=4)
        self.log.tag_config("ok",     foreground=GREEN)
        self.log.tag_config("warn",   foreground=YELLOW)
        self.log.tag_config("err",    foreground=RED)
        self.log.tag_config("normal", foreground=TEXT)
        self.log.pack(fill="both", expand=True)

    def _on_attack_change(self, _=None):
        name = self.attack_var.get()
        if name == "Delay Data":
            self.delay_frame.pack(fill="x", pady=2)
        else:
            self.delay_frame.pack_forget()
        if name == "Multiple Attacks":
            self.multi_frame.pack(fill="x", pady=2)
        else:
            self.multi_frame.pack_forget()

    def _apply_attack(self):
        name = self.attack_var.get()
        for a_name, cmd in self.ATTACKS:
            if a_name == name:
                if name == "Delay Data":
                    ms = self.delay_var.get().strip() or "2000"
                    self.pm.send_ctrl(f"SET_DELAY|{ms}")
                if name == "Multiple Attacks":
                    selected = []
                    mapping = {
                        "Drop Data": "DROP_DATA", "Delay Data": "DELAY",
                        "Duplicate Data": "DUPLICATE", "Modify Data": "MODIFY_DATA",
                        "Drop ACK": "DROP_ACK"
                    }
                    ms = self.delay_var.get().strip() or "2000"
                    delay_included = self._multi_vars.get("Delay Data", tk.BooleanVar()).get()
                    if delay_included:
                        self.pm.send_ctrl(f"SET_DELAY|{ms}")
                    for opt, var in self._multi_vars.items():
                        if var.get():
                            selected.append(mapping.get(opt, opt.upper()))
                    payload = ",".join(selected) if selected else "NONE"
                    self.pm.send_ctrl(f"SET_ATTACKS|{payload}")
                else:
                    self.pm.send_ctrl(cmd)
                self.cur_attack_lbl.config(text=f"Current: {name.upper()}")
                log_append(self.log, f"→ Attack applied: {name}", "warn")
                break

    def _set_flow_text(self, text):
        self.flow_box.config(state="normal")
        self.flow_box.delete("1.0", "end")
        self.flow_box.insert("end", text)
        self.flow_box.config(state="disabled")

    def _update_stat(self, key, value):
        lbl = self._stats.get(key)
        if lbl:
            lbl.config(text=str(value))

    def handle_event(self, parts):
        evt = parts[2] if len(parts) > 2 else ""
        fields = {k: v for p in parts[3:] if "=" in p for k, v in [p.split("=", 1)]}
        seq = fields.get("seq", "?")

        if evt == "READY":
            log_append(self.log, "✓ Attacker ready", "ok")

        elif evt == "STATS":
            self._update_stat("Intercepted",   fields.get("intercepted", "0"))
            self._update_stat("Forwarded",      fields.get("forwarded", "0"))
            self._update_stat("Dropped",        fields.get("dropped", "0"))
            self._update_stat("Modified",       fields.get("modified", "0"))
            self._update_stat("Duplicated",     fields.get("duplicated", "0"))
            self._update_stat("ACKs Dropped",   fields.get("ack_dropped", "0"))

        elif evt == "DATA_RECEIVED":
            atk = fields.get("attack", "?")
            self._set_flow_text(
                f"  SENDER\n    |\n    | DATA seq={seq}\n    ▼\n"
                f"  [ATTACKER]  attack={atk}\n    |\n    ?\n  RECEIVER")
            log_append(self.log, f"DATA received: seq={seq}  attack={atk}", "normal")

        elif evt == "DATA_FORWARDED":
            self._set_flow_text(
                f"  SENDER\n    |\n    | DATA seq={seq}\n    ▼\n"
                f"  [ATTACKER]\n    |\n    | DATA seq={seq}\n    ▼\n  RECEIVER")
            log_append(self.log, f"✓ DATA forwarded: seq={seq}", "ok")

        elif evt == "DATA_DROPPED":
            self._set_flow_text(
                f"  SENDER\n    |\n    | DATA seq={seq}\n    ▼\n"
                f"  [ATTACKER]\n    |\n    X\n  *** DATA DROPPED ***\n  RECEIVER")
            log_append(self.log, f"✗ DATA DROPPED: seq={seq}", "err")

        elif evt == "DATA_DELAYED":
            dly = fields.get("delay", "?")
            self._set_flow_text(
                f"  SENDER\n    |\n    | DATA\n    ▼\n"
                f"  [ATTACKER]\n    |\n    | DELAYING {dly}ms\n    ▼\n  RECEIVER")
            log_append(self.log, f"⏳ DATA DELAYED: seq={seq}  delay={dly}ms", "warn")

        elif evt == "DATA_DUPLICATED":
            self._set_flow_text(
                f"  SENDER\n    |\n    | DATA seq={seq}\n    ▼\n"
                f"  [ATTACKER]\n   / \\\n  /   \\\n  ▼   ▼\nRCV  RCV\n*** DUPLICATED ***")
            log_append(self.log, f"⚡ DATA DUPLICATED: seq={seq}", "warn")

        elif evt == "DATA_MODIFIED":
            self._set_flow_text(
                f"  SENDER\n    |\n    | DATA seq={seq}\n    ▼\n"
                f"  [ATTACKER]  *** MODIFY ***\n    |\n    | MODIFIED DATA\n    ▼\n  RECEIVER")
            log_append(self.log, f"✏ DATA MODIFIED: seq={seq}", "warn")

        elif evt == "ACK_RECEIVED":
            log_append(self.log, f"ACK received from receiver: seq={seq}", "normal")

        elif evt == "ACK_FORWARDED":
            log_append(self.log, f"✓ ACK forwarded to sender: seq={seq}", "ok")

        elif evt == "ACK_DROPPED":
            self._set_flow_text(
                f"  RECEIVER\n    |\n    | ACK {seq}\n    ▼\n"
                f"  [ATTACKER]\n    |\n    X\n  *** ACK DROPPED ***\n  SENDER")
            log_append(self.log, f"✗ ACK DROPPED: seq={seq}", "err")

        elif evt == "ATTACK_SET":
            name = fields.get("name", "?")
            self.cur_attack_lbl.config(text=f"Current: {name}")
            log_append(self.log, f"Attack set to: {name}", "warn")

        elif evt == "ERROR":
            log_append(self.log, f"✗ ERROR: {fields.get('msg','')}", "err")


# ══════════════════════════════════════════════════════════════════════════════
# Receiver Screen
# ══════════════════════════════════════════════════════════════════════════════
class ReceiverScreen(tk.Frame):
    def __init__(self, master, pm: ProcessManager, **kw):
        super().__init__(master, bg=BG, **kw)
        self.pm = pm
        self._build()

    def _build(self):
        label(self, "📥  RECEIVER MACHINE", color=PURPLE, size=14,
              bold=True, bg=BG).pack(pady=(12,4))

        # ── Status block ──
        sf = make_frame(self)
        sf.pack(fill="x", padx=20, pady=6)
        label(sf, "─── RECEIVER STATUS ───", color=SUBTEXT, size=9).pack(anchor="w")
        grid = make_frame(sf)
        grid.pack(fill="x", pady=4)
        self._sv = {}
        rows = [("Connection:", "● Disconnected", RED),
                ("Expected Seq:", "0", TEXT),
                ("Last Received:", "—", TEXT),
                ("Frames Received:", "0", TEXT),
                ("Valid Frames:", "0", GREEN),
                ("Duplicate Frames:", "0", YELLOW),
                ("Corrupted Frames:", "0", RED),
                ("ACKs Sent:", "0", TEXT)]
        for i, (k, v, c) in enumerate(rows):
            label(grid, k, color=SUBTEXT, bg=PANEL).grid(row=i, column=0, sticky="w", padx=6, pady=1)
            lv = label(grid, v, color=c, bg=PANEL)
            lv.grid(row=i, column=1, sticky="w", padx=6)
            self._sv[k] = lv

        # ── Received frame ──
        fv = make_frame(self)
        fv.pack(fill="x", padx=20, pady=6)
        label(fv, "─── RECEIVED FRAME ───", color=SUBTEXT, size=9).pack(anchor="w")
        self.frame_box = tk.Text(fv, height=8, bg="#0a0e14", fg=PURPLE,
                                  font=(MONO, 9), relief="flat", state="disabled",
                                  padx=8, pady=6)
        self.frame_box.pack(fill="x")
        self._clear_frame_box()

        # Validation status
        self.valid_lbl = label(fv, "", color=GREEN, bg=PANEL, size=10)
        self.valid_lbl.pack(anchor="w", pady=2)

        # ── Delivered messages ──
        dm = make_frame(self, bg=BG)
        dm.pack(fill="x", padx=20, pady=4)
        label(dm, "─── DELIVERED MESSAGES ───", color=SUBTEXT, bg=BG, size=9).pack(anchor="w")
        self.msg_box = scrolledtext.ScrolledText(dm, height=5, bg=PANEL, fg=GREEN,
                                                  font=(MONO, 9), state="disabled",
                                                  relief="flat", padx=6, pady=4)
        self.msg_box.pack(fill="x")

        # ── Event log ──
        el = make_frame(self, bg=BG)
        el.pack(fill="both", expand=True, padx=20, pady=4)
        label(el, "─── RECEIVER EVENT LOG ───", color=SUBTEXT, bg=BG, size=9).pack(anchor="w")
        self.log = scrolledtext.ScrolledText(el, height=7, bg=PANEL, fg=TEXT,
                                              font=(MONO, 8), state="disabled",
                                              relief="flat", padx=6, pady=4)
        self.log.tag_config("ok",     foreground=GREEN)
        self.log.tag_config("warn",   foreground=YELLOW)
        self.log.tag_config("err",    foreground=RED)
        self.log.tag_config("normal", foreground=TEXT)
        self.log.pack(fill="both", expand=True)

    def _clear_frame_box(self):
        self.frame_box.config(state="normal")
        self.frame_box.delete("1.0", "end")
        self.frame_box.insert("end",
            "┌─────────────────────────────┐\n"
            "│ No frame received yet       │\n"
            "└─────────────────────────────┘")
        self.frame_box.config(state="disabled")

    def set_status(self, key, value, color=TEXT):
        lbl = self._sv.get(key)
        if lbl:
            lbl.config(text=value, fg=color)

    def update_frame_box(self, seq, data, recv_cs, calc_cs):
        self.frame_box.config(state="normal")
        self.frame_box.delete("1.0", "end")
        self.frame_box.insert("end",
            f"┌─────────────────────────────┐\n"
            f"│ RECEIVED DATA FRAME         │\n"
            f"│                             │\n"
            f"│ Sequence : {seq:<18} │\n"
            f"│ Data     : {data[:18]:<18} │\n"
            f"│ Recv CSum: {str(recv_cs):<18} │\n"
            f"│ Calc CSum: {str(calc_cs):<18} │\n"
            f"└─────────────────────────────┘")
        self.frame_box.config(state="disabled")

    def handle_event(self, parts):
        evt = parts[2] if len(parts) > 2 else ""
        fields = {k: v for p in parts[3:] if "=" in p for k, v in [p.split("=", 1)]}
        seq = fields.get("seq", "?")

        if evt == "READY":
            self.set_status("Connection:", "● Connected", GREEN)
            log_append(self.log, "✓ Receiver ready", "ok")

        elif evt == "DATA_RECEIVED":
            seq = fields.get("seq","?")
            data = fields.get("data","")
            rc   = fields.get("recv_checksum","?")
            cc   = fields.get("calc_checksum","?")
            exp  = fields.get("expected_seq","?")
            self.update_frame_box(seq, data, rc, cc)
            self.set_status("Last Received:", seq)
            self.set_status("Expected Seq:", exp)
            self.valid_lbl.config(text="")
            log_append(self.log, f"Frame received: seq={seq}  data={data[:20]}", "normal")

        elif evt == "CHECKSUM_VALID":
            self.valid_lbl.config(
                text="✓ CHECKSUM VALID   ✓ VALID SEQUENCE", fg=GREEN)
            log_append(self.log, f"✓ Checksum valid: seq={seq}", "ok")

        elif evt == "CHECKSUM_INVALID":
            rc = fields.get("recv_checksum","?"); cc = fields.get("calc_checksum","?")
            self.valid_lbl.config(
                text=f"✗ CHECKSUM MISMATCH  recv={rc}  calc={cc}", fg=RED)
            log_append(self.log,
                f"✗ Checksum MISMATCH: seq={seq}  recv={rc}  calc={cc}", "err")

        elif evt == "FRAME_DISCARDED":
            log_append(self.log, f"✗ Frame DISCARDED: seq={seq}", "err")
            self.valid_lbl.config(text="✗ FRAME DISCARDED", fg=RED)

        elif evt == "DUPLICATE":
            exp = fields.get("expected","?")
            self.valid_lbl.config(
                text=f"⚠ DUPLICATE FRAME  seq={seq}  expected={exp}", fg=YELLOW)
            log_append(self.log, f"⚠ Duplicate frame: seq={seq}", "warn")

        elif evt == "DELIVERED":
            data = fields.get("data","")
            self.valid_lbl.config(
                text="✓ CHECKSUM VALID   ✓ VALID SEQUENCE   ✓ DELIVERED", fg=GREEN)
            log_append(self.msg_box_append := None or self.log,
                       f"✓ DELIVERED: {data}", "ok")
            # Also add to delivered messages box
            self.msg_box.config(state="normal")
            self.msg_box.insert("end", f"> {data}\n")
            self.msg_box.see("end")
            self.msg_box.config(state="disabled")

        elif evt == "ACK_SENT":
            log_append(self.log, f"ACK sent: seq={seq}", "ok")

        elif evt == "STATS":
            self.set_status("Frames Received:",  fields.get("received","0"))
            self.set_status("Valid Frames:",      fields.get("valid","0"), GREEN)
            self.set_status("Duplicate Frames:",  fields.get("duplicate","0"), YELLOW)
            self.set_status("Corrupted Frames:",  fields.get("corrupted","0"), RED)
            self.set_status("ACKs Sent:",         fields.get("acks","0"))
            self.set_status("Expected Seq:",      fields.get("expected_seq","0"))

        elif evt == "ERROR":
            log_append(self.log, f"✗ ERROR: {fields.get('msg','')}", "err")

        elif evt == "SHUTDOWN":
            self.set_status("Connection:", "● Disconnected", RED)


# ══════════════════════════════════════════════════════════════════════════════
# Network topology header band
# ══════════════════════════════════════════════════════════════════════════════
class TopologyBar(tk.Frame):
    def __init__(self, master, **kw):
        super().__init__(master, bg=PANEL, height=56, **kw)
        self.pack_propagate(False)
        self._build()

    def _build(self):
        self._s_lbl = tk.Label(self, text="┌──────────┐\n│  SENDER  │\n└──────────┘",
                                bg=PANEL, fg=ACCENT, font=(MONO, 8, "bold"))
        self._s_lbl.pack(side="left", padx=(20,0), pady=4)

        self._flow_fwd = tk.Label(self, text="  ──────────▶  ", bg=PANEL, fg=SUBTEXT, font=(MONO, 8))
        self._flow_fwd.pack(side="left")

        self._a_lbl = tk.Label(self, text="┌──────────┐\n│ ATTACKER │\n└──────────┘",
                                bg=PANEL, fg=RED, font=(MONO, 8, "bold"))
        self._a_lbl.pack(side="left")

        self._flow_rev = tk.Label(self, text="  ──────────▶  ", bg=PANEL, fg=SUBTEXT, font=(MONO, 8))
        self._flow_rev.pack(side="left")

        self._r_lbl = tk.Label(self, text="┌──────────┐\n│ RECEIVER │\n└──────────┘",
                                bg=PANEL, fg=PURPLE, font=(MONO, 8, "bold"))
        self._r_lbl.pack(side="left")

        self._ack_lbl = tk.Label(self, text="  ◀─── ACK ───", bg=PANEL, fg=GREEN, font=(MONO, 8))
        self._ack_lbl.pack(side="left")

        # Status dot
        self._sys_lbl = tk.Label(self, text="  ● SYSTEM STOPPED", bg=PANEL,
                                  fg=RED, font=(MONO, 8, "bold"))
        self._sys_lbl.pack(side="right", padx=20)

    def set_system_state(self, running: bool):
        if running:
            self._sys_lbl.config(text="  ● SYSTEM RUNNING", fg=GREEN)
        else:
            self._sys_lbl.config(text="  ● SYSTEM STOPPED", fg=RED)

    def flash_data(self):
        self._flow_fwd.config(fg=YELLOW, text="  ━━━━DATA━━━━▶  ")
        self.after(800, lambda: self._flow_fwd.config(fg=SUBTEXT, text="  ──────────▶  "))

    def flash_ack(self):
        self._ack_lbl.config(fg=GREEN, text="  ◀━━━ ACK ━━━")
        self.after(800, lambda: self._ack_lbl.config(fg=GREEN, text="  ◀─── ACK ───"))


# ══════════════════════════════════════════════════════════════════════════════
# Main Application
# ══════════════════════════════════════════════════════════════════════════════
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Man-in-the-Middle Simulator — Network Attack Demo")
        self.configure(bg=BG)
        self.geometry("950x780")
        self.minsize(800, 640)

        self._eq: queue.Queue = queue.Queue()
        self._pm = ProcessManager(self._eq)
        self._running = False

        self._build_ui()
        self.after(100, self._poll_events)

    # ── UI construction ───────────────────────────────────────────────────────
    def _build_ui(self):
        # Top bar
        top = make_frame(self, bg=BG)
        top.pack(fill="x", padx=0, pady=0)

        title_lbl = tk.Label(top, text="Man-in-the-Middle Network Attack Simulator",
                              bg=BG, fg=TEXT, font=(MONO, 12, "bold"))
        title_lbl.pack(side="left", padx=16, pady=8)

        # Topology bar
        self._topo = TopologyBar(self)
        self._topo.pack(fill="x", padx=0, pady=0)

        # Global controls
        gc = make_frame(self, bg=BG)
        gc.pack(fill="x", padx=16, pady=6)
        self._start_btn = btn(gc, "▶  START SYSTEM",  self._start_system, color=GREEN)
        self._start_btn.pack(side="left", padx=4)
        self._stop_btn  = btn(gc, "■  STOP SYSTEM",   self._stop_system,  color=RED)
        self._stop_btn.pack(side="left", padx=4)
        btn(gc, "🗑  CLEAR LOGS", self._clear_logs, color=BORDER).pack(side="left", padx=4)

        # Process indicators
        self._ind = {}
        for role, color in [("sender", ACCENT), ("attacker", RED), ("receiver", PURPLE)]:
            lbl_row = make_frame(gc, bg=BG)
            lbl_row.pack(side="left", padx=10)
            dot = tk.Label(lbl_row, text="●", fg=BORDER, bg=BG, font=(MONO, 10))
            dot.pack(side="left")
            tk.Label(lbl_row, text=role.capitalize(), fg=SUBTEXT, bg=BG,
                     font=(MONO, 8)).pack(side="left", padx=2)
            self._ind[role] = dot

        # Notebook (three screens)
        style = ttk.Style(self)
        style.theme_use("default")
        style.configure("Dark.TNotebook",
                         background=BG, borderwidth=0)
        style.configure("Dark.TNotebook.Tab",
                         background=PANEL, foreground=SUBTEXT,
                         font=(MONO, 10, "bold"), padding=[18, 6])
        style.map("Dark.TNotebook.Tab",
                  background=[("selected", BORDER)],
                  foreground=[("selected", TEXT)])

        self._nb = ttk.Notebook(self, style="Dark.TNotebook")
        self._nb.pack(fill="both", expand=True, padx=4, pady=0)

        # Scrollable frames for each screen
        self._sender_screen   = self._make_scrollable_screen(SenderScreen)
        self._attacker_screen = self._make_scrollable_screen(AttackerScreen)
        self._receiver_screen = self._make_scrollable_screen(ReceiverScreen)

        self._nb.add(self._sender_screen[0],   text="  🖥 SENDER  ")
        self._nb.add(self._attacker_screen[0], text="  ⚔ ATTACKER  ")
        self._nb.add(self._receiver_screen[0], text="  📥 RECEIVER  ")

    def _make_scrollable_screen(self, ScreenClass):
        container = tk.Frame(self._nb, bg=BG)
        canvas = tk.Canvas(container, bg=BG, highlightthickness=0)
        vsb = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        inner = ScreenClass(canvas, self._pm)
        win_id = canvas.create_window((0, 0), window=inner, anchor="nw")
        def _on_resize(e):
            canvas.itemconfig(win_id, width=e.width)
        canvas.bind("<Configure>", _on_resize)
        inner.bind("<Configure>", lambda e: canvas.configure(
            scrollregion=canvas.bbox("all")))
        # Mouse wheel
        def _wheel(e):
            canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")
        canvas.bind_all("<MouseWheel>", _wheel)
        return container, inner

    # ── System start/stop ─────────────────────────────────────────────────────
    def _start_system(self):
        if self._running:
            return
        self._running = True
        self._topo.set_system_state(True)
        t = threading.Thread(target=self._pm.start_all, daemon=True)
        t.start()

    def _stop_system(self):
        self._running = False
        self._topo.set_system_state(False)
        for role in ["sender", "attacker", "receiver"]:
            self._ind[role].config(fg=BORDER)
        t = threading.Thread(target=self._pm.stop_all, daemon=True)
        t.start()

    def _clear_logs(self):
        for _, screen in [self._sender_screen, self._attacker_screen,
                           self._receiver_screen]:
            for attr in ("log", "msg_box"):
                w = getattr(screen, attr, None)
                if w:
                    w.config(state="normal")
                    w.delete("1.0", "end")
                    w.config(state="disabled")

    # ── Event polling ─────────────────────────────────────────────────────────
    def _poll_events(self):
        try:
            while True:
                kind, role, data = self._eq.get_nowait()
                self._handle_event(kind, role, data)
        except queue.Empty:
            pass
        self.after(50, self._poll_events)

    def _handle_event(self, kind, role, data):
        ss = self._sender_screen[1]
        ats = self._attacker_screen[1]
        rs  = self._receiver_screen[1]

        if kind == "STARTED":
            self._ind[role].config(fg=GREEN)
        elif kind == "EXITED":
            self._ind[role].config(fg=RED)
        elif kind == "STOPPED":
            self._topo.set_system_state(False)
        elif kind == "ERROR":
            pass

        elif kind == "LINE":
            # Parse structured events
            if not data.startswith("EVENT|"):
                return
            parts = data.split("|")
            if len(parts) < 3:
                return
            evt_role = parts[1].upper()
            evt_type = parts[2].upper() if len(parts) > 2 else ""

            if evt_role == "SENDER":
                ss.handle_event(parts)
                if evt_type == "DATA_SENT":
                    self._topo.flash_data()
                elif evt_type in ("ACK_RECEIVED", "ACK_OK"):
                    self._topo.flash_ack()

            elif evt_role == "ATTACKER":
                ats.handle_event(parts)

            elif evt_role == "RECEIVER":
                rs.handle_event(parts)

            elif evt_role == "SYSTEM":
                # Broadcast READY to all
                for screen in [ss, ats, rs]:
                    if hasattr(screen, "handle_event"):
                        try:
                            screen.handle_event(["EVENT", screen.__class__.__name__.upper(), "SYSTEM_READY"])
                        except Exception:
                            pass


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = App()
    app.mainloop()
