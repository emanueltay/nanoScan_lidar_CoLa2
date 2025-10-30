import socket
import time
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime, timedelta, date

# -----------------------------
# CoLa2 protocol helpers
# -----------------------------

def _recv_for(sock: socket.socket, duration_sec: float, chunk_size: int = 8192) -> bytes:
    """Receive bytes from socket for up to duration_sec, collecting fragmented frames."""
    end = time.time() + duration_sec
    buf = bytearray()
    while time.time() < end:
        try:
            part = sock.recv(chunk_size)
            if not part:
                break
            buf.extend(part)
        except socket.timeout:
            continue
    return bytes(buf)


def cola2_make_request(ip_address: str, command_mode: str, command_hex: str, timeout=0.5) -> bytes:
    """
    One-shot CoLa2 request:
      - open session (OX)
      - send command (r / m1 / m2 / c)
      - read response (~300ms)
      - close session (CX)
    Returns raw bytes response from the command (not including OA/CA).
    Raises exceptions on failure instead of exiting/printing.
    """
    port = 2122
    # OA (Open session)
    oa_hex = "020202020000000d00000000000000014f581e0000"
    oa = bytes.fromhex(oa_hex)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect((ip_address, port))
        s.sendall(oa)

        # Read OA reply (allow fragmentation)
        data = _recv_for(s, 0.3)
        if not data or len(data) < 16:
            raise RuntimeError("No/short OA reply; session not opened.")

        resp_hex = data.hex()
        # SessionID sits after: 4*0x02 + 4(LEN) + 2(Hub, NoC) = offset 10..13 (bytes)
        # In hex-string indexing, 20..28 (8 hex chars)
        if len(resp_hex) < 28:
            raise RuntimeError("Malformed OA reply.")
        session_id = resp_hex[20:28]  # 4 bytes in hex

        # Build the request telegram with the session ID
        if command_mode == "r":       # Read variable, Indexed (RI)
            # 0x02020202 + len(0x0000000c) + 0000 + session + 0001 + 'RI' + index(LE)
            header0 = "020202020000000c0000"
            header1 = "00015249"
            final_hex = header0 + session_id + header1 + command_hex
        elif command_mode == "m1":    # Method MI with 1 byte parameter (identify)
            header0 = "020202020000000e0000"
            header1 = "00024d49"
            final_hex = header0 + session_id + header1 + command_hex
        elif command_mode == "m2":    # Method MI multi-parameter (UDP config)
            header0 = "02020202000000280000"
            header1 = "00034d49b0000000000001"
            final_hex = header0 + session_id + header1 + command_hex
        elif command_mode == "c":     # Custom full CoLa2 frame (session placeholder at 00000000)
            # splice session_id into caller's full frame
            # assumes caller put 8 hex chars of zeros for session at the right place
            if len(command_hex) < 36:
                raise ValueError("Custom hex too short to inject SessionID.")
            # Take header up to session id placeholder (after '0000'), inject session, rest
            # This mirrors your CLI's slicing: requestPart1 = [:20], requestPart2 = [28:]
            part1 = command_hex[:20]
            part2 = command_hex[28:]
            final_hex = part1 + session_id + part2
        else:
            raise ValueError(f"Unknown command_mode '{command_mode}'.")

        req = bytes.fromhex(final_hex)
        s.sendall(req)

        # Read command reply (allow fragmentation)
        reply = _recv_for(s, 0.3)
        if not reply:
            raise RuntimeError("No reply to request (timeout).")

        # Check CoLa2 error FA (ASCII 'FA' at specific header position)
        rh = reply.hex()
        if len(rh) >= 36 and rh[32:36].lower() == "4641":  # 'FA'
            # Device sends an FA error frame; extract a hint if present
            raise RuntimeError("Device returned CoLa2 error (FA).")

        # Close session (CX), then return the command reply bytes
        cx_hex = "020202020000000a0000" + session_id + "00054358"
        s.sendall(bytes.fromhex(cx_hex))
        time.sleep(0.1)
        return reply


# -----------------------------
# Tiny parsers for common reads
# -----------------------------

def parse_ascii_tail(data: bytes, start: int = 21) -> str:
    return data[start:].decode("utf-8", errors="replace")

def parse_ascii_range(data: bytes, start: int, end: int) -> str:
    return data[start:end].decode("utf-8", errors="replace")

def parse_u8(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off+1], "little", signed=False)

def parse_u16(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off+2], "little", signed=False)

def parse_u32(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off+4], "little", signed=False)

def parse_i32_q22(data: bytes, off: int) -> float:
    # angle Q22.10 style used in doc (1/4194304 deg)
    return int.from_bytes(data[off:off+4], "little", signed=True) / 4194304.0


# -----------------------------
# GUI Application
# -----------------------------

class Cola2GUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SICK CoLa2 (TCP 2122)")
        self.minsize(760, 520)

        self._build_ui()

    def _build_ui(self):
        pad = 10
        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=1)

        style = ttk.Style(self)
        # Use a pleasant default theme
        if "vista" in style.theme_names():
            style.theme_use("vista")
        elif "clam" in style.theme_names():
            style.theme_use("clam")

        # Connection bar
        bar = ttk.Frame(self)
        bar.grid(row=0, column=0, sticky="ew", padx=pad, pady=(pad, 5))
        bar.grid_columnconfigure(1, weight=1)

        ttk.Label(bar, text="IP:").grid(row=0, column=0, sticky="e", padx=(0, 5))
        self.ip_var = tk.StringVar(value="192.168.0.2")
        ttk.Entry(bar, textvariable=self.ip_var, width=18).grid(row=0, column=1, sticky="w")

        self.run_btn = ttk.Button(bar, text="Test OA", command=self.on_test_oa)
        self.run_btn.grid(row=0, column=2, padx=(10, 0))

        # Tabs
        nb = ttk.Notebook(self)
        nb.grid(row=1, column=0, sticky="nsew", padx=pad, pady=5)

        # Tab: Read variables
        self.tab_read = ttk.Frame(nb)
        nb.add(self.tab_read, text="Read")

        self._build_read_tab(self.tab_read)

        # Tab: Methods
        self.tab_methods = ttk.Frame(nb)
        nb.add(self.tab_methods, text="Methods")
        self._build_methods_tab(self.tab_methods)

        # Tab: Custom
        self.tab_custom = ttk.Frame(nb)
        nb.add(self.tab_custom, text="Custom")
        self._build_custom_tab(self.tab_custom)

        # Output area
        out = ttk.LabelFrame(self, text="Output")
        out.grid(row=2, column=0, sticky="nsew", padx=pad, pady=(0, pad))
        out.grid_rowconfigure(0, weight=1)
        out.grid_columnconfigure(0, weight=1)

        self.text = tk.Text(out, wrap="word", font=("Consolas", 10))
        self.text.grid(row=0, column=0, sticky="nsew")
        yscroll = ttk.Scrollbar(out, orient="vertical", command=self.text.yview)
        yscroll.grid(row=0, column=1, sticky="ns")
        self.text.configure(yscrollcommand=yscroll.set)

        # helpful tags
        self.text.tag_configure("time", foreground="#2a7ae2")
        self.text.tag_configure("error", foreground="#b00020")
        self.text.tag_configure("ok", foreground="#1a6e1a")

    def _build_read_tab(self, parent):
        pad = 8
        frm = ttk.Frame(parent)
        frm.pack(fill="x", padx=10, pady=10)

        ttk.Label(frm, text="Select read:").grid(row=0, column=0, sticky="w")
        self.read_options = [
            ("Serial numbers", "0300"),
            ("Firmware version", "0400"),
            ("Type code", "0d00"),
            ("Part number", "0e00"),
            ("Status overview", "1700"),
        ]
        self.read_var = tk.StringVar(value=self.read_options[0][1])
        opt = ttk.Combobox(frm, values=[x[0] for x in self.read_options], state="readonly", width=28)
        opt.grid(row=0, column=1, padx=(10, 0))
        opt.current(0)
        opt.bind("<<ComboboxSelected>>", lambda e: self._on_read_choice(opt.current()))

        # Measurement channel
        ttk.Label(frm, text="Measurement channel:").grid(row=1, column=0, sticky="w", pady=(pad, 0))
        self.chan_var = tk.StringVar(value="b300")  # channel 0 default
        ch = ttk.Combobox(frm, values=["0 (b300)", "1 (b400)", "2 (b500)", "3 (b600)"], state="readonly", width=28)
        ch.grid(row=1, column=1, padx=(10, 0), pady=(pad, 0))
        ch.current(0)
        ch.bind("<<ComboboxSelected>>", lambda e: self._on_chan_choice(ch.current()))

        # Buttons row
        btns = ttk.Frame(parent)
        btns.pack(fill="x", padx=10, pady=(0, 10))
        ttk.Button(btns, text="Read selected", command=self.on_read_selected).pack(side="left")
        ttk.Button(btns, text="Read measurement HEX", command=self.on_read_measure_hex).pack(side="left", padx=10)

    def _on_read_choice(self, idx):
        self.read_var.set(self.read_options[idx][1])

    def _on_chan_choice(self, idx):
        # b3xx where xx increments
        mapping = ["b300", "b400", "b500", "b600"]
        self.chan_var.set(mapping[idx])

    def _build_methods_tab(self, parent):
        pad = 8
        frm = ttk.Frame(parent)
        frm.pack(fill="x", padx=10, pady=10)

        # Identify device (blue)
        ttk.Label(frm, text="Identify device (seconds 1..255):").grid(row=0, column=0, sticky="w")
        self.ident_secs = tk.IntVar(value=5)
        ttk.Spinbox(frm, from_=1, to=255, textvariable=self.ident_secs, width=6).grid(row=0, column=1, padx=10)
        ttk.Button(frm, text="Run Identify", command=self.on_identify).grid(row=0, column=2)

    def _build_custom_tab(self, parent):
        pad = 8
        frm = ttk.Frame(parent)
        frm.pack(fill="x", padx=10, pady=10)

        ttk.Label(frm, text="Custom CoLa2 HEX (session placeholder = 00000000):").grid(row=0, column=0, sticky="w")
        self.custom_hex = tk.StringVar(value="020202020000000c00000000000000015249b300")
        ent = ttk.Entry(frm, textvariable=self.custom_hex, width=96)
        ent.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(5, 0))
        ttk.Button(frm, text="Send Custom", command=self.on_custom).grid(row=2, column=0, pady=(10,0))

    # -----------------------------
    # Button handlers (threaded)
    # -----------------------------

    def on_test_oa(self):
        ip = self.ip_var.get().strip()
        self._run_thread(self._do_test_oa, ip)

    def _do_test_oa(self, ip):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            # Just open session then close (we'll reuse the request path with 'r' but a tiny read)
            # Send a harmless read that should ack, e.g. firmware version 0x0400
            data = cola2_make_request(ip, "r", "0400")
            self._log(f"[{ts}] OA/RI OK ({len(data)} bytes)\n", "ok")
        except Exception as e:
            self._log(f"[{ts}] OA test failed: {e}\n", "error")

    def on_read_selected(self):
        ip = self.ip_var.get().strip()
        cmd = self.read_var.get()
        self._run_thread(self._do_read_selected, ip, cmd)

    def _do_read_selected(self, ip, cmd):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            data = cola2_make_request(ip, "r", cmd)
            hx = data.hex(" ")
            self._log(f"[{ts}] Read 0x{cmd} OK ({len(data)} bytes)\n", "ok")
            # quick parse for popular ones
            if cmd == "0300":
                # serials at offsets 22..29 and 31..41 in your CLI
                sn1 = parse_ascii_range(data, 22, 30)
                sn2 = parse_ascii_range(data, 31, 42)
                self._log(f"Serials: Sensor={sn1} | SystemPlug={sn2}\n", None)
            elif cmd in ("0400", "0d00", "0e00"):
                self._log(parse_ascii_tail(data, 21) + "\n", None)
            elif cmd == "1700":
                ver_major = data[20:21].decode("utf-8", "replace")
                ver_minor = parse_u8(data, 21)
                ver_patch = parse_u8(data, 22)
                ver_build = parse_u8(data, 23)
                self._log(f"Version: {ver_major}{ver_minor}.{ver_patch}.{ver_build}\n", None)
            self._log(f"HEX:\n{hx}\n\n", None)
        except Exception as e:
            self._log(f"[{ts}] Read failed: {e}\n", "error")

    def on_read_measure_hex(self):
        ip = self.ip_var.get().strip()
        chan = self.chan_var.get()
        self._run_thread(self._do_read_measure_hex, ip, chan)

    def _do_read_measure_hex(self, ip, chan_hex):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            data = cola2_make_request(ip, "r", chan_hex)
            self._log(f"[{ts}] Measurement ({chan_hex}) OK, {len(data)} bytes\n", "ok")
            self._log(f"HEX dump (first 256 bytes):\n{data[:256].hex(' ')}\n\n", None)
        except Exception as e:
            self._log(f"[{ts}] Measurement read failed: {e}\n", "error")

    def on_identify(self):
        ip = self.ip_var.get().strip()
        secs = self.ident_secs.get()
        self._run_thread(self._do_identify, ip, secs)

    def _do_identify(self, ip, secs):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            duration_hex = f"{secs:02x}00"
            # method m1  -> command = "0e00" + duration + "00"
            cmd = "0e00" + duration_hex + "00"
            _ = cola2_make_request(ip, "m1", cmd)
            self._log(f"[{ts}] Identify triggered for {secs} s\n", "ok")
        except Exception as e:
            self._log(f"[{ts}] Identify failed: {e}\n", "error")

    def on_custom(self):
        ip = self.ip_var.get().strip()
        hx = self.custom_hex.get().strip().replace(" ", "").lower()
        self._run_thread(self._do_custom, ip, hx)

    def _do_custom(self, ip, hx):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            data = cola2_make_request(ip, "c", hx)
            self._log(f"[{ts}] Custom OK ({len(data)} bytes)\n", "ok")
            self._log(f"HEX:\n{data.hex(' ')}\n\n", None)
        except Exception as e:
            self._log(f"[{ts}] Custom failed: {e}\n", "error")

    # -----------------------------
    # Thread runner and logger
    # -----------------------------

    def _run_thread(self, fn, *args):
        def runner():
            try:
                self.run_btn.config(state="disabled")
                fn(*args)
            finally:
                self.run_btn.config(state="normal")
        threading.Thread(target=runner, daemon=True).start()

    def _log(self, text, tag=None):
        self.text.insert("end", text, tag)
        self.text.see("end")

if __name__ == "__main__":
    app = Cola2GUI()
    app.mainloop()
