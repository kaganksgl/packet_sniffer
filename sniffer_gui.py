#!/usr/bin/env python3
"""Desktop front-end for the packet_sniffer.c packet sniffer.

Collects the sniffer's command line options in a small Tk window, runs the
compiled binary, and tails its log file into a live output pane.
"""

import ipaddress
import os
import queue
import shutil
import signal
import subprocess
import sys
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, scrolledtext, ttk

APP_DIR = os.path.dirname(os.path.abspath(__file__))
BINARY = os.path.join(APP_DIR, "sniffer")
LOG_DIR = os.path.join(os.path.expanduser("~"), ".local", "share", "packet-sniffer", "logs")
WINDOW_ICON = os.path.join(APP_DIR, "packet-sniffer-128.png")

MAX_VIEW_LINES = 20000     # trim the pane so a long capture cannot grow without bound
MAX_READ_CHUNK = 256 * 1024  # bytes pulled from the log per poll

MONO = ("monospace", 10)
BG = "#1e2127"
FG = "#d7dae0"


def interface_names():
    try:
        names = sorted(os.listdir("/sys/class/net"))
    except OSError:
        names = []
    return [""] + names


def has_net_raw_capability(path):
    """True when the binary carries file capabilities (so no root is needed)."""
    try:
        os.getxattr(path, "security.capability")
        return True
    except OSError:
        return False


class SnifferApp:
    def __init__(self, root):
        self.root = root
        self.proc = None
        self.tail_thread = None
        self.stop_tail = threading.Event()
        self.terminator = None
        self.lines = queue.Queue()
        self.packet_count = 0
        self.log_path = None
        self.pid_file = None

        root.title("Packet Sniffer")
        root.geometry("980x680")
        root.minsize(760, 520)
        self._set_window_icon()

        self._build_filters()
        self._build_controls()
        self._build_output()
        self._build_status()

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(120, self._drain_queue)
        self._check_binary()

    # ---------------------------------------------------------------- layout

    def _build_filters(self):
        box = ttk.LabelFrame(self.root, text="Capture filters  (leave a field empty to match anything)")
        box.pack(fill="x", padx=10, pady=(10, 6))

        for col in (1, 3):
            box.columnconfigure(col, weight=1)

        self.src_ip = tk.StringVar()
        self.dst_ip = tk.StringVar()
        self.src_port = tk.StringVar()
        self.dst_port = tk.StringVar()
        self.src_if = tk.StringVar()
        self.dst_if = tk.StringVar()
        self.protocol = tk.StringVar(value="any")

        ifaces = interface_names()

        def entry(label, var, row, col):
            ttk.Label(box, text=label).grid(row=row, column=col, sticky="e", padx=(10, 6), pady=5)
            e = ttk.Entry(box, textvariable=var, width=20)
            e.grid(row=row, column=col + 1, sticky="ew", padx=(0, 10), pady=5)
            return e

        entry("Source IP", self.src_ip, 0, 0)
        entry("Destination IP", self.dst_ip, 0, 2)
        entry("Source port", self.src_port, 1, 0)
        entry("Destination port", self.dst_port, 1, 2)

        ttk.Label(box, text="Source interface").grid(row=2, column=0, sticky="e", padx=(10, 6), pady=5)
        ttk.Combobox(box, textvariable=self.src_if, values=ifaces, state="readonly", width=18) \
            .grid(row=2, column=1, sticky="ew", padx=(0, 10), pady=5)
        ttk.Label(box, text="Destination interface").grid(row=2, column=2, sticky="e", padx=(10, 6), pady=5)
        ttk.Combobox(box, textvariable=self.dst_if, values=ifaces, state="readonly", width=18) \
            .grid(row=2, column=3, sticky="ew", padx=(0, 10), pady=5)

        proto = ttk.Frame(box)
        proto.grid(row=3, column=0, columnspan=4, sticky="w", padx=10, pady=(2, 8))
        ttk.Label(proto, text="Protocol:").pack(side="left", padx=(0, 8))
        for text, value in (("Any (TCP + UDP)", "any"), ("TCP only", "tcp"), ("UDP only", "udp")):
            ttk.Radiobutton(proto, text=text, value=value, variable=self.protocol).pack(side="left", padx=(0, 12))

    def _build_controls(self):
        bar = ttk.Frame(self.root)
        bar.pack(fill="x", padx=10, pady=(0, 6))

        self.start_btn = ttk.Button(bar, text="Start capture", command=self.start)
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(bar, text="Stop", command=self.stop, state="disabled")
        self.stop_btn.pack(side="left", padx=6)

        ttk.Button(bar, text="Clear view", command=self.clear_view).pack(side="left", padx=(18, 6))
        ttk.Button(bar, text="Save log as…", command=self.save_log_as).pack(side="left", padx=6)
        ttk.Button(bar, text="Open log folder", command=self.open_log_folder).pack(side="left", padx=6)

        self.autoscroll = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="Auto-scroll", variable=self.autoscroll).pack(side="right")

    def _build_output(self):
        frame = ttk.LabelFrame(self.root, text="Live capture")
        frame.pack(fill="both", expand=True, padx=10, pady=(0, 6))
        self.out = scrolledtext.ScrolledText(
            frame, wrap="none", font=MONO, bg=BG, fg=FG,
            insertbackground=FG, relief="flat", state="disabled",
        )
        self.out.pack(fill="both", expand=True, padx=4, pady=4)
        self.out.tag_config("header", foreground="#61afef")
        self.out.tag_config("info", foreground="#98c379")
        self.out.tag_config("error", foreground="#e06c75")

    def _build_status(self):
        bar = ttk.Frame(self.root)
        bar.pack(fill="x", padx=10, pady=(0, 10))
        self.status = tk.StringVar(value="Idle")
        self.counter = tk.StringVar(value="Packets: 0")
        ttk.Label(bar, textvariable=self.status).pack(side="left")
        ttk.Label(bar, textvariable=self.counter).pack(side="right")

    def _set_window_icon(self):
        """Use the bundled icon if install.sh rendered it; the app works without."""
        if not os.path.exists(WINDOW_ICON):
            return
        try:
            self._icon = tk.PhotoImage(file=WINDOW_ICON)
            self.root.iconphoto(True, self._icon)
        except tk.TclError:
            pass

    # ------------------------------------------------------------- utilities

    def write(self, text, tag=None):
        self.out.configure(state="normal")
        self.out.insert("end", text, tag or ())
        # A capture can run for hours; drop the oldest lines so the widget does
        # not grow without limit. The full capture is always in the log file.
        excess = int(self.out.index("end-1c").split(".")[0]) - MAX_VIEW_LINES
        if excess > 0:
            self.out.delete("1.0", "%d.0" % (excess + 1))
        if self.autoscroll.get():
            self.out.see("end")
        self.out.configure(state="disabled")

    def _check_binary(self):
        if not os.path.exists(BINARY):
            self.write("The sniffer binary is missing. Run 'make' in %s.\n" % APP_DIR, "error")
            self.status.set("sniffer binary not built")
            self.start_btn.configure(state="disabled")
            return
        if has_net_raw_capability(BINARY):
            self.write("Ready. Capture permission is granted on the sniffer binary.\n", "info")
            self.status.set("Idle — ready to capture")
        else:
            self.write(
                "Ready. The sniffer has no capture permission yet, so each capture asks for\n"
                "your password. Run 'make setcap' once in %s to stop the prompts.\n" % APP_DIR,
                "info",
            )
            self.status.set("Idle — will ask for authentication")

    def build_args(self):
        args = []
        if self.protocol.get() == "tcp":
            args.append("--tcp")
        elif self.protocol.get() == "udp":
            args.append("--udp")

        for flag, var, label in (
            ("--sip", self.src_ip, "Source IP"),
            ("--dip", self.dst_ip, "Destination IP"),
        ):
            value = var.get().strip()
            if value:
                try:
                    ipaddress.IPv4Address(value)
                except ipaddress.AddressValueError:
                    raise ValueError("%s must be a dotted IPv4 address, got %r." % (label, value))
                args += [flag, value]

        for flag, var, label in (
            ("--sport", self.src_port, "Source port"),
            ("--dport", self.dst_port, "Destination port"),
        ):
            value = var.get().strip()
            if value:
                if not value.isdigit() or not 1 <= int(value) <= 65535:
                    raise ValueError("%s must be a number between 1 and 65535, got %r." % (label, value))
                args += [flag, value]

        for flag, var in (("--sif", self.src_if), ("--dif", self.dst_if)):
            value = var.get().strip()
            if value:
                args += [flag, value]

        return args

    # --------------------------------------------------------------- capture

    def start(self):
        if self.proc is not None:
            return
        try:
            args = self.build_args()
        except ValueError as exc:
            messagebox.showerror("Invalid filter", str(exc))
            return

        self._ensure_log_dir()
        self.log_path = self._new_log_path()

        cmd = [BINARY] + args + ["--logfile", self.log_path]
        privileged = has_net_raw_capability(BINARY)
        if not privileged:
            # pkexec keeps the sniffer alive after it exits, so record the root
            # PID and signal it from stop().
            self.pid_file = self.log_path + ".pid"
            cmd = ["pkexec", "sh", "-c", 'echo $$ > "$1"; shift 2; exec "$@"',
                   "sh", self.pid_file, "--"] + cmd

        try:
            self.proc = subprocess.Popen(
                cmd, cwd=APP_DIR, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, start_new_session=True,
            )
        except OSError as exc:
            messagebox.showerror("Cannot start capture", str(exc))
            self.proc = None
            return

        self.packet_count = 0
        self.counter.set("Packets: 0")
        self.clear_view()
        self.write("$ %s\n\n" % " ".join(cmd), "info")

        while not self.lines.empty():   # drop anything left from the previous run
            self.lines.get_nowait()

        self.stop_tail = threading.Event()   # a fresh flag per capture
        self.tail_thread = threading.Thread(
            target=self._tail_log, args=(self.log_path, self.stop_tail), daemon=True)
        self.tail_thread.start()
        threading.Thread(target=self._read_process, args=(self.proc,), daemon=True).start()

        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.status.set("Capturing → %s" % self.log_path)

    @staticmethod
    def _ensure_log_dir():
        """Create the log directory private, and tighten it if it already exists."""
        os.makedirs(LOG_DIR, mode=0o700, exist_ok=True)
        try:
            os.chmod(LOG_DIR, 0o700)
        except OSError:
            pass

    def _new_log_path(self):
        """A fresh 0600 log file. Two captures in the same second must not collide."""
        base = os.path.join(LOG_DIR, "capture-%s" % datetime.now().strftime("%Y%m%d-%H%M%S"))
        path, suffix = base + ".log", 2
        while True:
            try:
                fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
            except FileExistsError:
                path = "%s-%d.log" % (base, suffix)
                suffix += 1
                continue
            os.close(fd)
            return path

    def stop(self):
        proc, self.proc = self.proc, None
        self.stop_tail.set()
        pid_file, self.pid_file = self.pid_file, None

        if proc is not None and proc.poll() is None:
            # Signalling a pkexec-launched capture means another authentication
            # prompt, so do it off the UI thread instead of freezing the window.
            self.terminator = threading.Thread(
                target=self._terminate, args=(proc, pid_file), daemon=True)
            self.terminator.start()
        elif pid_file:
            self._remove_pid_file(pid_file)

        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.status.set("Stopped — log saved to %s" % (self.log_path or "(none)"))
        self.write("\n--- capture stopped ---\n", "info")

    def _terminate(self, proc, pid_file):
        root_pid = self._read_pid_file(pid_file)
        if root_pid:
            kill = shutil.which("kill") or "/usr/bin/kill"
            subprocess.run(["pkexec", kill, "-TERM", str(root_pid)], check=False)
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        except OSError:
            pass
        if pid_file:
            self._remove_pid_file(pid_file)

    @staticmethod
    def _remove_pid_file(path):
        try:
            os.remove(path)
        except OSError:
            pass

    @staticmethod
    def _read_pid_file(pid_file):
        if not pid_file:
            return None
        for _ in range(20):  # the root shell may not have written it yet
            try:
                with open(pid_file) as fh:
                    text = fh.read().strip()
                if text.isdigit():
                    return int(text)
            except OSError:
                pass
            time.sleep(0.1)
        return None

    def _read_process(self, proc):
        """Surface the sniffer's own stdout/stderr (startup banner, errors)."""
        if proc.stdout is None:
            return
        for line in proc.stdout:
            self.lines.put(("proc", proc, line))
        code = proc.wait()
        self.lines.put(("exit", proc, code))

    def _tail_log(self, path, stopping):
        pos = 0
        pending = ""
        while not stopping.is_set():
            try:
                size = os.path.getsize(path)
                if size < pos:  # the sniffer truncated the file on restart
                    pos = 0
                if size > pos:
                    with open(path, "r", errors="replace") as fh:
                        fh.seek(pos)
                        chunk = fh.read(MAX_READ_CHUNK)
                        pos = fh.tell()
                    pending += chunk
                    if "\n" in pending:
                        text, pending = pending.rsplit("\n", 1)
                        self.lines.put(("log", stopping, text + "\n"))
            except OSError:
                pass
            time.sleep(0.25)

    def _drain_queue(self):
        try:
            while True:
                kind, owner, payload = self.lines.get_nowait()

                # Anything from a previous capture is stale once a new one has
                # started; showing it would mix runs, and acting on its exit
                # code would stop the capture that is currently running.
                if kind == "log":
                    if owner is not self.stop_tail:
                        continue
                    self.packet_count += payload.count("Ethernet Header")
                    self.counter.set("Packets: %d" % self.packet_count)
                    self.write(payload)
                elif owner is not self.proc:
                    continue
                elif kind == "proc":
                    self.write(payload, "info")
                elif kind == "exit":
                    self.write("\n--- sniffer exited with code %s ---\n" % payload, "error")
                    self.stop()
        except queue.Empty:
            pass
        self.root.after(120, self._drain_queue)

    # ---------------------------------------------------------------- actions

    def clear_view(self):
        self.out.configure(state="normal")
        self.out.delete("1.0", "end")
        self.out.configure(state="disabled")

    def save_log_as(self):
        if not self.log_path or not os.path.exists(self.log_path):
            messagebox.showinfo("Nothing to save", "Run a capture first.")
            return
        target = filedialog.asksaveasfilename(
            title="Save capture log", defaultextension=".log",
            initialfile=os.path.basename(self.log_path),
        )
        if target:
            # The copy holds captured payloads too, so create it 0600 as well.
            with open(self.log_path, "rb") as src:
                fd = os.open(target, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "wb") as dst:
                    shutil.copyfileobj(src, dst)
            os.chmod(target, 0o600)
            self.status.set("Log copied to %s" % target)

    def open_log_folder(self):
        self._ensure_log_dir()
        subprocess.Popen(["xdg-open", LOG_DIR])

    def on_close(self):
        if self.proc is not None:
            if not messagebox.askokcancel("Quit", "A capture is running. Stop it and quit?"):
                return
            self.stop()
            # Unlike the Stop button, quitting waits: the terminator is a daemon
            # thread and would be killed before it could signal a root capture.
            if self.terminator is not None:
                self.terminator.join(timeout=10)
        self.root.destroy()


def main():
    root = tk.Tk()
    try:
        ttk.Style().theme_use("clam")
    except tk.TclError:
        pass
    SnifferApp(root)
    root.mainloop()


if __name__ == "__main__":
    sys.exit(main())
