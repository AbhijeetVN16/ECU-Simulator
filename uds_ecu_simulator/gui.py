# gui.py

import time
import os
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog
import can

from virtual_ecu import VirtualECU
from ecu_state import ECUState
from vulnerability_engine import VulnerabilityEngine

class ECU_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("UDS ECU Simulator")
        self.root.geometry("1500x780")

        self._build_style()
        self._build_layout()

        self.ecu = VirtualECU(self.log_uds, self.log_raw_can, self.log_oracle)

        self.thread = threading.Thread(target=self.ecu.start, daemon=True)
        self.thread.start()

        self.root.after(200, self._refresh_status)

    def _build_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Title.TLabel", font=("Consolas", 14, "bold"))
        style.configure("Stat.TLabel", font=("Consolas", 11, "bold"))

    def _build_layout(self):
        top = ttk.Frame(self.root)
        top.pack(fill="x", padx=10, pady=8)

        ttk.Label(top, text="UDS ECU Simulator", style="Title.TLabel").pack(side="left")

        ctrl = ttk.Frame(top)
        ctrl.pack(side="right")

        ttk.Button(ctrl, text="Load JSON", command=self._load_vulnerability_file).pack(side="left", padx=8)

        self.var_persistent = tk.BooleanVar(value=False)
        ttk.Checkbutton(ctrl, text="Persistent Lockout", variable=self.var_persistent,
                        command=self._toggle_lockout).pack(side="left", padx=8)

        ttk.Button(ctrl, text="Clear Logs", command=self._clear_logs).pack(side="left", padx=8)
        ttk.Button(ctrl, text="Exit", command=self._exit).pack(side="left")

        stat = ttk.LabelFrame(self.root, text="ECU State")
        stat.pack(fill="x", padx=10, pady=6)

        self.lbl_session = ttk.Label(stat, text="Session: DEFAULT", style="Stat.TLabel")
        self.lbl_session.pack(side="left", padx=10)

        self.lbl_security = ttk.Label(stat, text="Security: LOCKED", style="Stat.TLabel")
        self.lbl_security.pack(side="left", padx=10)

        self.lbl_attempts = ttk.Label(stat, text="Attempts: 0/3", style="Stat.TLabel")
        self.lbl_attempts.pack(side="left", padx=10)

        self.lbl_boot = ttk.Label(stat, text="Boot: 0", style="Stat.TLabel")
        self.lbl_boot.pack(side="left", padx=10)

        self.lbl_fault = ttk.Label(stat, text="Fault: NO", style="Stat.TLabel")
        self.lbl_fault.pack(side="left", padx=10)

        main = ttk.Frame(self.root)
        main.pack(fill="both", expand=True, padx=10, pady=8)

        left = ttk.Frame(main)
        left.pack(side="left", fill="both", expand=True, padx=(0, 6))

        mid = ttk.Frame(main)
        mid.pack(side="left", fill="both", expand=True, padx=(6, 6))

        right = ttk.Frame(main)
        right.pack(side="right", fill="both", expand=True, padx=(6, 0))

        uds_frame = ttk.LabelFrame(left, text="UDS Log")
        uds_frame.pack(fill="both", expand=True)

        self.uds_console = scrolledtext.ScrolledText(
            uds_frame, bg="black", fg="#00FF00", insertbackground="white",
            font=("Consolas", 10)
        )
        self.uds_console.pack(fill="both", expand=True)

        raw_frame = ttk.LabelFrame(mid, text="CAN Log")
        raw_frame.pack(fill="both", expand=True)

        self.raw_console = scrolledtext.ScrolledText(
            raw_frame, bg="black", fg="#00FF00", insertbackground="white",
            font=("Consolas", 10)
        )
        self.raw_console.pack(fill="both", expand=True)

        oracle_frame = ttk.LabelFrame(right, text="Oracle Log")
        oracle_frame.pack(fill="both", expand=True)

        self.oracle_console = scrolledtext.ScrolledText(
            oracle_frame, bg="black", fg="#FFD700", insertbackground="white",
            font=("Consolas", 10)
        )
        self.oracle_console.pack(fill="both", expand=True)

    def _load_vulnerability_file(self):
        path = filedialog.askopenfilename(
            title="Select JSON",
            filetypes=(("JSON files", "*.json"), ("all files", "*.*"))
        )

        if not path:
            return

        self.log_uds(f"[SYSTEM] Selected JSON: {os.path.basename(path)}")

        self.ecu.cfg.path = path

        if self.ecu.cfg.load():
            self.ecu.apply_cfg()
            self.ecu.vuln_engine = VulnerabilityEngine(self.ecu.cfg, self.ecu.state, self.ecu.log, self.ecu.oracle)
            self.log_uds(f"[SYSTEM] Reloaded {len(self.ecu.cfg.vulnerabilities)} vulnerabilities")
        else:
            self.log_uds("[SYSTEM][ERR] Failed to load JSON")

    def _toggle_lockout(self):
        self.ecu.state.persistent_lockout = self.var_persistent.get()

    def log_uds(self, msg):
        self.uds_console.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {msg}\n")
        self.uds_console.see(tk.END)

    def log_raw_can(self, msg: can.Message):
        self.raw_console.insert(
            tk.END,
            f"[{time.strftime('%H:%M:%S')}] ID={msg.arbitration_id:03X} DLC={msg.dlc} DATA={msg.data.hex().upper()}\n"
        )
        self.raw_console.see(tk.END)

    def log_oracle(self, msg):
        self.oracle_console.insert(tk.END, f"{msg}\n")
        self.oracle_console.see(tk.END)

    def _refresh_status(self):
        st = self.ecu.state

        if st.session == 0x01:
            sess = "DEFAULT"
        elif st.session == 0x02:
            sess = "PROGRAMMING"
        else:
            sess = "EXTENDED"

        self.lbl_session.config(text=f"Session: {sess}")
        self.lbl_security.config(text=f"Security: {'LOCKED' if st.security_level == 0 else 'UNLOCKED'}")

        attempts = self.ecu.nvm.store["persistent_auth_failures"] if st.persistent_lockout else st.auth_failures_ram
        self.lbl_attempts.config(text=f"Attempts: {attempts}/{st.max_attempts}")

        self.lbl_boot.config(text=f"Boot: {self.ecu.nvm.store['boot_count']}")

        if st.faulted:
            self.lbl_fault.config(text=f"Fault: YES ({st.fault_reason})")
        else:
            self.lbl_fault.config(text="Fault: NO")

        self.root.after(200, self._refresh_status)

    def _clear_logs(self):
        self.uds_console.delete(1.0, tk.END)
        self.raw_console.delete(1.0, tk.END)
        self.oracle_console.delete(1.0, tk.END)

    def _exit(self):
        self.ecu.stop()
        self.root.destroy()
