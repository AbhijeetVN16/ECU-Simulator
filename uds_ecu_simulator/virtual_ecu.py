# virtual_ecu.py

import time
import threading
import can

from config import INTERFACE, ECU_RX_ID, ECU_TX_ID, VULN_JSON_PATH
from uds_constants import SID_WRITE_MEMORY_BY_ADDRESS, NRC_RESPONSE_PENDING
from uds_helpers import hex2, uds_sid_name, nrc_name

from ecu_state import ECUState
from ecu_memory import VirtualMemory, VirtualNVM
from uds_core import UDSCore
from isotp_server import ISOTPServer
from vulnerability_config import VulnerabilityConfig
from vulnerability_engine import VulnerabilityEngine

class VirtualECU:
    def __init__(self, log_callback, raw_can_callback, oracle_callback):
        self.log = log_callback
        self.raw_log = raw_can_callback
        self.oracle = oracle_callback

        self.state = ECUState()
        self.mem = VirtualMemory(4096)
        self.nvm = VirtualNVM()

        self.uds = UDSCore(self.state, self.mem, self.nvm, self.log)
        self.tp = ISOTPServer(INTERFACE, ECU_RX_ID, ECU_TX_ID, self.log)

        self.running = True

        try:
            self.bus_sniffer = can.Bus(INTERFACE, bustype="socketcan")
        except:
            self.bus_sniffer = None

        self.sniffer_thread = threading.Thread(target=self._sniff_raw_can, daemon=True)

        self.cfg = VulnerabilityConfig(VULN_JSON_PATH, self.log, self.oracle)
        self.cfg.load()

        self.apply_cfg()

        self.vuln_engine = VulnerabilityEngine(self.cfg, self.state, self.log, self.oracle)

    def apply_cfg(self):
        self.state.p2_ms = int(self.cfg.uds_settings.get("p2_timeout_ms", 50))
        self.state.p2_star_ms = int(self.cfg.uds_settings.get("p2_star_timeout_ms", 2000))

    def start(self):
        self.log("[SYSTEM] ECU Simulator Started")
        self.oracle("[SYSTEM] Oracle Log started")
        self.sniffer_thread.start()

        while self.running:
            # Fault handling with recovery
            if self.state.faulted:
                if time.time() >= self.state.fault_until:
                    self.oracle(f"[{time.strftime('%H:%M:%S')}] ECU reboot after fault ({self.state.fault_reason})")

                    self.state.reset_volatile()
                    self.mem.reset()
                    self.nvm.store["boot_count"] += 1

                    self.log("[ECU] Reboot complete")
                else:
                    time.sleep(0.01)
                    continue

            self.tp.process()

            if self.tp.available():
                req = self.tp.recv()
                self._handle_request(req)

            time.sleep(0.002)

    def stop(self):
        self.running = False

    def _sniff_raw_can(self):
        while self.running and self.bus_sniffer:
            try:
                msg = self.bus_sniffer.recv(timeout=0.5)
                if msg:
                    self.raw_log(msg)
                    self.vuln_engine.on_raw_can_frame(msg)
            except:
                pass

    def _handle_request(self, req: bytes):
        if not req:
            return

        if time.time() < self.state.hang_until:
            return

        sid = req[0]
        self.log(f"[RX][UDS] {hex2(sid)} {uds_sid_name(sid)} | {req.hex().upper()}")

        action = self.vuln_engine.evaluate_uds(req)

        if action:
            if action.get("type") == "FORCED_RESPONSE":
                resp = action["response"]
                time.sleep(self.state.p2_ms / 1000.0)
                self.tp.send(resp)
                self._log_response(resp)
                return

            if action.get("type") == "FAULTED":
                self.log("[ECU] Fault triggered")
                return

            if action.get("type") == "HANG":
                self.log("[ECU] Hang triggered")
                return

            if action.get("type") == "BYPASS_WRITE_DID":
                if len(req) >= 3:
                    resp = bytes([0x6E, req[1], req[2]])
                    self.tp.send(resp)
                    self._log_response(resp)
                    return

            if action.get("type") == "ACCEPT_PROGRAMMING_SESSION":
                if len(req) >= 2 and req[0] == 0x10 and req[1] == 0x02:
                    self.state.session = ECUState.SESSION_PROGRAMMING
                    resp = bytes([0x50, 0x02, 0x00, 0x32, 0x01, 0xF4])
                    self.tp.send(resp)
                    self._log_response(resp)
                    return

        # Standard behavior
        if sid == SID_WRITE_MEMORY_BY_ADDRESS:
            self.tp.send(bytes([0x7F, sid, NRC_RESPONSE_PENDING]))
            time.sleep(0.35)

        resp = self.uds.handle(req)

        time.sleep(self.state.p2_ms / 1000.0)

        if resp:
            self.tp.send(resp)
            self._log_response(resp)

    def _log_response(self, resp: bytes):
        if resp[0] == 0x7F and len(resp) >= 3:
            self.log(f"[TX][UDS] 7F {hex2(resp[1])} {hex2(resp[2])} ({nrc_name(resp[2])}) | {resp.hex().upper()}")
        else:
            self.log(f"[TX][UDS] {resp.hex().upper()}")
