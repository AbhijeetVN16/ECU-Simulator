# isotp_server.py

import can
import isotp

class ISOTPServer:
    def __init__(self, interface, rx_id, tx_id, log):
        self.log = log
        self.stack = None

        try:
            self.bus = can.Bus(interface, bustype="socketcan")
            self.stack = isotp.CanStack(
                bus=self.bus,
                address=isotp.Address(isotp.AddressingMode.Normal_11bits, rxid=rx_id, txid=tx_id),
                params={"stmin": 5, "blocksize": 8, "wftmax": 2}
            )
        except Exception as e:
            self.log(f"[SYSTEM][ERR] CAN/ISO-TP init failed: {str(e)}")
            self.stack = None

    def process(self):
        if self.stack:
            self.stack.process()

    def available(self):
        return self.stack.available() if self.stack else False

    def recv(self):
        return self.stack.recv() if self.stack else None

    def send(self, payload: bytes):
        if self.stack:
            self.stack.send(payload)
