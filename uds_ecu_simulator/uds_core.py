# uds_core.py

import time
import struct
import random

from ecu_state import ECUState
from uds_constants import *
from uds_helpers import nrc_name

class UDSCore:
    def __init__(self, state: ECUState, mem, nvm, log):
        self.state = state
        self.mem = mem
        self.nvm = nvm
        self.log = log

        self.dids = {
            0xF190: ("VIN", lambda: self.nvm.store["vin"], self._set_vin),
            0xF18C: ("SerialNumber", lambda: self.nvm.store["serial"], self._set_serial),
            0xF187: ("BootCounter", lambda: struct.pack(">I", self.nvm.store["boot_count"]), None),
            0x0101: ("MagicBypassDID", lambda: b"\x00", self._set_magic_did),
        }

    def _set_magic_did(self, payload: bytes):
        self.mem.write(0x100, payload[:8])

    def negative(self, req_sid, nrc):
        return bytes([0x7F, req_sid, nrc])

    def handle(self, payload: bytes):
        if not payload:
            return None

        sid = payload[0]

        handler = {
            SID_DIAGNOSTIC_SESSION_CONTROL: self.srv_10_session_control,
            SID_ECU_RESET: self.srv_11_ecu_reset,
            SID_READ_DATA_BY_IDENTIFIER: self.srv_22_read_did,
            SID_WRITE_DATA_BY_IDENTIFIER: self.srv_2e_write_did,
            SID_SECURITY_ACCESS: self.srv_27_security_access,
            SID_READ_MEMORY_BY_ADDRESS: self.srv_23_read_memory,
            SID_WRITE_MEMORY_BY_ADDRESS: self.srv_3d_write_memory,
            SID_TESTER_PRESENT: self.srv_3e_tester_present,
        }.get(sid)

        if not handler:
            return self.negative(sid, NRC_SERVICE_NOT_SUPPORTED)

        try:
            return handler(payload)
        except IndexError:
            return self.negative(sid, NRC_INCORRECT_MESSAGE_LENGTH)
        except Exception as e:
            self.log(f"[UDS][ERR] {str(e)}")
            return self.negative(sid, NRC_GENERAL_REJECT)

    def srv_10_session_control(self, data: bytes):
        if len(data) < 2:
            return self.negative(SID_DIAGNOSTIC_SESSION_CONTROL, NRC_INCORRECT_MESSAGE_LENGTH)

        sub = data[1]

        if sub == 0x01:
            self.state.session = ECUState.SESSION_DEFAULT
            self.state.security_level = 0
            return bytes([0x50, 0x01, 0x00, 0x32, 0x01, 0xF4])

        if sub == 0x03:
            self.state.session = ECUState.SESSION_EXTENDED
            return bytes([0x50, 0x03, 0x00, 0x32, 0x01, 0xF4])

        if sub == 0x02:
            return self.negative(SID_DIAGNOSTIC_SESSION_CONTROL, NRC_SUBFUNCTION_NOT_SUPPORTED)

        return self.negative(SID_DIAGNOSTIC_SESSION_CONTROL, NRC_SUBFUNCTION_NOT_SUPPORTED)

    def srv_11_ecu_reset(self, data: bytes):
        if len(data) < 2:
            return self.negative(SID_ECU_RESET, NRC_INCORRECT_MESSAGE_LENGTH)

        reset_type = data[1]
        if reset_type != 0x01:
            return self.negative(SID_ECU_RESET, NRC_SUBFUNCTION_NOT_SUPPORTED)

        self.state.reset_volatile()
        self.mem.reset()
        self.nvm.store["boot_count"] += 1

        return bytes([0x51, 0x01])

    def srv_3e_tester_present(self, data: bytes):
        if len(data) < 2:
            return self.negative(SID_TESTER_PRESENT, NRC_INCORRECT_MESSAGE_LENGTH)

        sub = data[1]

        if sub == 0x80:
            return None

        return bytes([0x7E, sub])

    def srv_22_read_did(self, data: bytes):
        if len(data) < 3:
            return self.negative(SID_READ_DATA_BY_IDENTIFIER, NRC_INCORRECT_MESSAGE_LENGTH)

        did = (data[1] << 8) | data[2]

        if did not in self.dids:
            return self.negative(SID_READ_DATA_BY_IDENTIFIER, NRC_REQUEST_OUT_OF_RANGE)

        name, getter, _setter = self.dids[did]
        value = getter()
        return bytes([0x62, data[1], data[2]]) + value

    def srv_2e_write_did(self, data: bytes):
        if len(data) < 4:
            return self.negative(SID_WRITE_DATA_BY_IDENTIFIER, NRC_INCORRECT_MESSAGE_LENGTH)

        if self.state.session != ECUState.SESSION_EXTENDED:
            return self.negative(SID_WRITE_DATA_BY_IDENTIFIER, NRC_SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION)

        if self.state.security_level < 1:
            return self.negative(SID_WRITE_DATA_BY_IDENTIFIER, NRC_SECURITY_ACCESS_DENIED)

        did = (data[1] << 8) | data[2]
        payload = data[3:]

        if did not in self.dids:
            return self.negative(SID_WRITE_DATA_BY_IDENTIFIER, NRC_REQUEST_OUT_OF_RANGE)

        name, _getter, setter = self.dids[did]
        if not setter:
            return self.negative(SID_WRITE_DATA_BY_IDENTIFIER, NRC_CONDITIONS_NOT_CORRECT)

        setter(payload)
        return bytes([0x6E, data[1], data[2]])

    def _set_vin(self, payload: bytes):
        self.nvm.store["vin"] = payload[:17]

    def _set_serial(self, payload: bytes):
        self.nvm.store["serial"] = payload[:16]

    def srv_27_security_access(self, data: bytes):
        if len(data) < 2:
            return self.negative(SID_SECURITY_ACCESS, NRC_INCORRECT_MESSAGE_LENGTH)

        sub = data[1]

        now = time.time()
        if now < self.state.locked_until:
            return self.negative(SID_SECURITY_ACCESS, NRC_REQUIRED_TIME_DELAY_NOT_EXPIRED)

        attempts = self.nvm.store["persistent_auth_failures"] if self.state.persistent_lockout else self.state.auth_failures_ram
        if attempts >= self.state.max_attempts:
            return self.negative(SID_SECURITY_ACCESS, NRC_EXCEEDED_NUMBER_OF_ATTEMPTS)

        if sub in (0x01, 0x05):
            level = 1 if sub == 0x01 else 3
            seed = random.randint(1, 65535)
            self.state.last_seed_level = level
            self.state.last_seed_value = seed
            return bytes([0x67, sub]) + struct.pack(">H", seed)

        if sub in (0x02, 0x06):
            if len(data) < 4:
                return self.negative(SID_SECURITY_ACCESS, NRC_INCORRECT_MESSAGE_LENGTH)

            level = 1 if sub == 0x02 else 3
            recv_key = struct.unpack(">H", data[2:4])[0]

            if self.state.last_seed_level != level:
                return self.negative(SID_SECURITY_ACCESS, NRC_CONDITIONS_NOT_CORRECT)

            seed = self.state.last_seed_value
            expected = (seed ^ 0x4567) if level == 1 else ((seed * 7) + 0x1234) & 0xFFFF

            if recv_key == expected:
                self.state.security_level = level
                if self.state.persistent_lockout:
                    self.nvm.store["persistent_auth_failures"] = 0
                else:
                    self.state.auth_failures_ram = 0
                return bytes([0x67, sub])

            if self.state.persistent_lockout:
                self.nvm.store["persistent_auth_failures"] += 1
            else:
                self.state.auth_failures_ram += 1

            self.state.locked_until = time.time() + self.state.required_delay_s
            return self.negative(SID_SECURITY_ACCESS, NRC_INVALID_KEY)

        return self.negative(SID_SECURITY_ACCESS, NRC_SUBFUNCTION_NOT_SUPPORTED)

    def srv_23_read_memory(self, data: bytes):
        if len(data) < 5:
            return self.negative(SID_READ_MEMORY_BY_ADDRESS, NRC_INCORRECT_MESSAGE_LENGTH)

        addr = (data[2] << 8) | data[3]
        size = data[4]

        try:
            mem = self.mem.read(addr, size)
            return bytes([0x63, data[1]]) + mem
        except IndexError:
            return self.negative(SID_READ_MEMORY_BY_ADDRESS, NRC_REQUEST_OUT_OF_RANGE)

    def srv_3d_write_memory(self, data: bytes):
        if len(data) < 5:
            return self.negative(SID_WRITE_MEMORY_BY_ADDRESS, NRC_INCORRECT_MESSAGE_LENGTH)

        if self.state.session != ECUState.SESSION_EXTENDED:
            return self.negative(SID_WRITE_MEMORY_BY_ADDRESS, NRC_SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION)

        if self.state.security_level < 1:
            return self.negative(SID_WRITE_MEMORY_BY_ADDRESS, NRC_SECURITY_ACCESS_DENIED)

        addr = (data[2] << 8) | data[3]
        size = data[4]
        payload = data[5:]

        if len(payload) < size:
            return self.negative(SID_WRITE_MEMORY_BY_ADDRESS, NRC_INCORRECT_MESSAGE_LENGTH)

        try:
            self.mem.write(addr, payload[:size])
            return bytes([0x7D, data[1], data[2], data[3]])
        except IndexError:
            return self.negative(SID_WRITE_MEMORY_BY_ADDRESS, NRC_REQUEST_OUT_OF_RANGE)
