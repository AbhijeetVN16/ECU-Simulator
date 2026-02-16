
# ECU Simulator

A Python-based **UDS ECU Simulator** for Linux using **SocketCAN + ISO-TP**, featuring a graphical dashboard and JSON-driven vulnerability configuration.

This project simulates a diagnostic ECU that supports core UDS services, timing behavior, controlled fault injection, and transport-layer anomalies. It is suitable for learning, testing, and validating diagnostic tools or fuzzers in a controlled environment.

---

## Features

- **UDS Services Implemented:**
  - `0x10` Diagnostic Session Control
  - `0x11` ECU Reset
  - `0x22` Read Data By Identifier
  - `0x2E` Write Data By Identifier
  - `0x27` Security Access
  - `0x23` Read Memory By Address
  - `0x3D` Write Memory By Address
  - `0x3E` Tester Present
- **ISO-TP Communication:** Reliable transport over CAN using Python `isotp` and SocketCAN.
- **Graphical Dashboard (Tkinter):**
  - UDS decoded log
  - Raw CAN frame log
  - Oracle log (ground-truth event log)
  - Live ECU state display
- **Vulnerability Engine:** JSON-based configuration to enable/disable specific vulnerabilities.
- **Fault Injection:** Simulation of crashes, hangs, and anomalies.
- **Auto-Recovery:** Automatic ECU reboot 5 seconds after a simulated crash.

---

## Project Structure
```text
uds_ecu_simulator/
│
├── main.py            # Entry point (GUI)
├── gui.py             # Dashboard implementation
├── virtual_ecu.py     # Main ECU runtime and logic loop
├── isotp_server.py    # SocketCAN + ISO-TP transport abstraction
├── uds_core.py        # UDS service logic and responses
├── vuln_engine.py     # Vulnerability trigger evaluation
├── ecu_state.py       # Tracks session, security, and timing
├── storage.py         # Simulated RAM and NVM
├── config_loader.py   # JSON parser
├── helpers.py         # Utility functions
├── constants.py       # CAN IDs, SIDs, NRCs
│
├── vulnerabilities.json  # Vulnerability definitions
└── requirements.txt      # Dependencies
```

## File Overview
* **main.py**: Entry point. Starts the GUI application.
* **gui.py**: Implements the Tkinter dashboard, logs, ECU state view, and JSON loader.
* **virtual_ecu.py**: The central brain. Handles ISO-TP processing, UDS dispatch, crash recovery, and the raw CAN sniffer.
* **isotp_server.py**: Wrapper for SocketCAN and ISO-TP socket operations.
* **uds_core.py**: Contains the logic for processing standard UDS requests and generating responses.
* **vuln_engine.py**: Checks incoming requests against the vulnerabilities.json rules to trigger effects.
* **ecu_state.py**: Manages runtime state (sessions, security locked/unlocked, boot count).
* **storage.py**: Simulates memory for Read/Write operations.
* **config_loader.py**: Handles loading and parsing of the vulnerability configuration file.
* **helpers.py**: Helpers for formatting hex strings and decoding NRCs.
* **constants.py**: Central configuration for constants (interface name, IDs, timings).

## Requirements

**System**
* **Linux** (recommended: Ubuntu/Debian)
* **SocketCAN** support (kernel modules)

**Python Dependencies**
Install required packages using:

```bash
pip3 install -r requirements.txt
```

Note: Tkinter is usually pre-installed on Linux. If missing:
```bash
sudo apt-get install python3-tk
```
## Setup & Usage
**1. Setup Virtual CAN (vcan0)**

Before running the simulator, create a virtual CAN interface:
```bash
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0
```
**2. Run the Simulator**

From inside the project directory:
```bash
python3 main.py
```

**Crash Recovery Behavior**

When a CRASH effect is triggered:

* **1.Fault State**: The ECU enters a faulted state.

* **2.Unresponsive**: All incoming requests are ignored for 5 seconds.

* **3.Reboot**: The ECU automatically reboots.

   * Session resets to default (0x01).

   * Security locks.

   * RAM is cleared.

   * Boot counter increments.

* **4.Logging**: The crash and reboot events are recorded in the Oracle Log.

## Logs
The GUI provides three distinct logs for analysis:

**1. UDS Log**: High-level decoded UDS RX/TX messages (SIDs, DIDs, Responses).

**2. CAN Log**: Raw CAN frames captured directly from the interface.

**3. Oracle Log**: "Ground-truth" log confirming when a vulnerability was successfully triggered.

## Notes
* Designed for local testing using vcan0.

* To use real hardware, change the interface name in constants.py.

* The architecture is modular, allowing for easy addition of new services or vulnerability types.

## License
Intended for academic and research use.

