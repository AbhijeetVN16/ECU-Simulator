# main.py
#
# Entry point for the Virtual ECU Simulator.
# Bootstraps centralized logging before starting the GUI so that every
# module's import-time logger initialisation writes to the same handlers.

import sys
import tkinter as tk

# ── Logging must be initialised before any other project import ──────────────
from logger import ECULogger as _ECULogger

_log = _ECULogger("main")


def _install_excepthook() -> None:
    """Redirect unhandled top-level exceptions to the ECU error log."""
    _orig = sys.excepthook

    def _hook(exc_type, exc_value, exc_tb):
        import traceback
        tb_str = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
        _log.error(
            f"[UNHANDLED EXCEPTION] {exc_type.__name__}: {exc_value}\n{tb_str}"
        )
        _orig(exc_type, exc_value, exc_tb)

    sys.excepthook = _hook


# ── Project imports (after logging is ready) ─────────────────────────────────
from gui import ECU_GUI


if __name__ == "__main__":
    _install_excepthook()
    _log.info("[SYSTEM] ECU Simulator starting up")

    root = tk.Tk()
    app  = ECU_GUI(root)

    try:
        _log.info("[SYSTEM] Entering Tk main loop")
        root.mainloop()
    except KeyboardInterrupt:
        _log.info("[SYSTEM] KeyboardInterrupt — shutting down")
    finally:
        _log.info("[SYSTEM] ECU Simulator exited")
