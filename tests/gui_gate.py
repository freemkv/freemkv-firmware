#!/usr/bin/env python3
"""qa's GUI gate driver: run a debug build of freemkv-flash-gui with its gate on, once.

    python3 tests/gui_gate.py APP OUT_DIR

APP is the debug binary built with `--features native` (`freemkv-flash-gui.exe` on
Windows). On Linux run this under `dbus-run-session -- xvfb-run`. The app starts on a
synthetic drive (no hardware is touched), walks every tab, opens and cancels the flash
confirmation twice, checks its own widgets and captures (crates/freemkv-flash-gui/src/
gui_gate.rs and each shell's gate.rs), writes OUT_DIR/gate.txt and a PNG per tab and sheet,
and exits non-zero on a failed check. This exits 1 if the app failed, crashed, timed out or
wrote no passing report.
"""

import os
import subprocess
import sys

# A Windows console writes the legacy code page, which cannot print the report's dashes.
for _s in (sys.stdout, sys.stderr):
    _s.reconfigure(encoding="utf-8", errors="replace")

TIMEOUT_S = 120


def main(app, out):
    app, out = os.path.abspath(app), os.path.abspath(out)
    os.makedirs(out, exist_ok=True)
    for name in os.listdir(out):
        if name in ("gate.txt", "panic.txt") or name.endswith(".png"):
            os.remove(os.path.join(out, name))
    env = dict(os.environ, FREEMKV_FLASH_GATE=out,
               FREEMKV_GUI_GATE_READ_NOTICE="ui.mtk_read_limits")
    # Exercise the real read-limitation copy and its layout using synthetic
    # profile evidence; the native gate never probes or writes a real drive.
    if sys.platform.startswith("linux"):
        # Xvfb has no GPU: GTK's software renderer, and no accessibility bus to wait on.
        env.setdefault("GSK_RENDERER", "cairo")
        env.setdefault("NO_AT_BRIDGE", "1")
    try:
        rc = subprocess.run([app], env=env, timeout=TIMEOUT_S).returncode
    except subprocess.TimeoutExpired:
        rc = f"timeout after {TIMEOUT_S} s"
    panic = os.path.join(out, "panic.txt")
    if os.path.exists(panic):
        with open(panic, encoding="utf-8", errors="replace") as f:
            print("the app panicked:\n" + f.read(), flush=True)
    report = os.path.join(out, "gate.txt")
    text = ""
    if os.path.exists(report):
        with open(report, encoding="utf-8") as f:
            text = f.read()
        print(text, end="")
    else:
        print("no gate report: the app crashed or never reached the gate")
    if rc != 0 or "\nGATE OK:" not in "\n" + text:
        print(f"::error title=GUI gate failed::exit {rc}")
        return 1
    print("GUI gate passed")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1], sys.argv[2]))
