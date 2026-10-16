#!/usr/bin/env python3
"""Emit the offline plan for the volatile gate-only RAM PoC.

This file deliberately emits no device commands.  It records the dependency
order for the first probe; the CDB hook is deferred until dispatcher entry is
observed.  Payload bytes must be produced by the repository's Thumb assembler.
"""

from __future__ import annotations

import json
import sys

GATE = 0x02000C6C
CALLBACK_CELL = 0x02000D30
ALTERNATE_CELL = 0x02000D2C


def main() -> None:
    out = {
        "kind": "volatile-gate-only-poc",
        "writes": [
            {"address": f"0x{GATE:08x}", "value": "0x00", "purpose": "disarm"},
            {"address": f"0x{CALLBACK_CELL:08x}", "value": "0x00000000", "purpose": "clear callback"},
            {"address": f"0x{ALTERNATE_CELL:08x}", "value": "read-and-clear", "purpose": "avoid zero-branch callback"},
            {"address": "staged-callback", "value": "thumb bytes", "purpose": "clear cells, set sentinel, return"},
            {"address": f"0x{CALLBACK_CELL:08x}", "value": "callback_entry | 1", "purpose": "install Thumb pointer"},
            {"address": f"0x{GATE:08x}", "value": "0x01", "purpose": "arm last"},
        ],
        "observations": [
            f"read 0x{GATE:08x}: zero after arming indicates dispatcher consumer entry",
            f"read 0x{CALLBACK_CELL:08x}: zero indicates callback cleared its pointer",
            "read separate sentinel: changed value is required to prove callback execution",
        ],
        "deferred": ["new CDB handler", "live device transport", "persistent firmware change"],
    }
    json.dump(out, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
