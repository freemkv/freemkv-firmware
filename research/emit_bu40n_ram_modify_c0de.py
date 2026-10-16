#!/usr/bin/env python3
"""Emit complete runtime Poke/Call frames for the offline modify code band."""
from __future__ import annotations

import json
import pathlib
import sys

LOAD_ADDRESS = 0x02000E80
ADAPTER_ADDRESS = 0x02001380
CALLBACK_CELL = 0x02000D30
ADAPTER = bytes.fromhex(
    "10 b5 09 4c 20 78 3c 28 0c d1 60 78 0e 28 09 d1 "
    "a0 78 de 28 06 d1 e0 78 b9 28 03 d1 03 4e b0 47 "
    "00 20 00 e0 01 20 10 bd 38 0d 00 02 81 0e 00 02"
)


def frame(verb: int, address: int, value: int = 0) -> bytes:
    # C0 DE runtime frame: full address is CDB[5:9], big endian.
    return bytes.fromhex("3c 0e de b9") + bytes([verb]) + address.to_bytes(4, "big") + bytes([value])


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit(f"usage: {sys.argv[0]} PAYLOAD MANIFEST COMMANDS")
    payload_path, manifest_path, commands_path = map(pathlib.Path, sys.argv[1:])
    payload = payload_path.read_bytes()
    pokes = []
    for offset, value in enumerate(payload):
        address = LOAD_ADDRESS + offset
        pokes.append({"address": f"0x{address:08x}", "value": f"0x{value:02x}", "cdb_hex": frame(0x0D, address, value).hex()})
    call = frame(0x0C, LOAD_ADDRESS).hex()
    adapter_pokes = []
    for offset, value in enumerate(ADAPTER):
        address = ADAPTER_ADDRESS + offset
        adapter_pokes.append({"address": f"0x{address:08x}", "value": f"0x{value:02x}", "cdb_hex": frame(0x0D, address, value).hex()})
    callback_bytes = (ADAPTER_ADDRESS | 1).to_bytes(4, "little")
    callback_pokes = []
    for offset, value in enumerate(callback_bytes):
        address = CALLBACK_CELL + offset
        callback_pokes.append({"address": f"0x{address:08x}", "value": f"0x{value:02x}", "cdb_hex": frame(0x0D, address, value).hex()})
    manifest = {
        "payload": str(payload_path),
        "load_address": f"0x{LOAD_ADDRESS:08x}",
        "length": len(payload),
        "end_address_exclusive": f"0x{LOAD_ADDRESS + len(payload):08x}",
        "call_cdb_hex": call,
        "pokes": pokes,
        "adapter_address": f"0x{ADAPTER_ADDRESS:08x}",
        "adapter_length": len(ADAPTER),
        "adapter_pokes": adapter_pokes,
        "callback_cell": f"0x{CALLBACK_CELL:08x}",
        "callback_pointer": f"0x{ADAPTER_ADDRESS | 1:08x}",
        "callback_pokes": callback_pokes,
        "data_in_length": 64,
        "claim": "OEM drive plus runtime-loaded modify code band; no flash write",
        "code_band": "handler plus generated stubs; original static detour sites are not changed by this file",
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    with commands_path.open("w") as out:
        out.write("#!/usr/bin/env bash\nset -euo pipefail\ndevice=${1:?usage: $0 /dev/sgX}\n")
        for poke in pokes:
            out.write(f"sg_raw -C 1 -R -r 64 \"$device\" {' '.join(bytes.fromhex(poke['cdb_hex']).hex()[i:i+2] for i in range(0, 20, 2))}\n")
        for poke in adapter_pokes + callback_pokes:
            out.write(f"sg_raw -C 1 -R -r 64 \"$device\" {' '.join(bytes.fromhex(poke['cdb_hex']).hex()[i:i+2] for i in range(0, 20, 2))}\n")
        out.write(f"sg_raw -C 1 -R -r 64 \"$device\" {' '.join(call[i:i+2] for i in range(0, 20, 2))}\n")
    commands_path.chmod(0o755)


if __name__ == "__main__":
    main()
