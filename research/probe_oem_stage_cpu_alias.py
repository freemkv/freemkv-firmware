#!/usr/bin/env python3
"""Probe whether OEM WRITE BUFFER staging bytes alias CPU-visible RAM.

Run only while the temporary modified handler is installed: C0 DE DumpAll is
used strictly as a readback instrument. The WRITE BUFFER operation itself is
the stock OEM command path and this probe does not program flash.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import tempfile

MARKER = bytes.fromhex("52414d2d53544147452d414c4941532d31")
STAGE_OFFSET = 0x153968


def run(argv: list[str], output: pathlib.Path | None = None) -> str:
    result = subprocess.run(argv, capture_output=True, text=True, check=False)
    text = result.stdout + result.stderr
    if result.returncode or "SCSI Status: Good" not in text:
        raise RuntimeError(text.strip())
    return text


def write_buffer_cdb(offset: int, length: int) -> list[str]:
    raw = bytes([0x3B, 0x06, 0x00]) + offset.to_bytes(3, "big") + length.to_bytes(3, "big") + b"\x00"
    return [f"{b:02x}" for b in raw]


def dump_cdb(address: int) -> list[str]:
    raw = bytes.fromhex("3c 0e de b9 09") + address.to_bytes(4, "big") + b"\x00"
    return [f"{b:02x}" for b in raw]


def dump(device: str, address: int, root: pathlib.Path) -> bytes:
    out = root / f"dump_{address:08x}.bin"
    run(["sg_raw", "-C", "1", "-R", "-r", "64", "-o", str(out), device, *dump_cdb(address)])
    return out.read_bytes()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("device")
    parser.add_argument("--report", type=pathlib.Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="bu40n-stage-alias-") as temp:
        root = pathlib.Path(temp)
        marker = root / "marker.bin"
        marker.write_bytes(MARKER)
        base = int.from_bytes(dump(args.device, 0x02000C78, root)[:4], "little")
        runtime_offset = int.from_bytes(dump(args.device, 0x02000C7C, root)[:4], "little")
        destination = base + STAGE_OFFSET
        run(["sg_raw", "-C", "1", "-s", str(len(MARKER)), "-i", str(marker), args.device,
             *write_buffer_cdb(STAGE_OFFSET, len(MARKER))])
        hits = []
        data = dump(args.device, destination, root)
        at = data.find(MARKER)
        if at >= 0:
            hits.append(f"0x{destination + at:08x}")
    report = {"marker_hex": MARKER.hex(), "base": f"0x{base:08x}",
              "runtime_offset": f"0x{runtime_offset:08x}", "destination": f"0x{destination:08x}",
              "hits": hits, "cpu_alias_found": bool(hits),
              "claim": "A hit proves stock WRITE BUFFER staging aliases CPU-visible RAM at the resolved destination."}
    print(json.dumps(report, indent=2))
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
