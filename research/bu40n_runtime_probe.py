#!/usr/bin/env python3
"""Probe whether OEM BU40N WRITE BUFFER mode 6 changes a flash/XIP code cave.

Read-only by default. --execute sends one 16-byte partial firmware-stage write;
the command does not complete the 2 MiB image threshold. This tests only the
stock 0x3B/6/0 path, not every MediaTek vendor command or RAM alias.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

OEM_SHA256 = "221ad35b7edd402353e125841893ce651064e8fc6b90368fe84ff19a85a506f4"
CAVE = 0x153968
SPEED_SITE = 0x1BB26
MARKER = b"RAM-POC-100-0002"


def command(argv: list[str]) -> str:
    result = subprocess.run(argv, capture_output=True, text=True, check=False)
    output = result.stdout + result.stderr
    if result.returncode != 0 or "SCSI Status: Good" not in output:
        raise RuntimeError(f"SCSI command failed ({result.returncode}): {output.strip()}")
    return output


def cdb(opcode: int, mode: int, offset: int, size: int, write: bool) -> list[str]:
    raw = bytes(
        [opcode, mode, 0x00]
        + list(offset.to_bytes(3, "big"))
        + list(size.to_bytes(3, "big"))
        + [0x00]
        + ([0x00, 0x00] if write else [])
    )
    return [f"{byte:02x}" for byte in raw]


def read_buffer(device: str, mode: int, offset: int, size: int, directory: Path) -> bytes:
    path = directory / f"read_m{mode}_{offset:06x}.bin"
    command(
        ["sg_raw", "-C", "1", "-R", "-r", str(size), "-o", str(path),
         device, *cdb(0x3C, mode, offset, size, False)]
    )
    data = path.read_bytes()
    if len(data) != size:
        raise RuntimeError(f"short READ BUFFER at {offset:#x}: {len(data)} bytes")
    return data


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("device", help="SCSI generic device, e.g. /dev/sg0")
    parser.add_argument("oem_image", type=Path, help="exact BU40N OEM 1.00 image")
    parser.add_argument("--execute", action="store_true", help="send one 16-byte WRITE BUFFER")
    parser.add_argument("--report", type=Path, help="write result JSON")
    args = parser.parse_args()

    image = args.oem_image.read_bytes()
    digest = hashlib.sha256(image).hexdigest()
    if len(image) != 0x200000 or digest != OEM_SHA256:
        parser.error("image is not the audited BU40N OEM 1.00 fixture")
    if len(MARKER) != 16 or image[CAVE:CAVE + 16] != bytes([0xFF]) * 16:
        parser.error("audited executable cave does not match expected erased bytes")

    inquiry = subprocess.run(
        ["sg_inq", args.device], capture_output=True, text=True, check=True
    ).stdout
    if "BD-RE BU40N" not in inquiry or "Product revision level: 1.00" not in inquiry:
        parser.error("target is not a BU40N reporting firmware 1.00")

    with tempfile.TemporaryDirectory(prefix="bu40n-runtime-probe-") as temp:
        directory = Path(temp)
        cave_before = read_buffer(args.device, 6, CAVE, 16, directory)
        stage_before = read_buffer(args.device, 2, CAVE, 16, directory)
        speed_before = read_buffer(args.device, 6, SPEED_SITE, 4, directory)
        if cave_before != image[CAVE:CAVE + 16] or speed_before != image[SPEED_SITE:SPEED_SITE + 4]:
            parser.error("live code bytes differ from OEM image; restore/verify OEM first")

        result = {
            "device": args.device,
            "image_sha256": digest,
            "cave_offset": f"0x{CAVE:06x}",
            "marker_hex": MARKER.hex(),
            "cave_before_hex": cave_before.hex(),
            "stage_before_hex": stage_before.hex(),
            "speed_site_before_hex": speed_before.hex(),
            "write_sent": args.execute,
        }
        if args.execute:
            marker_path = directory / "marker.bin"
            marker_path.write_bytes(MARKER)
            command(
                ["sg_raw", "-C", "1", "-s", "16", "-i", str(marker_path),
                 args.device, *cdb(0x3B, 6, CAVE, 16, True)]
            )
            cave_after = read_buffer(args.device, 6, CAVE, 16, directory)
            stage_after = read_buffer(args.device, 2, CAVE, 16, directory)
            speed_after = read_buffer(args.device, 6, SPEED_SITE, 4, directory)
            result.update({
                "cave_after_hex": cave_after.hex(),
                "stage_after_hex": stage_after.hex(),
                "speed_site_after_hex": speed_after.hex(),
                "marker_visible_at_xip_address": cave_after == MARKER,
                "marker_visible_in_staging_aperture": stage_after == MARKER,
                "xip_cave_unchanged": cave_after == cave_before,
                "speed_site_unchanged": speed_after == speed_before,
            })
        print(json.dumps(result, indent=2))
        if args.report:
            args.report.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
