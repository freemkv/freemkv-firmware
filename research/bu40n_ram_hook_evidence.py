#!/usr/bin/env python3
"""Collect read-only evidence for a BU40N OEM RAM-hook experiment.

This does not install a hook. Each phase independently checks the live
executable image; a positive result requires an external, verified RAM-only
setup and a real cold power cycle between the later phases.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

OEM_SHA256 = "221ad35b7edd402353e125841893ce651064e8fc6b90368fe84ff19a85a506f4"
CODE_START = 0x10000
CODE_END = 0x153E55  # exclusive; includes the last byte at 0x153e54
CHUNK = 0x4000
IDENTITY_CDB = bytes.fromhex("3c 0e c0 de 01 00 00 00 40 00")
PRIVATE_CDB = bytes.fromhex("de 00 00 00 00 00 00 00 00 00")


def runtime_cdb(verb: int, address: int, value: int = 0) -> bytes:
    """Build one debug runtime frame with a complete 32-bit address.

    The address occupies CDB bytes 5..8 in big-endian order. Keeping this
    builder here prevents a two-byte formatting mistake from redirecting a
    probe to a low peripheral address.
    """
    if not 0 <= verb <= 0xFF:
        raise ValueError("verb must fit one byte")
    if not 0 <= address <= 0xFFFF_FFFF:
        raise ValueError("address must fit 32 bits")
    if not 0 <= value <= 0xFF:
        raise ValueError("value must fit one byte")
    return bytes.fromhex("3c 0e de b9") + bytes([verb]) + address.to_bytes(4, "big") + bytes([value])


def runtime_memread_cdb(address: int) -> bytes:
    """Build the debug 64-byte memory-read frame for ``address``."""
    return runtime_cdb(0x09, address)


def runtime_poke_cdb(address: int, value: int) -> bytes:
    """Build the debug one-byte write frame for ``address``."""
    return runtime_cdb(0x0D, address, value)


def runtime_call_cdb(address: int, argument: int = 0) -> bytes:
    """Build the debug Thumb-call frame for ``address`` and ``r0`` argument."""
    return runtime_cdb(0x0C, address, argument)


def run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, check=False)


def read_cdb(device: str, cdb: bytes, length: int, path: Path) -> dict:
    argv = ["sg_raw", "-C", "1"]
    if length:
        argv += ["-R", "-r", str(length), "-o", str(path)]
    result = run([*argv, device, *(f"{byte:02x}" for byte in cdb)])
    output = result.stdout + result.stderr
    data = path.read_bytes() if path.exists() else b""
    return {
        "cdb_hex": cdb.hex(),
        "exit_code": result.returncode,
        "status_good": result.returncode == 0 and "SCSI Status: Good" in output,
        "sense": output.strip(),
        "data_hex": data.hex(),
    }


def image_read_cdb(offset: int, length: int) -> bytes:
    return bytes([0x3C, 0x06, 0x00]) + offset.to_bytes(3, "big") + length.to_bytes(3, "big") + b"\x00"


def dump_code(device: str, directory: Path) -> bytes:
    chunks = []
    for offset in range(CODE_START, CODE_END, CHUNK):
        length = min(CHUNK, CODE_END - offset)
        transfer_length = length + length % 2
        observation = read_cdb(device, image_read_cdb(offset, transfer_length), transfer_length, directory / f"code_{offset:06x}.bin")
        data = bytes.fromhex(observation["data_hex"])
        if not observation["status_good"] or len(data) != transfer_length:
            raise RuntimeError(f"code read at {offset:#x} failed: {observation['sense']}")
        chunks.append(data[:length])
    return b"".join(chunks)


def classify(phase: str, identity: dict, private: dict, sentinel: dict | None, expected: bytes | None) -> list[str]:
    failures = []
    if phase in {"before", "cold"}:
        if identity["status_good"] or "Invalid field in cdb" not in identity["sense"]:
            failures.append("stock Identity CDB did not reject with Invalid field in cdb")
        if private["status_good"] or "Invalid command operation code" not in private["sense"]:
            failures.append("stock private opcode did not reject with Invalid command operation code")
    else:
        if not private["status_good"]:
            failures.append("private opcode did not return SCSI GOOD")
        if sentinel is None or expected is None:
            failures.append("after phase requires a verified sentinel readback CDB and expected bytes")
        elif not sentinel["status_good"] or bytes.fromhex(sentinel["data_hex"]) != expected:
            failures.append("handler sentinel readback did not match the expected bytes")
    return failures


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("before", "after", "cold"))
    parser.add_argument("device", help="SCSI generic device, e.g. /dev/sg0")
    parser.add_argument("oem_image", type=Path)
    parser.add_argument("--sentinel-cdb-hex", help="verified readback CDB for the handler's RAM result cell")
    parser.add_argument("--expected-sentinel-hex", help="exact bytes expected from the result cell")
    parser.add_argument("--report", type=Path, help="JSON evidence destination")
    args = parser.parse_args()

    image = args.oem_image.read_bytes()
    if len(image) != 0x200000 or hashlib.sha256(image).hexdigest() != OEM_SHA256:
        parser.error("input is not the audited BU40N OEM 1.00 fixture")
    try:
        sentinel_cdb = bytes.fromhex(args.sentinel_cdb_hex) if args.sentinel_cdb_hex else None
        expected_sentinel = bytes.fromhex(args.expected_sentinel_hex) if args.expected_sentinel_hex else None
    except ValueError as error:
        parser.error(f"invalid hex argument: {error}")
    if sentinel_cdb is not None and not (6 <= len(sentinel_cdb) <= 16):
        parser.error("sentinel CDB must be 6..16 bytes")
    if expected_sentinel is not None and not (1 <= len(expected_sentinel) <= 0x100):
        parser.error("expected sentinel must be 1..256 bytes")

    inquiry = run(["sg_inq", args.device])
    if inquiry.returncode != 0 or "BD-RE BU40N" not in inquiry.stdout or "Product revision level: 1.00" not in inquiry.stdout:
        parser.error("drive did not identify as BU40N 1.00")

    with tempfile.TemporaryDirectory(prefix="bu40n-ram-hook-evidence-") as temp:
        directory = Path(temp)
        code = dump_code(args.device, directory)
        identity = read_cdb(args.device, IDENTITY_CDB, 64, directory / "identity.bin")
        private = read_cdb(args.device, PRIVATE_CDB, 0, directory / "private.bin")
        sentinel = None
        if args.phase == "after" and sentinel_cdb and expected_sentinel:
            sentinel = read_cdb(args.device, sentinel_cdb, len(expected_sentinel), directory / "sentinel.bin")

    expected_code = image[CODE_START:CODE_END]
    mismatch = next((CODE_START + i for i, (a, b) in enumerate(zip(code, expected_code)) if a != b), None)
    failures = classify(args.phase, identity, private, sentinel, expected_sentinel)
    if mismatch is not None:
        failures.append(f"live executable image differs from OEM at {mismatch:#x}")
    report = {
        "phase": args.phase,
        "device": args.device,
        "inquiry": inquiry.stdout.strip(),
        "oem_image_sha256": OEM_SHA256,
        "code_range": [f"0x{CODE_START:x}", f"0x{CODE_END:x}"],
        "code_sha256": hashlib.sha256(code).hexdigest(),
        "code_matches_oem": mismatch is None,
        "first_code_mismatch": f"0x{mismatch:x}" if mismatch is not None else None,
        "identity": identity,
        "private_opcode": private,
        "sentinel": sentinel,
        "checks_passed": not failures,
        "failures": failures,
        "claim_limit": "Read-only phase evidence; does not prove RAM setup or a cold power cycle by itself.",
    }
    rendered = json.dumps(report, indent=2) + "\n"
    print(rendered, end="")
    if args.report:
        args.report.write_text(rendered)
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
