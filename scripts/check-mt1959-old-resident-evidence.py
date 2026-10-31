#!/usr/bin/env python3
"""Validate saved BN11 resident evidence. Never contacts or modifies hardware.

Usage: --source MAIN.bin --capture MEMORY.bin --metadata CAPTURE.json
Metadata fields and exact source bindings are in the companion audit manifest.
This is an evidence/bounds checker, not a UHD qualification or flash tool.
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path


def number(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def branch_target(address, word):
    delta = (word & 0xFFFFFF) << 2
    if delta & 0x2000000:
        delta -= 0x4000000
    return address + 8 + delta


def check(source, capture, metadata, manifest):
    errors = []
    expected = manifest["source"]
    if len(source) != expected["bytes"] or sha(source) != expected["sha256"]:
        errors.append("Source length/hash does not match immutable BN11 main image.")
    for key in manifest["capture_metadata_required"]:
        if key not in metadata or metadata[key] in (None, ""):
            errors.append("Missing capture metadata: " + key)
        elif isinstance(metadata[key], str) and metadata[key].startswith("REPLACE_WITH"):
            errors.append("Unfilled capture metadata placeholder: " + key)
    if errors:
        return {"status": "rejected", "errors": errors}
    if metadata["artifact_type"] != "runtime-memory-capture":
        errors.append("artifact_type must be runtime-memory-capture.")
    if metadata["source_firmware_sha256"] != expected["sha256"]:
        errors.append("Capture metadata does not identify the bound BN11 source hash.")
    base = number(metadata["absolute_base"])
    if base < 0 or base > 0xFFFFFFFF or base + len(capture) > 0x100000000:
        errors.append("Capture absolute address range is invalid.")
    if number(metadata["byte_length"]) != len(capture):
        errors.append("Capture length differs from metadata.")
    if metadata["capture_sha256"] != sha(capture):
        errors.append("Capture SHA256 differs from metadata.")

    def read(address, count):
        offset = address - base
        if offset < 0 or count < 0 or offset + count > len(capture):
            raise ValueError("Capture does not cover " + hex(address) + " + " + hex(count))
        return capture[offset:offset + count]

    entries = []
    for binding in manifest["bindings"]:
        site = number(binding["source_veneer"])
        word = struct.unpack_from("<I", source, site)[0]
        if source[site:site + 4].hex() != binding["source_encoding"]:
            errors.append("Source veneer encoding mismatch: " + binding["role"])
        if binding["transfer"] == "arm_b":
            if word >> 24 != 0xEA:
                errors.append("Source veneer is not the expected unconditional ARM B.")
            raw = branch_target(site, word)
        else:
            if word != 0xE51FF004:
                errors.append("Source veneer is not the expected ARM literal interwork transfer.")
            literal = number(binding["literal_address"])
            if literal != site + 4:
                errors.append("Source literal address is inconsistent with the instruction.")
            raw = struct.unpack_from("<I", source, literal)[0]
        if raw != number(binding["raw_target"]) or raw & ~1 != number(binding["entry"]):
            errors.append("Source-derived entry target mismatch: " + binding["role"])
        entry = number(binding["entry"])
        state = binding["instruction_state"]
        traversal = []
        classification = "manual_semantic_review_required"
        try:
            initial = read(entry, binding["minimum_window"])
            if len(set(initial)) == 1 and initial[0] in (0, 255):
                raise ValueError("Entry window is uniform zero/FF: " + binding["role"])
            address = entry
            visited = set()
            for _ in range(8):
                key = address, state
                if key in visited:
                    raise ValueError("Entry veneer cycle: " + binding["role"])
                visited.add(key)
                step = {"address": hex(address), "instruction_state": state}
                traversal.append(step)
                if state == "arm":
                    ins = struct.unpack("<I", read(address, 4))[0]
                    if ins >> 24 == 0xEA:
                        address = branch_target(address, ins)
                        step["operation"] = "unconditional_arm_branch"
                    elif ins == 0xE51FF004:
                        target = struct.unpack("<I", read(address + 4, 4))[0]
                        address, state = target & ~1, "thumb" if target & 1 else "arm"
                        step["operation"] = "arm_literal_interwork_transfer"
                    else:
                        step["operation"] = "body_or_unrecognized_entry"
                        step["standard_push_prologue"] = (ins & 0xFFFF0000) == 0xE92D0000
                        window = read(address, binding["minimum_window"])
                        if len(set(window)) == 1 and window[0] in (0, 255):
                            raise ValueError("Resolved ARM body window is uniform zero/FF.")
                        step["body_window_sha256"] = sha(window)
                        break
                else:
                    ins = struct.unpack("<H", read(address, 2))[0]
                    if ins & 0xF800 == 0xE000:
                        delta = (ins & 0x7FF) << 1
                        if delta & 0x800:
                            delta -= 0x1000
                        address += 4 + delta
                        step["operation"] = "unconditional_thumb_branch"
                    else:
                        step["operation"] = "body_or_unrecognized_entry"
                        step["standard_push_prologue"] = (ins & 0xFE00) == 0xB400
                        window = read(address, binding["minimum_window"])
                        if len(set(window)) == 1 and window[0] in (0, 255):
                            raise ValueError("Resolved Thumb body window is uniform zero/FF.")
                        step["body_window_sha256"] = sha(window)
                        break
                step["target"] = hex(address)
            else:
                classification = "veneer_depth_limit_manual_review_required"
            entries.append({"role": binding["role"], "source_veneer": hex(site),
                            "entry": hex(entry), "entry_window_sha256": sha(initial),
                            "classification": classification, "traversal": traversal})
        except ValueError as error:
            errors.append(str(error))
    return {"status": "rejected" if errors else "structurally_valid_capture_evidence",
            "errors": errors, "source_sha256": sha(source), "capture_sha256": sha(capture),
            "capture_base": hex(base), "capture_bytes": len(capture), "entries": entries,
            "provenance": "Metadata assertions require independent review; filenames do not authenticate the running firmware.",
            "qualification": "Not established: review actual bodies, B19 layout, outgoing calls, software policy and independent read necessity."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=Path(__file__).resolve().parents[1] /
                        "internal/docs/audits/mt1959-old-resident-evidence-20261030.json")
    args = parser.parse_args()
    try:
        result = check(args.source.read_bytes(), args.capture.read_bytes(),
                       json.loads(args.metadata.read_text()), json.loads(args.manifest.read_text()))
    except (OSError, ValueError, KeyError, TypeError, struct.error) as error:
        result = {"status": "rejected", "errors": [str(error)]}
    print(json.dumps(result, indent=2))
    return 1 if result["status"] == "rejected" else 0


if __name__ == "__main__":
    sys.exit(main())
