#!/usr/bin/env python3
"""Compare prepared Pioneer updates with the exact freemkv 0.15.4 baseline.

Read-only OEM corpus validation, not hardware certification. Checks every modern
pair's self-update and directed SAT 1014/1030/1031 combinations. Existing admitted
routes must retain exact transfer/image hashes, control bytes and settings. New
admissions must have been refused specifically for a Kernel handoff mismatch.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile

BASELINE = "d7ae773da92d37f05fa2740be98cdb6e0281e486"
RUST_SOURCE = Path(__file__).with_name("pioneer-bridge-parity.rs").read_text()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hoard", required=True, type=Path)
    parser.add_argument("--pioneer", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="pioneer-bridge-parity-") as temporary:
        root = Path(temporary)
        (root / "src").mkdir()
        (root / "src/main.rs").write_text(RUST_SOURCE)
        manifest = f'''[package]
name = "bridge-parity"
version = "0.1.0"
edition = "2021"
[workspace]
[dependencies]
baseline = {{ package = "pioneer-optical", git = "https://github.com/MattJackson/pioneer-optical", rev = "{BASELINE}", features = ["drive", "envelope"] }}
candidate = {{ package = "pioneer-optical", path = {json.dumps(str(args.pioneer.resolve()))}, features = ["drive", "envelope"] }}
serde_json = "1"
sha2 = "0.10"
'''
        (root / "Cargo.toml").write_text(manifest)
        corpus = args.hoard / "packages/pioneer"
        entries = []
        for archive in sorted(corpus.rglob("*.tar")):
            with tarfile.open(archive) as bundle:
                members = [(member.name, bundle.extractfile(member).read())
                           for member in bundle.getmembers()
                           if member.isfile() and member.name.endswith(".enc")]
            kernels = [data for _, data in members if len(data) == 0x11200]
            normals = [data for _, data in members if len(data) > 0x11200]
            if len(kernels) != 1 or len(normals) != 1:
                continue
            directory = root / "corpus" / archive.stem
            directory.mkdir(parents=True)
            entry = {"package": str(archive.relative_to(args.hoard)), "group": archive.relative_to(corpus).parts[0]}
            for name, data in [("kernel", kernels[0]), ("normal", normals[0])]:
                path = directory / name
                path.write_bytes(data)
                entry[name] = str(path)
                entry[name + "_sha256"] = hashlib.sha256(data).hexdigest()
            entries.append(entry)
        if not entries:
            parser.error("no complete modern Pioneer pairs found")
        inputs = root / "corpus.json"
        inputs.write_text(json.dumps(entries))
        result = subprocess.run(
            ["cargo", "run", "--release", "--manifest-path", str(root / "Cargo.toml"), "--", str(inputs)],
            stdout=subprocess.PIPE, text=True, check=False,
        )
        if result.stdout:
            evidence = json.loads(result.stdout)
            evidence["inputs"] = [{key: value for key, value in entry.items()
                                  if key not in ("kernel", "normal")} for entry in entries]
            args.output.write_text(json.dumps(evidence, indent=2) + "\n")
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
