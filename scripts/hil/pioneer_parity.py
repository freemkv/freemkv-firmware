#!/usr/bin/env python3
"""Hardware-in-the-loop parity: run two freemkv-flash builds against one real
Pioneer drive and compare every SCSI command they send.

For each build, in order: info, backup, dump (after a warm-up dump, so RAM
logging is already on for both builds), flash dry run, and (with
--execute) a real flash of PACKAGE followed by a post-flash backup. Each run's
diagnostic log is reduced to its SCSI request/result sequence (CDB, direction,
length, status, transferred, sense); timestamps, PIDs, paths and versions are
dropped, and back-to-back repeats of one command (readiness polling) are
collapsed so drive timing cannot cause a false difference. Write payloads are
not logged; they come from PACKAGE through the same pioneer-optical release
and are pinned by the golden tests.

Usage:
  pioneer_parity.py OLD_BIN NEW_BIN DEVICE PACKAGE OUT_DIR [--execute]

Exit status 0 means every step matched; 1 lists the first difference per step.
--execute writes PACKAGE to the drive twice (once per build): use only an
official package the drive already runs.
"""
import hashlib
import os
import re
import subprocess
import sys
import time

REQ = re.compile(
    r"SCSI request: device=\S+ cdb=\[([0-9a-f, ]+)\] direction=(\w+) requested=(\d+)"
    r" attempt=\d+ strict=(\w+)"
)
RES = re.compile(r"SCSI result: status=(0x[0-9a-f]+) transferred=(\d+) sense=\[([0-9a-f, ]+)\]")
LOG = re.compile(r"Diagnostic log saved: (.+)$")


def transcript(log_path):
    """The SCSI request/result sequence of one run, polling collapsed."""
    pairs = []
    with open(log_path, errors="replace") as f:
        for line in f:
            m = REQ.search(line)
            if m:
                pairs.append([m.groups(), None])
                continue
            m = RES.search(line)
            if m and pairs and pairs[-1][1] is None:
                pairs[-1][1] = m.groups()
    out = []
    for req, res in pairs:
        step = (req, res)
        if out and out[-1][0] == step:
            out[-1] = (step, "repeated")
        else:
            out.append((step, "once"))
    return out


def run(binary, args, cwd):
    """Run one step; return (exit code, stdout+stderr, diagnostic log path)."""
    os.makedirs(cwd, exist_ok=True)
    # Another app (a ripper polling for discs) can hold the drive for a moment;
    # nothing was sent when the open fails, so retry before judging the step.
    for _ in range(10):
        p = subprocess.run(
            [binary] + args, cwd=cwd, stdin=subprocess.DEVNULL, capture_output=True, text=True
        )
        text = p.stdout + p.stderr
        if "already open by another process" not in text:
            break
        time.sleep(3)
    logs = [m.group(1).strip() for m in map(LOG.search, text.splitlines()) if m]
    return p.returncode, text, logs[-1] if logs else None


def sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def main():
    argv = [a for a in sys.argv[1:] if a != "--execute"]
    execute = "--execute" in sys.argv[1:]
    if len(argv) != 5:
        sys.exit(__doc__)
    old, new, device, package, out = argv
    steps = [
        ("info", ["info", device]),
        ("backup", ["backup", device]),
        # The first dump after power-on switches RAM logging on and the next does
        # not, so each build gets a warm-up dump and the second one is compared.
        ("dump-warmup", ["dump", device]),
        ("dump", ["dump", device]),
        ("flash-dry-run", ["flash", device, "-i", package]),
    ]
    if execute:
        steps += [
            (
                "flash-execute",
                ["flash", device, "-i", package, "-b", "preflash.tar", "--execute",
                 "--i-understand-risk"],
            ),
            ("post-flash-backup", ["backup", device]),
        ]
    results = {}
    for label, binary in (("old", old), ("new", new)):
        for step, args in steps:
            cwd = os.path.join(out, label, step)
            code, text, log = run(binary, args, cwd)
            with open(os.path.join(cwd, "output.txt"), "w") as f:
                f.write(text)
            files = sorted(n for n in os.listdir(cwd) if n.endswith((".tar", ".bin")))
            results[(label, step)] = {
                "code": code,
                "log": log,
                "seq": transcript(log) if log else [],
                "files": {n: sha(os.path.join(cwd, n)) for n in files},
            }
            print(f"{label:3} {step:18} exit={code} commands={len(results[(label, step)]['seq'])}")
    failed = False
    for step, _ in steps:
        if step == "dump-warmup":
            continue
        a, b = results[("old", step)], results[("new", step)]
        problems = []
        if a["code"] != b["code"]:
            problems.append(f"exit {a['code']} vs {b['code']}")
        if not a["seq"] or not b["seq"]:
            problems.append("no SCSI transcript")
        elif a["seq"] != b["seq"]:
            first = next(
                (i for i, (x, y) in enumerate(zip(a["seq"], b["seq"])) if x != y),
                min(len(a["seq"]), len(b["seq"])),
            )
            ctx = lambda s: s[first] if first < len(s) else "<end>"
            problems.append(
                f"commands differ at #{first}: old {ctx(a['seq'])} / new {ctx(b['seq'])}"
            )
        # Firmware captures must match byte for byte; a dump holds live RAM.
        if step in ("backup", "post-flash-backup") and a["files"] and b["files"]:
            if sorted(a["files"].values()) != sorted(b["files"].values()):
                problems.append(f"backup bytes differ: {a['files']} vs {b['files']}")
        if step == "post-flash-backup":
            want = sha(package)
            for label, r in (("old", a), ("new", b)):
                if want not in r["files"].values():
                    problems.append(f"{label} post-flash backup is not the package ({want[:16]})")
        verdict = "MATCH" if not problems else "DIFFER"
        failed |= bool(problems)
        print(f"{step:18} {verdict}" + "".join(f"\n    {p}" for p in problems))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
