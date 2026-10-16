#!/usr/bin/env bash
# Build an offline BU40N 1.00 command-hook proof artifact.
#
# This is intentionally file-only: it never opens a SCSI device and never
# writes a drive. The command hook resides in the output image's flash/XIP
# region, so this script is not evidence for executable RAM on stock firmware.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
input="$repo_root/crates/freemkv-fw/tests/fixtures/BU40N_OEM_1.00.bin"
output="${TMPDIR:-/tmp}/BU40N_command_hook_poc.bin"
report="${TMPDIR:-/tmp}/BU40N_command_hook_poc.json"
expected_input_sha="221ad35b7edd402353e125841893ce651064e8fc6b90368fe84ff19a85a506f4"

actual_input_sha="$(shasum -a 256 "$input" | awk '{print $1}')"
if [[ "$actual_input_sha" != "$expected_input_sha" ]]; then
    printf 'refusing unexpected input hash: got %s, want %s\n' \
        "$actual_input_sha" "$expected_input_sha" >&2
    exit 1
fi

cd "$repo_root"
cargo run -p freemkv-fw -- create --base --audit --json "$input" "$output" >"$report"

# The live READ BUFFER record is at 0x14fd74; its handler field is +4 and is
# little-endian. Verify it points at the injected Thumb handler 0x153968|1.
handler_word="$(dd if="$output" bs=1 skip=$((0x14fd78)) count=4 2>/dev/null | od -An -tu4 | tr -d '[:space:]')"
if [[ "$handler_word" != "1390953" ]]; then
    printf 'unexpected handler pointer: got %s, want 1390953 (0x153969)\n' "$handler_word" >&2
    exit 1
fi

printf 'PoC image: %s\n' "$output"
printf 'Build report: %s\n' "$report"
printf 'Output SHA-256: %s\n' "$(shasum -a 256 "$output" | awk '{print $1}')"
printf 'Identity CDB: 3c 0e c0 de 01 00 00 00 40 00\n'
printf 'Static proof only: no SCSI device was opened.\n'
