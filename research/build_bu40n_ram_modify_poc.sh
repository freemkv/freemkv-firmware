#!/usr/bin/env bash
# Build an OEM + RAM-loaded modify-handler POC.
#
# This never flashes an image. It runs the normal offline `modify` build only
# to obtain the handler bytes, then emits the runtime Poke/Call command list.
# The emitted commands require a pre-existing C0 DE runtime handler; stock OEM
# firmware rejects these frames and cannot bootstrap itself with them.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
input="${1:-$repo_root/crates/freemkv-fw/tests/fixtures/BU40N_OEM_1.00.bin}"
out_dir="${2:-${TMPDIR:-/tmp}/bu40n-ram-modify-poc}"
mkdir -p "$out_dir"

modified="$out_dir/modified-offline.bin"
payload="$out_dir/modify-handler.bin"
manifest="$out_dir/modify-handler-c0de.json"
commands="$out_dir/modify-handler-c0de.sh"

cd "$repo_root"
cargo run -q -p freemkv-fw -- create --base "$input" "$modified" >/dev/null

# The MT1959 BU40N injected modify band is emitted at this audited
# file/runtime offset. It contains the command handler plus the generated
# boot and feature stubs, not just the command handler.
# Keep the length explicit and fail if the generated pointer is not the one
# from the audited image, rather than silently loading unrelated bytes.
handler_offset=0x153968
handler_length=$((0x153e54 - 0x153968))
handler_word="$(dd if="$modified" bs=1 skip=$((0x14fd78)) count=4 2>/dev/null | od -An -tu4 | tr -d '[:space:]')"
if [[ "$handler_word" != "1390953" ]]; then
  echo "unexpected modify handler pointer: $handler_word" >&2
  exit 1
fi
dd if="$modified" of="$payload" bs=1 skip=$handler_offset count=$handler_length status=none

python3 "$repo_root/research/emit_bu40n_ram_modify_c0de.py" \
  "$payload" "$manifest" "$commands"

echo "OEM input: $input"
echo "Offline modify image: $modified"
echo "RAM payload: $payload"
echo "C0 DE manifest: $manifest"
echo "C0 DE command script: $commands"
