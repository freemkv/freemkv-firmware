# Kickoff — Pioneer firmware downgrade support

## Mission
Make **every Pioneer flash succeed regardless of version**, handling the drive's
generation-marker downgrade gate. Pioneer only. **Do not touch any MTK / MediaTek
code.** No live device I/O in this work (offline/mock only). Do not commit. Claude
settings are global (`~/.claude/settings.json`); never create a project-level
`.claude/settings.json`. Reference platform: BDR-UD04 (`SAT 8A10`), big-endian H8SX.

## Read first (authoritative, word-for-word)
- `freemkv-private/docs/pioneer-firmware-whitepaper.md` — Ch.12 (update protocol),
  Ch.13 (boot contract), Ch.14 (pairing), **Ch.15 (generation marker + downgrade)**,
  Ch.21 (open problems).
- `firmware-extractor/internal/research/pioneer-s13-de/README.md` and its
  disassembly (`s13u-105-boot-gate.asm`, `s13u-105-marker-gate.asm`), and
  `internal/research/pioneer-kernel-compatibility/boot-contracts.md`.
- BDRFlash disasm already produced at `/tmp/bdrflash_dis.txt` (+ strings).

## Repos / where things live
- Flasher: `freemkv/freemkv-firmware`, crate `freemkv-flash`. Executor
  `src/pioneer_flash.rs` (`execute_flash`); caller `src/drive/pioneer.rs`
  (`flash_bundle`); key table `src/pioneer_keys.bin` + `src/pioneer_keys.rs`
  (keyed by SAT/controller_id; carries per-model control descriptor + key + a
  fallback `fb`); OEM backup tables `src/pioneer_k.bin` / `src/pioneer_n.bin`.
- Codec: `firmware-extractor/crates/pioneer-codec` (used as `pioneer_codec`).
  Decoder CLI `firmware-extractor/target/release/pioneer-firmware decode PKG.firmware.tar -o DIR [--unverified-codec]`.

## What is PROVEN (two independent RE passes, grounded to addresses/offsets)

### The generation gate (receiver side — confirmed corpus-wide)
- Marker = **decoded Kernel body `0xFE`** (runtime `0x4000FE`): `01` newer, `FF`
  older, `00` legacy. Corpus iff: the 4 newer-gate code signatures are present in
  exactly the 91 `01` kernels (26 hardware labels) and **none** of the 78 `FF`
  kernels. Scope: this is the **newer derived-key SAT** architecture; legacy
  SAT10xx (markers `0C/0D/18/55`) and non-SAT ATA use `0xFE` differently — exclude.
- **Site 1 — incoming-kernel gate** (S13 1.05 `0x405266`, from receive-buffer
  `+0x12FE`): rejects incoming kernel marker `FF` or `00`; caller `0x404D42` →
  error `0x404D8A`. Older receivers lack it.
- **Site 2 — boot equality** (`0x400212`): Normal `0x410028` vs Kernel `0x4000FE`;
  mismatch → `0x40026A` → **`JMP 0x4057DE`** ("Kernel Power ON" + RAM2800 receiver),
  never reaching the Normal entry (`JSR 0x4049CA`). I.e. a mismatch is a
  **recoverable soft-brick**: kernel keeps the update receiver alive (re-flashable),
  but the Normal never boots. Older kernels lack Site 2.

### The Normal is signature-locked at flash time — NEVER edit the Normal
On the encrypted (OEM) receive route, the Normal commit arm (`0x404B96`) calls the
ECDSA validator `0x4050C6` → HW EC engine at `0xA00000`, verifying `[0x200,end]`
(the `r/s/Qx/Qy` block at header `0x170`); nonzero → **error `0x0B`, abort
`0x404D1E`**. `0x410028` (envelope `0x10228`) is inside that signed span. We do
**not** hold the OEM private key, so a flipped/edited Normal cannot be re-signed.
The boot path does **not** re-verify (signature is flash-time only). A plaintext
receive route skips the signature but is model-literal-gated and unproven — do not
use. ⇒ **"patch the Normal's `0x410028`" (old Option C) is dead.**

### Our backup is rollback-safe
Our capture reconstructs the full OEM **envelope byte-for-byte identical to the
OEM-distributed file** (both components, `OEM-VERIFIED`). Re-flashing it restores
exact OEM state. The whitepaper's generic "no restorable backup" caveat (Ch.21 #3)
does NOT apply to us. Keep the mandatory pre-flash backup as the rollback guarantee.

## How the tools actually downgrade (trust-weighted)
| | kernel `0xFE` patch | `0x1020` rebalance | Normal edit | mechanism |
|---|---|---|---|---|
| **BDRFlash** (TRUSTED) | **No** | **No** | **No** | `--forceflash/2/3` skip HOST version/model match + drive-side vendor **kernel-mode unlock** (`0xF3` then `0xF2` 0x400-byte status handshake) + `07`-family key/16-byte-descriptor control header (fallback key `0x6123789A`); then stream OEM image **unmodified**. (`--forceflash` refused for drive id > `0x9401`.) |
| **Autoflasher** (TRUSTED) | **No** | **No** | **No** | 16-byte descriptor + 32-bit key control header (GENERAL→`0xFD236642`, fallback `0x6123789A`); raw image as-is. |
| **trev.bot** (UNTRUSTED, beta) | **Yes** FF→01 | **Yes** +`0xFE00` | No | patch kernel bytes, re-encode, ship patched kernel + unmodified Normal. Only tool that edits the image. |

**Neither trusted tool corroborates trev's marker patch.** Both get an older/foreign
OEM image accepted by **unlocking the drive-side receiver** (vendor key/descriptor
control header + `0xF3`/`0xF2` handshake), not by mutating the image.

## THE decisive open question (resolve this FIRST)
Both facts are proven and in tension:
- The Site-1 marker reject (`0x405266`, FF/00) is real on newer receivers.
- The trusted tools send the **unmodified** (older, `FF`) kernel and rely on a
  drive-side unlock.

So: **does the vendor kernel-mode unlock (`0xF3`/`0xF2`, and/or the control-word
accepted-state — bit6=1/bit7=0 at RAM `0x0144`) bypass the Site-1 `FF`/`00` reject?**
Trace the S13 1.05 receiver (`0x405266` and its caller `0x404D42`; the
"receiver-state/installed-length exception at `0x4052B2..0x4052C4`" noted as
partly-untraced in the research) to see whether an unlocked/entered state clears
the reject.
- **If YES** → the clean, trusted-corroborated downgrade needs **no image edit**:
  enter kernel mode with the correct control key + unlock, then stream the
  **unmodified** matching older OEM kernel + Normal. Preferred.
- **If NO** (Site-1 still rejects `FF` even when unlocked) → the marker patch is
  required for marker-gated generations; use it as a **fallback**, flagged as
  trev-derived/not-corroborated.

## Recommended plan
1. **Close the open question above** (drive-side disasm; the S13 1.05 receiver is
   already disassembled under `pioneer-s13-de/`).
2. **Primary path — reproduce the trusted drive-side unlock** (what BDRFlash +
   Autoflasher do): confirm/implement the vendor kernel-mode unlock (`0xF3`/`0xF2`
   handshake) and the key/descriptor control header (our `pioneer_keys.bin` already
   has descriptor+key+fallback; confirm the fallback is `0x6123789A`), then transfer
   the **unmodified** matching OEM kernel + Normal. This writes a kernel for a true
   downgrade (a Normal-only older flash on a retained newer kernel fails Site 2 →
   soft-brick), pairing the kernel by the date rule (§14.5: newest kernel sharing
   hardware+type whose date ≤ the Normal's; 170/170 on known pairings).
3. **Fallback path (only if step 1 says unlock does NOT bypass Site 1):** the
   marker transform, flagged untrusted. On the **decoded kernel** body: `0xFE`
   FF→01; add `0xFE00` (mod 2^32) to the BE word at `0x1020` (carry may touch
   `0x1021/22`); re-encode with the original key table; preserve first `0x1200`.
   This is proven *offline only* by `firmware-extractor` `check_marker_patch` (KAT
   `pioneer-s13-de/ud04-marker-patch-kat.json`: UD04 1.00 → patched core
   `f60f21e2…`, envelope `198b879b…`, changed offsets `0xFE`+`0x1022`, roundtrip
   true). The kernel receive route is checksum-only (no signature on the FE/type-0
   arm — validator `0x4050C6` is reachable only from the Normal arm), so a
   marker+balance edit is a legal kernel edit. Build it in `pioneer-codec` as
   `normalize_generation_marker(envelope)->envelope` (+ `generation_marker`),
   reusing `check_marker_patch`; KAT + zero-sum + idempotency + diff-only-at-`0xFE`/`0x1020` tests.
4. **Wire into `freemkv-flash`** only the path chosen by step 1, surfaced in the
   plan/confirm output. **Normal-only flashes write no kernel — leave untouched.**
   Keep byte-exact UD04 Normal-only self-flash. Keep MTK untouched.

## Hard limits & residual risk
- Never edit the Normal image (signature-locked at flash; cannot re-sign).
- No cross-type/cross-model acceptance (that's crossflash — separate; boot enforces
  model @`0x410000` and type @`0x410018` vs kernel `0x40644E`/`0x401008`).
- Open problems (Ch.21): **#1 signature-trust policy** (is the HW engine's public
  point pinned or accepted-as-supplied? unproven — bounded trace shows no *software*
  equality test but HW pinning possible); **#7 downgrade end-state** (clean boot of
  a marker-edited older pair not proven on silicon). The drive-side "does unlock
  bypass Site 1" question (above) is the other load-bearing unknown.
- Mitigation for any live run: the OEM-identical pre-flash backup makes a Site-2
  soft-brick / failed downgrade reversible. First live downgrade = reversible,
  supervised, on a drive we can re-flash.
- Build hygiene: offline/mock tests only, no commit, every change tested,
  `cargo fmt` + `cargo clippy --all-targets -D warnings` + `cargo test` green in
  both crates.
