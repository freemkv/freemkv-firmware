# freemkv-hwtest

A data-driven hardware-test harness for flashed freemkv firmware. It replaces
the shell suite `scripts/fw_hwtest.sh` with a single-framing, YAML-driven runner.

## Why this exists

freemkv's vendor commands hijack SCSI `READ BUFFER` (`0x3C`), and **every** knock
returns a fixed 64-byte data-in reply. The old shell suite issued some toggles
with **no data-in phase** (`sg_raw` without `-r`), which desyncs the transfer:
the drive returns ABORTED COMMAND and then **hangs** on the next command (the
0.6.0 wedge). The fix is architectural: there is exactly **one** call primitive,
`call::call_cdb(scsi, cdb, dir, alloc, timeout_ms) -> CallResult`, and every test
step goes through it, so the framing can never drift. The transport is
libfreemkv's real `scsi` layer (the same one production uses), so test framing ==
production framing.

## Running against hardware

```
freemkv-hwtest --dev /dev/sg0                       # disc-less phases (default)
freemkv-hwtest --dev /dev/sg0 --disc                # include disc phases
freemkv-hwtest --dev /dev/sg0 --expect-version "freemkv 0.6.6"
freemkv-hwtest --dev /dev/sg0 --script my.yaml      # custom script
freemkv-hwtest --dev /dev/sg0 --disc --delay-ms 300 --settle-ms 600  # slower pacing
freemkv-hwtest --script tests.yaml                  # validate-only (no --dev; touches nothing)
```

Exit codes: `0` all steps passed (skips don't fail the run), `1` a step failed,
`2` the drive wedged (DID_BAD_TARGET / timeout — power-cycle to recover). After
every step the runner re-issues the identity knock as a wedge guard; a dead bus
aborts immediately. The final line reports `PASS=… FAIL=… SKIP=…`; a skipped step
prints `SKIP [phase] …` (e.g. a cert-AKE step with no `AKE_HELPER` configured).
See **Command pacing** and **Cert-AKE matrix** below for the pacing flags
(`--delay-ms` / `--settle-ms` / `--tur-retries` / `--tur-backoff-ms`) and the
`AKE_HELPER` / cert env vars.

Without `--dev` the tool only parses/validates the script (host-independent), so
`cargo test` and CI never need hardware.

## Script schema

The full schema is documented at the top of [`tests.yaml`](tests.yaml). In short,
each step names itself, declares a `phase` (`discless`/`disc`), and supplies
**exactly one** command form: a structured `knock` (`{ subfn, state, addr }`,
assembled into `3C 0E C0 DE <subfn> <state> 00 00 40 00`), a `raw` hex CDB, an
ordered `sequence` of sub-commands (see below), or an `exec` host-side helper
(the cert AKE — see **Cert-AKE matrix**). It sets the data `dir` and `alloc`
length, may `repeat` the command, run it `iterations: N` times (see below), or
mark itself `report`-only, and lists `expect`ations: the SCSI `status`, an
optional `sense_key`, optional `data` assertions and an optional `flag`
persistence check (`{ subfn, equals }`, read back via DumpAll at `flag_base`).
An `exec` command is asserted with `expect_exec` instead (`result` / `any_of` /
`exit_code` / `stdout_contains` / `vid`).

`data` assertions come in two groups. Whole-response: `starts_with_ascii` /
`starts_with_hex` / `contains_ascii` / `contains_version`. Field checks operate
on a `slice: { offset, len }` window (or the whole response if omitted) — e.g.
the 16-byte VID at `[4..20]` of a `READ DISC STRUCTURE` reply — and cover
`nonzero`, `min_len`, `stable` (identical across every `repeat` read),
`capture: <name>` (store the window for later), and `equals_capture: <name>`
(must equal a window captured by an earlier step). This is how the disc-phase
Raw Read contract asserts the VID is present, sticky/idempotent, and unchanged
across toggle cycles without ever hard-coding the disc-specific value.

Numbers accept decimal, `0x`-hex, or a quoted `"0x.."` string. `flag_base`
defaults to `0x02000e40` (mirrors `freemkv-fw`'s `FLAG_TABLE_BASE`) and is
overridable in the script.

### Reliability (`iterations`) and multi-command `sequence` steps

Two step forms turn a single lucky/unlucky shot into a statistic and let a test
reproduce order-dependent bugs:

* **`iterations: N`** runs the step's command form `N` times, scoring **each run
  independently** and reporting `X/N passed` instead of aborting on the first
  failure — so an intermittent toggle shows up as e.g. `17/20`, not a coin-flip
  PASS. The step passes only when `X == N`. This differs from `repeat: N`, which
  collects all reads for `stable`/status ANDing within one logical command. A
  per-command timeout/hang is classified as a **WEDGE** (exit 2), never a silent
  skip. Between iterations the runner re-asserts the identity wedge-guard; if the
  drive has stopped answering it aborts (exit 2) rather than hammering it.

* **`sequence: [ sub, … ]`** runs an ordered list of sub-commands as one logical
  unit. Each sub is `{ name, knock|raw, dir?, alloc?, repeat?, expect }` — a step
  without its own `phase` (it inherits the parent's) and with no nesting. Combined
  with `iterations`, the *whole ordered sequence* repeats, which is how the
  deny→approve→read hang is reproduced (below).

Both are exercised by unit tests against the mock transport (a stateful drive
that models the bug and its fix), so CI catches regressions in the harness logic
itself with no hardware.

### The `04 01` deny→approve→read hang repro

The regression this guards against: from a clean state `04 01` (Raw Read
cert-valid) + a bare `READ DISC STRUCTURE` (`AD 01 …`, format `0x80`) returns the
VID reliably, **but** after a `04 00` (Raw Read OEM) **deny** the *next*
`04 01` + `0xAD` **hangs / times out**. `tests.yaml` step **D8** reproduces
exactly that ordering and repeats it 20×:

```
[ 04 01 → bare 0xAD expect VID ]        # unlock + read
[ 04 00 → bare 0xAD expect DENY ]       # OEM deny (CHECK CONDITION / ILLEGAL REQUEST)
[ 04 01 → bare 0xAD expect VID again ]  # re-approve + read  ← THE HANG POINT
```

The final unlock read is asserted **GOOD + nonzero VID every iteration** and is
compared to the VID captured once in D2 (`equals_capture: vid`), so a value that
drifts across the deny→approve cycle also fails. Pre-fix, that last read wedges
and the run exits **2**; post-fix it reports `20/20 iteration(s) passed`.

Run it with `--disc` (a disc must be loaded):

```
freemkv-hwtest --dev /dev/sg0 --disc     # includes D8 and the P3r reliability soak
```

The disc-less **P3r** steps run `04 00` / `04 01` / `04 02` 20× each and report a
per-mode pass-rate, so a flaky toggle is caught without a disc. Bump the
`iterations` count in the script for a longer soak.

## Coverage

Disc-less (default): identity == expected version; Speed `02` FF/00/42 flag
persistence; Region `03` 01/00; Raw Read `04` 00/01/02 (no wedge + flag
persists); **P3r** per-mode reliability soak (`04` 00/01/02 ×20 each, pass-rate
reported); DumpAll window; OEM `0x3C` passthrough intact; alive invariant.

Disc (`--disc`): the full Raw Read (`0x04`) behavioural contract, all validated
on real hardware (freemkv 0.6.6, UHD/AACS-2.x disc) —
D1 **deny** (Raw Read off → bare `0xAD` = CHECK CONDITION / ILLEGAL REQUEST),
D2 **unlock** (`04 01` → bare `0xAD` returns a 16-byte nonzero VID at `[4..20]`,
captured), D3 **idempotent** (bare `0xAD` x5 with no knock between — every read
GOOD and the VID identical, proving a sticky, non-single-use flag), D4 **revert**
(`04 00` → denied again), D5 **re-enable** (`04 01` → the *same* VID returns),
D6 `READ(10)` sector (GOOD + 2048 bytes, still AACS-encrypted), D7
informational disc-type probes (READ CAPACITY(10), GET CONFIGURATION — printed,
never asserted), **D8** the deny→approve→read hang repro (see below), **D9** the
01/02 split (`04 02` + bare `0xAD` still DENIED — `02` forces only the AKE path,
not the bare producer gate), **D10** the disc unlock reliability soak
(`04 01` → bare `0xAD` → VID, x20, reported X/20), and **D11** the cert-AKE matrix
(see below). The VID is disc-specific and is **never** asserted against a fixed
value; the tests assert only presence, nonzero, and stability.

## Command pacing (don't DDoS the drive)

Rapid-fire commands are a known wedge trigger on this controller, and a
spun-down disc is a false-timeout source. The runner paces every command
(defaults; all overridable per `--flag`, env, or the script top level, and
settable to `0` to disable — the mock unit tests run with pacing off so
`cargo test` stays instant):

| knob | default | CLI | env | what |
|------|---------|-----|-----|------|
| inter-command delay | 200 ms | `--delay-ms` | `HWTEST_DELAY_MS` | sleep after every SCSI command |
| post-toggle settle | 400 ms | `--settle-ms` | `HWTEST_SETTLE_MS` | extra sleep after a flag-toggle knock (`02`/`03`/`04`) so the flag write + engine state land before the next read |
| TUR poll retries | 10 | `--tur-retries` | `HWTEST_TUR_RETRIES` | before any disc read (`0xAD`/`READ(10)`), poll `TEST UNIT READY` until GOOD (`0` disables) |
| TUR poll backoff | 150 ms | `--tur-backoff-ms` | `HWTEST_TUR_BACKOFF_MS` | linear backoff between TUR polls |

Precedence is CLI > env > script > default. The per-command timeout and the
identity wedge-guard remain the hard stop: a genuine hang still classifies as a
wedge and exits 2. If `TEST UNIT READY` never goes GOOD within the retry budget
the runner proceeds best-effort (the read then fails naturally rather than the
harness looping forever).

## Cert-AKE matrix (`exec` step + config)

**D11** drives libfreemkv's host-side AACS AKE (the `cert_vid` example) against
each Raw Read mode with a **valid** and a **revoked** host cert, proving the
firmware's cert policy. Each entry is a `sequence` — knock the mode, then run the
AKE via an `exec` sub-step — repeated `iterations: 20`:

| mode | valid cert | revoked cert |
|------|-----------|--------------|
| `04 00` OEM enforce | AKE runs the drive's own policy → **VID** | drive HRL denies → **REJECTED** |
| `04 01` bare unlock | behaves like OEM (`01` does **not** touch the AKE path) → **VID** | like OEM → **REJECTED** |
| `04 02` accept-any-cert | **VID** | **forced accept → VID** (the `04 02` headline) |

The `exec` step runs `AKE_HELPER --dev <dev> --cert <hex> --key <hex>`; the
helper prints `VID <hex32>` (exit 0) or `REJECTED` / `NO_VID` / `TRANSPORT`
(exit 2 / 3 / 5). Supply the helper + certs via env (or the script's `ake:`
block):

```
AKE_HELPER=/path/to/cert_vid \
VALID_CERT=<hex> VALID_KEY=<hex> \
REVOKED_CERT=<hex> REVOKED_KEY=<hex> \
freemkv-hwtest --dev /dev/sg0 --disc
```

If `AKE_HELPER` (or a cert pair) isn't set/found, the D11 steps **SKIP** with a
clear message (printed as `SKIP [disc] …`) — they never hang or hard-fail on
absence, exactly like the disc-phase gate. The VID is disc-specific, so only
16-byte / nonzero is asserted (a cert-AKE VID can also be `equals_capture`d
against the bare-read VID).

**Disc-type caveat:** the shipped certs are AACS 1.0. On a UHD / AACS-2.0 disc a
1.0 cert may legitimately `REJECTED` even when it "should" succeed, so the
AKE-success entries assert `any_of: [vid, rejected]`. On a BD / AACS-1.0 disc,
tighten those to `result: vid` (edit your copy of `tests.yaml` per disc-type).

The `exec` step type, TUR polling, pacing, and the skip logic are all covered by
mock unit tests (a stateful drive modelling the bug + fix, a TUR drive, and
`/bin/sh`-backed exec helpers) — CI catches harness regressions with no hardware.
