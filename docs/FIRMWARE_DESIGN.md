# freemkv firmware (`fmkvfw`) — authoritative design spec

> **The single source of design truth for freemkv firmware.** It defines the
> **locked spec** (the target). Wire *values* are also carried in
> `crates/freemkv-fw/src/abi.rs` (the machine mirror) — where a value there
> disagrees with this doc during migration, this doc is the spec-of-record and
> `abi.rs` is being brought into line (see §12). The host driver re-declares the
> ABI in `freemkv-unlock/src/firmware/mod.rs`, kept in lockstep by the drift-guard
> test `freemkv-unlock/src/firmware/mod_tests.rs`.
>
> **Tool split:** `freemkv-fw` = the **modifier** (OEM image in → freemkv image
> out). `freemkv-unlock` = the **host app** that arms/disarms features at runtime
> over the wire. RE offsets (§10) are BU40N 1.0x and **must be re-confirmed per
> variant.**

---

## 1. What it is — the two-layer rule

`fmkvfw` is a stock MediaTek MT19xx drive firmware, patched to drop the drive-side
**transport / access-control policing** so ordinary host software can read a
protected disc. Built by patching an OEM image — never authored from scratch.

| Layer | Protects | Removed by |
|---|---|---|
| **Content encryption** (AACS proper) | the `.m2ts` payload (AES-128-CBC, title keys) | **host software** (libfreemkv) — never the drive |
| **Transport / access control** | gates the Volume ID + protected values behind the drive–host AKE; optionally bus-encrypts sectors | **this firmware** |

We do **not** decrypt content. The values we surface (VID etc.) are **plaintext at
rest** in a privileged region the drive merely *refuses to emit* without a valid
host cert — the barrier is **firmware policy, not crypto**. Most gates are a policy
flag-flip.

---

## 2. Delivery model — one image per model, signature-retargeted

One self-contained flashed image per model, **OEM-behaviour-identical until
armed.** All feature code is baked in at build time; **no runtime RAM blob, no
per-model profile database.** Per-model address differences are resolved **at build
time by signature** (§10).

> `fmkvfw` = [model X's stock image] + [one shared, signature-retargeted feature+ABI patch].

We inherit X (per-model servo/mechanism/calibration, byte-for-byte) and own the
`++` (one shared patch-set retargeted per model).

---

## 3. Architecture — gate-jump, never gate-edit

We **do not modify OEM gates. We jump each OEM gate into our own gate.** Our gate
reads the feature's state byte:

- **`0xFF` → call the original OEM code** (do exactly what OEM does).
- **anything else → we decide** and return the forced behaviour for that value.

This keeps OEM logic bit-intact (stealth, and no re-RE of OEM internals) and makes
`0xFF` a true "hands-off" everywhere.

---

## 4. Runtime state model

The firmware holds a **feature-state table in RAM** — one state byte per feature
(§7). Every gate consults its byte.

### 4.1 Lifecycle
```
power-on ─► always-on BOOT HOOK ─► RESET(from-flash)
                                     │
                    ┌────────────────┴────────────────┐
             flash has valid config?             flash empty/invalid?
                    │                                  │
            load saved table → RAM            set every feature = OEM (0xFF)
                    └───────────► RAM table is live ◄──┘

SET  feature=state ─► RAM only (never flash)
GET  feature       ─► reads RAM
RESET mode         ─► reload RAM from {flash | OEM}; never writes flash
SAVE               ─► persist whole RAM table to flash (the ONLY writer)
```

### 4.2 Invariants
1. **Flash is written *only* by `SAVE`.** Not SET, not RESET, not boot.
2. **RAM is live state.** SET/RESET mutate RAM; lost on power-cycle unless SAVEd.
3. **Boot = `RESET(from-flash)`** — the one thing the boot hook does today (extensible later).
4. **Empty/invalid flash ⇒ all `0xFF` (OEM).** A freshly flashed, never-SAVEd drive boots byte-identical to OEM.
5. **`RESET` has two RAM-only modes:** `to-flash` (reload saved) and `to-OEM` (all `0xFF`). "Reset to OEM and keep it" = `RESET(to-OEM)` **then** `SAVE`.

### 4.3 Stealth model
Stealth is **"OEM until *configured and saved*"** — not "OEM every boot." A drive
that SAVEd non-OEM features boots with them applied (the point of SAVE); an
unconfigured/fresh drive boots stock.

---

## 5. State-byte grammar

Every feature's state byte is a **per-feature value domain** with exactly **one
universally reserved code**:

| Code | Meaning | Reserved everywhere |
|---|---|---|
| **`0xFF`** | **OEM** — run OEM code (the gate-jump passthrough). Load-bearing: boot/empty-flash/RESET-to-OEM/stealth all depend on "all `0xFF` = OEM." | **yes** |
| `0x00` | the feature's **OFF / most-permissive-unlock or most-restrictive** pole (per feature) | convention |
| `0x01` | **ON** (toggles) or first value (valued features) | convention |
| `0x02–0xFE` | valued features only (Speed, Region) | per feature |

Rule we hold to: **OEM is never assumed equal to a specific on/off value** — it is
always its own code `0xFF`. Two feature shapes result: **toggles**
(`0xFF`/`0x01`/`0x00`) and **valued** (a range within `0x00–0xFE`).

---

## 6. Wire ABI — verbs (`cdb[4]`)

Every command hijacks SCSI `READ BUFFER` (`0x3C`) behind an OEM-unused mode +
knock. OEM's `0x3C` dispatches modes `0x00..=0x0D` and rejects `>=0x0E`; the fleet
never uses `0x0E`, so freemkv's mode is collision-free and normal `READ BUFFER`
stays byte-identical.

### 6.1 CDB layout (10 bytes)
```
byte:  0     1     2  3     4      5         6       7   8      9
       3C    0E    C0 DE    VERB   FEATURE   STATE   <alloc16 BE>   (ctrl/val)
```
`DumpAll`/`FlashWrite` repurpose `cdb[5..9]` as a 32-bit address (FlashWrite puts
the value in `cdb[9]`). **`MIN_ALLOC_LEN = 64`** — HW-confirmed: the hijack aborts
data-in under ~16 bytes, so every builder floors the request at 64.
`RESP_MAGIC = "freemkv"`.

### 6.2 Verbs
| Verb | `cdb[4]` | Args | Touches | Reply | Status |
|---|---|---|---|---|---|
| **Identity** | `0x01` | — | — | magic + version + live state table | built |
| **Set** | `0x02` | feature, state | **RAM only** | ok/fail | built |
| **Get** | `0x03` | feature | reads RAM | state byte @ data[0] | built |
| **Reset** | `0x04` | **mode** `cdb[6]`: `0x00`=to-flash · `0xFF`=to-OEM | **RAM only** (never saves) | ok/fail | +mode byte |
| **Save** | `0x0B` | — | **writes flash** (config block, §8) | ok/fail | planned |
| **DumpAll** | `0x09` | addr32 | reads RAM | 64 bytes | built (diagnostic) |
| **FlashWrite** | `0x0A` | addr32, val | 1 byte → allowlisted scratch | status/`REFU` | temporary probe; subsumed by Save |

**Boot** is not a verb — it is the hook that calls `RESET(from-flash)` (§4).

---

## 7. Wire ABI — features (`cdb[5]`) and final encodings

| Feature | `cdb[5]` | Shape | `0xFF` OEM | `0x00` | `0x01` | `0x02–0xFE` |
|---|---|---|---|---|---|---|
| **Speed** | `0x01` | valued | OEM ramp | OFF — speed-control off (max/uncapped) | specific speed 1 | specific speed |
| **Region** | `0x02` | valued | drive's RPC logic | locked (nothing plays) | DVD region 1 | `0x01–0x08` DVD region 1–8 · `0x0A–0x0C` BD region A/B/C · `0x0F` region-free |
| **Uhd** | `0x03` | toggle | OEM decides | **No** — refuse UHD discs | **Yes** — accept UHD discs | — |
| **Bd** | `0x04` | toggle | OEM decides | **No** — refuse BD discs | **Yes** — accept BD discs | — |
| **Hrl** | `0x05` | toggle | enforce | **off** — ignore HRL (accept revoked) | **on** — enforce HRL | — |
| **Ake** | `0x06` | toggle | real handshake | **off** — bypass (pre-authenticated) | **on** — require handshake | — |
| **Bus** | `0x07` | toggle | as OEM | **off** — no bus encryption (de-bussed) | **on** — bus encryption | — |

**Reading the toggles:** for Uhd/Bd, `0x00`=No / `0x01`=Yes / `0xFF`=OEM ("does
this drive accept this disc type?"). For Hrl/Ake/Bus one polarity holds: `0x00` =
mechanism **off** (the unlock direction), `0x01` = **on**, `0xFF` = OEM. `0x01`
("on") is OEM-like in effect but stays a distinct value — never folded into `0xFF`.

---

## 8. Flash config block (SAVE target) — **planned**

The persistent store `SAVE` writes and `RESET(from-flash)`/boot read.

- **Format:** `magic` (validity marker → firmware detects empty/invalid ⇒ all-OEM)
  · `version` · **one raw state byte per feature** (`0x01..0x07`) · `checksum`.
  Fixed, small, forward-versioned. SAVE persists the raw byte, so a saved region or
  speed value survives — not just an on/off bit.
- **Location (confirmed safe):** inside the FlashWrite allowlist region
  **`0x1C4000–0x1D7000`** — non-CMAC (CMAC ends `0x1B001F`), clear of HRL
  (`0x1D8000`/`0x1E0000`) and per-unit calibration (`0x1F0000`), HW-proven writable.
- **Erase primitive — key open item.** `FlashWrite` only programs a byte into an
  already-erased cell (flash writes 1→0; needs an erase to reset to 1). `SAVE` must
  **erase-then-program**, needing an RE'd callable flash **erase** entry (near the
  PROGRAM routine `0x13da2a`). **Not yet confirmed — SAVE is blocked on it.**
- **Atomicity:** power loss mid-write must not brick. Rule: write payload first,
  **validity marker last** (or double-buffer two slots and flip the marker).

---

## 9. The two-layer API — bytes for the drive, words for humans

The wire ABI (§5–§7) is optimized for stability, not readability. **Users never
type hex** — the `freemkv-unlock` CLI speaks words and the mirror translates to the
state byte:

```
freemkv-unlock <dev> speed   max | off | oem | <N>
freemkv-unlock <dev> region  free | oem | locked | 1..8 | A|B|C
freemkv-unlock <dev> uhd     yes | no | oem
freemkv-unlock <dev> bd      yes | no | oem
freemkv-unlock <dev> hrl     off | on | oem
freemkv-unlock <dev> ake     off | on | oem
freemkv-unlock <dev> bus     off | on | oem
freemkv-unlock <dev> status                 # Identity → live table
freemkv-unlock <dev> save                    # persist to flash
freemkv-unlock <dev> reset   --to oem|flash
```

### 9.1 Default unlock profile (what `freemkv-unlock` applies for a normal rip)
| Feature | Setting | Byte |
|---|---|---|
| Speed | max | `0x00` |
| Region | free | `0x0F` |
| Uhd | yes (accept) | `0x01` |
| Bd | yes (accept) | `0x01` |
| Hrl | off (skip) | `0x00` |
| Ake | off (bypass) | `0x00` |
| Bus | off (de-bussed) | `0x00` |

The firmware supports **any** combination of feature values; the unlocker uses the
subset above by default. Full-combo exercise lives in the tester (§11).

---

## 10. Build & sign model
- **Signature-located, nothing hardcoded:** every patch site found by signature at build time; one builder covers MT1959 and MT1939. `create` applies every supported capability and reports each as a tri-state (applied / already-set / n/a / skipped); idempotent (`--audit` re-derives expected bytes).
- **Integrity:** re-compute the image **AES-CMAC** over affected regions with the known key. Mask-ROM→flash handoff and the OTFAD-sealed bank inherited unchanged.
- **Downgrade-enable:** DE byte (`0x1EC056 = 0xDE`) set on every build — HW-proven to install over any version.
- **Preserve per-unit calibration** (`rom_1F0000`, 64 KiB) across flash.
- **Principle:** call sealed AACS/VID routines **by entry address**; never reimplement or decrypt them.

### RE offset map (BU40N 1.0x — re-confirm per variant)
Flash PROGRAM `0x13da2a`; FlashWrite allowlist `0x1C4000–0x1D7000`; CMAC ends `0x1B001F`; HRL `0x1D8000`/`0x1E0000`; calibration `0x1F0000`. Raw reads: whitelist `FUN_0014282c` (body ≈ `0x142988`), raw bit `0x80`. Speed cap ≈ `0x01BB06`. Host-cert gates: `FUN_0014282c` deny `0x1429b2` flag `0x02000c6f`; `FUN_00148774` deny `0x14894c` flag `0x02000cdb`. Sealed AACS bank `0x11080–0x13fff` via hook `FUN_000ca74c`.

---

## 11. Gated read surface (opens with the auth gate)
All AACS-gated values ride `READ DISC STRUCTURE (0xAD, Media Type BD)` fmt `0x80–0x84` (16 B value + 16 B MAC). Once `Ake`=off stops enforcement the whole `0x80–0x84` namespace opens together; base codes + capacity + raw sectors open when the command filter drops.

| Value | Command + format | Gate |
|---|---|---|
| **Volume ID** | `0xAD` fmt `0x80` | AACS-Auth — per-title ROM-Mark, feeds `Kvu` |
| **PMSN** | `0xAD` fmt `0x81` | AACS-Auth — per-disc; on BD this **is** the BCA serial |
| **Media ID** | `0xAD` fmt `0x82` | AACS-Auth |
| **MKB** | `0xAD` fmt `0x83` / `/AACS/MKB_RO.inf` | filesystem (UDF file is practical source) |
| **RDK (bus key)** | `0xAD` fmt `0x84` | AACS-Auth — moot once `Bus`=off |
| **PIC/DI, capacity** | `0xAD` fmt `0x00`, `READ CAPACITY` | command-filter only |
| **Raw sectors** | `READ(10/12)` `0x28`/`0xA8` | command-filter (+ bus enc) |

VID = per-title ROM-Mark (key ladder); PMSN = per-disc BCA serial; MKB = open file — do not conflate.

---

## 12. Test oracle & migration checklist

**Combo tester:** `freemkv-private/tools/freemkv-fw-tester` (phase0 = ABI mechanics
+ each feature independently; phaseA = BD rip suite; phaseB = UHD) drives the ABI
through the `freemkv-unlock` mirror, declaring SET→RUN→EXPECT→REAL→PASS. Companion:
`fmkv-caps` (capability read-back), plan `freemkv-private/docs/FW_FEATURE_TEST_PLAN_1.7.2.md`.
*(Today it's per-feature + layered scenarios, not an exhaustive 3⁷ sweep — add a
full-matrix mode if we want total coverage.)*

**This spec diverges from current `abi.rs`/mirror; migrate in this order:**

| # | Touchpoint | Change | State |
|---|---|---|---|
| 1 | `freemkv-fw/src/abi.rs` (+ `abi_tests.rs`) | flip Hrl/Ake/Bus polarity (`0x00`=off); Speed `0x00`=max, `0x01–0xFE`=speed; Region `0x01–08`/`0x0A–0C`/`0x0F`=free; add `Save 0x0B`; RESET mode byte | ✅ **DONE** (tests green) |
| 2 | `freemkv-unlock/src/firmware/mod.rs` + `mod_tests.rs` (+ `freemkv/mod.rs` default profile) | mirror the above; update drift-guard pins; flip `full_unlock` recipe | ✅ **DONE** (310 tests green) |
| 3 | `freemkv-fw` engine handlers (`engine/mt1959_build.rs`) | boot hook → `RESET(from-flash)`; flip Hrl/Ake/Bus stub gates to `==STATE_OFF`; feature-gate codegen to new values; SAVE writer + erase (§8) | ⬜ **NEXT — do together** (firmware behavior) |
| 4 | `freemkv-fw-tester` + `fmkv-caps` | update EXPECT values to new polarity/encodings; add SAVE/RESET-mode + persistence phase | ✅ **DONE** (tester: 14 tests green; `fmkv-caps` needs no change) |
| 5 | `FW_FEATURE_TEST_PLAN_1.7.2.md` | re-state expected results | ⬜ pending |
| 6 | website `firmware-tools.md` (`marketing/` + `freemkv.github.io/`) | sync from the old subfunction model to this verb/feature ABI; both pages have drifted | ⬜ pending |

> **Progress note:** the *contract* (abi.rs → mirror → tester) is landed and green,
> uncommitted on `dev` (tester on `freemkv-private` branch
> `feat/kat-vid-negctl-capacity` — that repo has no `dev`). The **engine behavior**
> (#3) is intentionally held to do jointly. Until #3 lands, the tester's hardware
> phases encode the new contract but only pass on-drive after the engine flip.

### Open items (priority)
- [ ] **Runtime flash *erase* primitive** — blocks `SAVE` (§8).
- [ ] **Bus-enc AES apply-stage locus** — plaintext read path vs sealed hook (§7 Bus).
- [ ] **Migration §12** — implement in order across the six touchpoints.
- [ ] **Per-variant offset re-confirmation** — §10 map is BU40N 1.0x.
- [ ] **Close/scope-out** the ASUS-3.xx / CH12 / UH12 `create` errors.
- [ ] **MT1939-classic** boot-init HW confirm (promotes ~27 fail-closed → built).

---

## 13. What must change (inventory)

The locked spec (§4–§9) diverges from the shipped code in five concrete ways:
**(a)** three toggle polarities flip (`Hrl`/`Ake`/`Bus` unlock moves from `0x01`
→ `0x00`); **(b)** two valued features re-encode (`Speed` max `0x01`→`0x00`;
`Region` free `0x01`→`0x0F`, DVD `0x11–0x18`→`0x01–0x08`, BD `0x2A–0x2C`→
`0x0A–0x0C`); **(c)** two new verbs/behaviours (`Save 0x0B`; `Reset` gains a
`cdb[6]` mode); **(d)** boot changes from "write all-`0xFF`" to `RESET(from-flash)`;
**(e)** a new flash **erase→program** SAVE writer. `Uhd`/`Bd` do **not** change
(they already use `0x00`=refuse / `0x01`=accept). The row below is the migration
inventory; §14 is the how.

| # | Touchpoint | File(s) | Old (current) | New (locked) | Why |
|---|---|---|---|---|---|
| 1 | ABI source of truth | `crates/freemkv-fw/src/abi.rs` (+ `abi_tests.rs`) | `Verb` has no `Save`; `Reset` ignores feature/state; `Feature::Speed` doc `0x01`=max; `Region` doc DVD `0x11..=0x18`; `REGION_BD_A/_B/_C = 0x2A/0x2B/0x2C`; Hrl/Ake/Bus docs say `0x01`=unlock; no `REGION_FREE`; `build_reset_cdb()` no mode | add `Save = 0x0B`; `Reset` reads `cdb[6]` mode (`0x00`=to-flash / `0xFF`=to-OEM); Speed `0x00`=max, `0x01–0xFE`=cap; DVD `0x01–0x08`; `REGION_BD_A/_B/_C = 0x0A/0x0B/0x0C`; add `REGION_FREE = 0x0F`; Hrl/Ake/Bus `0x00`=off(unlock)/`0x01`=on; `build_reset_cdb(mode)` + new `build_save_cdb()` | `abi.rs` is the wire contract; every other crate mirrors it |
| 2 | Host mirror + drift-guard | `freemkv-unlock/src/firmware/mod.rs` (+ `mod_tests.rs`) | `SPEED_MAX = 0x01`; `REGION_DVD_BASE = 0x10`; `REGION_BD_A = 0x2A`; no `REGION_FREE`; no `Verb::Save`; `reset()` no mode; `skip_hrl/null_ake/bus_off` write `STATE_ON`; `region_free` writes `STATE_ON`; recipes arm `STATE_ON`; drift pins `0x2A`/`0x10`/`0x01` | `SPEED_MAX = 0x00`; `REGION_DVD_BASE = 0x00`; `REGION_BD_A = 0x0A`; add `REGION_FREE = 0x0F`; add `Verb::Save = 0x0B` + `save()`; `reset(mode)`; those three setters write `STATE_OFF`; `region_free` writes `REGION_FREE`; recipes flip; re-pin drift-guards | mirror MUST NOT drift from `abi.rs`; the pinned-value tests are the guard |
| 3 | Engine codegen | `crates/freemkv-fw/src/engine/mt1959_build.rs` (+ `engine/mod.rs` field docs) | HRL/AKE/BUS stubs gate on `==STATE_ON`; Speed stub treats `STATE_ON`=max; Region stub free=`STATE_ON`, DVD `0x11/0x19`, BD `REGION_BD_A`; `emit_boot_init`/`build_flag_reset` write `STATE_PASSTHROUGH` to all flags; RESET handler unconditional all-`0xFF`; no SAVE verb; no runtime erase | flip HRL/AKE/BUS stub gates to `==STATE_OFF`; Speed max at `0x00`; Region free at `REGION_FREE`, DVD `0x01/0x09`, BD `0x0A`; boot hook → `RESET(from-flash)` (read config block, fallback all-`0xFF`); RESET handler branches on `cdb[6]` mode; **new** SAVE (0x0B) writer + **new** runtime flash **erase** primitive | the firmware actually enforces the gates; boot/SAVE realise §4/§8 |
| 4 | Combo tester + caps | `freemkv-private/tools/freemkv-fw-tester/{main.rs,phases.rs}`; `fmkv-caps/*` | phase0/A/B arm HRL/AKE/BUS with `STATE_ON`; Region EXPECT `0x2A`/`0x11`; Speed A4 `STATE_ON`; no SAVE/RESET-mode/persistence phase; `main.rs` `Reset` has no `--to`; `fmkv-caps` read-only (no vendor encodings) | arm those with `STATE_OFF`; Region EXPECT `0x0A`/`0x01`, free `0x0F`; Speed max `0x00`; add SAVE + RESET-mode + power-cycle persistence phase; `main.rs` add `save` + `reset --to oem\|flash`; (optional) full-matrix mode; `fmkv-caps` unaffected | EXPECT values are the on-HW oracle; must match new encodings or every step false-fails |
| 5 | Test plan | `freemkv-private/docs/FW_FEATURE_TEST_PLAN_1.7.2.md` | cheat-sheet & phase tables use `SET 05/06/07 01`, Region `2A`/`11`, Speed `01`; "known no-op OFFs" note | restate SET/EXPECT to new polarity (`05/06/07 00`), Region `0F`/`01`/`0A`, Speed `00`; add SAVE + RESET-to-oem/flash + persistence rows | human oracle must agree with the wire |
| 6 | Marketing + docs sites | `marketing/src/content/docs/docs/firmware-tools.md` **and** `freemkv.github.io/src/content/docs/docs/firmware-tools.md` | `marketing`: verb/feature model but OLD encodings (Speed ON=`01`, Region free=`01`/DVD `11`/BD `2A`, HRL/AKE/Bus ON=`01`=unlock, "honesty note" OFF=no-op, no SAVE, no RESET-two-mode, no default profile). `github.io`: entirely OLD "sub-function / Raw Read" model (state at `cdb[5]`, 24-bit alloc `cdb[6..8]`, `0x03`=Region-free, `0x04`=Raw Read) | both: tri-state OEM/OFF/ON with **OFF = unlock** for Hrl/Ake/Bus, Speed `00`=max, Region `0F`=free / `01–08` DVD / `0A–0C` BD, add **Save** & **Reset --to oem\|flash**, add the default-unlock-profile table; `github.io` additionally needs the whole sub-function page replaced by the verb/feature ABI + 16-bit alloc at `cdb[7..9]` | user-facing hex/wording is now wrong; the two pages have themselves drifted apart |

### Biggest-risk deltas
- **Flash *erase* primitive (blocks SAVE).** `FlashWrite`/PROGRAM (`0x13da2a`) only
  programs `1→0` into already-erased cells; SAVE must **erase→program** the config
  block in the allowlist gap `0x1C4000–0x1D7000`. The erase entry is **not yet
  RE-confirmed** (a decoy erase routine at `0x8faa` shares PROGRAM's prologue) — §8
  open item. Until it lands, `Verb::Save` and the `RESET(from-flash)` boot path have
  no durable store to read/write.
- **Boot semantics flip.** Today boot = "write all-`0xFF`" (== `RESET(to-OEM)`).
  The spec's boot = `RESET(from-flash)`, which is a behavioural change **only once
  SAVE exists**; until then boot must keep emitting all-`0xFF` (empty/invalid flash
  ⇒ OEM, §4.2.4), so the boot stub and the "invalid config" fallback are the same
  code path and can ship first.
- **Silent-corruption polarity flips.** Hrl/Ake/Bus unlock moving `0x01`→`0x00`
  touches the mirror setters, the engine stub `cmp` immediates, the tester ARM
  bytes, the plan, and both sites simultaneously; a half-applied flip reads back
  fine over GET yet arms the OEM (locked) direction on hardware.

---

## 14. How to implement (per touchpoint)

Migrate strictly in dependency order — `abi.rs` → mirror+drift-guard → engine →
tester+caps → plan → both sites — so each layer builds on a green one below it.
Do **not** ship the polarity flip piecemeal: land steps 1–4 together (they share a
`cargo test` gate) before touching docs.

### 14.1 `abi.rs` (+ `abi_tests.rs`)
1. **`Verb` enum** (`abi.rs:139`): add `Save = 0x0B` after `FlashWrite` (`:163`).
   Extend the `Reset` doc (`:147–149`) to note it reads a **mode** at `cdb[6]`:
   `0x00`=to-flash, `0xFF`=to-OEM. Add `RESET_TO_FLASH = 0x00` / `RESET_TO_OEM =
   0xFF` consts.
2. **Region encodings** (`:238–244`): change `REGION_BD_A/_B/_C` from
   `0x2A/0x2B/0x2C` → `0x0A/0x0B/0x0C`; add `pub const REGION_FREE: u8 = 0x0F;` and
   `pub const REGION_DVD_BASE: u8 = 0x00;` (region N = `0x00 + N`, i.e. `0x01–0x08`).
3. **Feature docs** — rewrite the state legends to the locked poles:
   - `Speed` (`:178–182`): `0xFF`=OEM ramp; **`0x00`=off = max/uncapped**;
     `0x01–0xFE`=explicit speed. (Currently says `0x01`=max, `0x00`=floor.)
   - `Region` (`:183–188`): `0x00`=locked; **`0x01–0x08`=DVD 1–8**;
     **`0x0A–0x0C`=BD A/B/C**; **`0x0F`=free**. (Currently `0x01`=free, `0x11–0x18`.)
   - `Hrl` (`:206–212`): **`0x00`=off (skip, accept revoked)**, `0x01`=on (enforce),
     `0xFF`=OEM enforce. (Flip: skip was `0x01`.)
   - `Ake` (`:213–217`): **`0x00`=off (bypass/null)**, `0x01`=on (require), `0xFF`=OEM.
     (Flip: null was `0x01`.)
   - `Bus` (`:218–222`): **`0x00`=off (de-bussed)**, `0x01`=on, `0xFF`=OEM. (Flip.)
   - `Uhd` (`:189–197`) / `Bd` (`:198–205`): **unchanged** (`0x00`=No/refuse,
     `0x01`=Yes/accept already match); only reword to drop "reserved OFF" caveats
     where the spec now names them.
   - Header doc (`:13–28`): the boot line "writes `0xFF` into every flag" becomes
     "boot = `RESET(from-flash)`; empty/invalid flash ⇒ all-`0xFF`" (§4).
4. **Builders**: change `build_reset_cdb()` (`:290`) → `build_reset_cdb(mode: u8)`
   writing `mode` into `cdb[CDB_STATE]` (`cdb[6]`). Add `build_save_cdb()` →
   `build_cdb(Verb::Save, None, None, MIN_ALLOC_LEN)`.
5. **`abi_tests.rs`**: pin `Verb::Save as u8 == 0x0B` (`:14`); change the
   `REGION_BD_*` asserts `0x2A/2B/2C` → `0x0A/0B/0C` (`:39–41`) and add
   `REGION_FREE == 0x0F`; update `build_set_cdb(Feature::Region, REGION_BD_A)` to
   expect `0x0A` (`:69–71`); add a `build_save_cdb`/`build_reset_cdb(mode)` byte test.

### 14.2 Host mirror + drift-guard
1. **`mod.rs` consts** (`:92,95–99,103`): `SPEED_MAX = 0x00`; `REGION_BD_A/_B/_C =
   0x0A/0x0B/0x0C`; `REGION_DVD_BASE = 0x00`; add `pub const REGION_FREE: u8 = 0x0F;`.
2. **`Verb`** (`:108`): add `Save = 0x0B`; **`FirmwareControl`**: `reset()` (`:480`)
   → `reset(&mut self, mode: u8)` building `build_reset_cdb(mode)`; add `save()` →
   `build_save_cdb()`. Add `reset_to_oem()`/`reset_to_flash()` convenience wrappers.
3. **Typed setters** — flip the three unlock directions and the valued encodings:
   `skip_hrl` (`:541`), `null_ake` (`:545`), `bus_off` (`:549`) write `STATE_OFF`
   (not `STATE_ON`); `region_free` (`:553`) writes `REGION_FREE`; `unlock_speed`
   (`:569`) rides the new `SPEED_MAX = 0x00`; `force_region_dvd` (`:562`) rides the
   new `REGION_DVD_BASE = 0x00`.
4. **Recipes**: `arm_oem_bd` (`:582`) `Hrl → STATE_OFF`; `arm_oem_uhd` (`:591`) keep
   `Uhd = STATE_ON`, flip `Hrl`/`Bus → STATE_OFF`; `arm_bypass_bd` (`:601`) `Ake →
   STATE_OFF`; `arm_bypass_uhd` (`:609`) keep `Uhd`, flip `Ake`/`Bus`. Add an
   `apply_default_profile()` = Speed `0x00`, Region `0x0F`, Uhd `0x01`, Bd `0x01`,
   Hrl `0x00`, Ake `0x00`, Bus `0x00` (§9.1).
5. **`arm_stealth_oem`** (`:619`) becomes `reset_to_oem()` under the hood; keep the
   read-back verify.
6. **`mod_tests.rs` drift-guards**: add `Verb::Save == 0x0B` (`:10`); update
   `state_and_frame_constants_match_abi` — `SPEED_MAX == 0x00` (`:41`), `REGION_BD_*
   == 0x0A/0x0B/0x0C` (`:42`), `REGION_DVD_BASE == 0x00` (`:43`), add `REGION_FREE ==
   0x0F`. Fix the behaviour tests: `typed_setters_issue_expected_set_cdbs`
   (`:356–364`) now expects `Hrl/Ake/Bus = STATE_OFF`, `Region = REGION_FREE`,
   `force_region_dvd(2) = 0x02`, `Speed = 0x00`; the recipe tests (`:378–437`) flip
   to the new SET bytes; add a `save()`/`reset(mode)` CDB-and-mock test.

### 14.3 Engine codegen (`mt1959_build.rs`)
1. **Flip the three unlock gates** (immediate change in each stub's `cmp_imm`):
   - HRL-skip trampoline (`:2771–2772`): `cmp_imm(3, STATE_ON); beq(clean)` →
     `cmp_imm(3, STATE_OFF)` — force the clean/skip path when `flag[Hrl]==0x00`.
   - AKE accept stubs — `build_ake_stub` (`:2233`), `build_ake_stub_nb` (`:2261`),
     `build_ake_stub_classic` (`:2590`), and the VID null-read stub (`:2926`): each
     `cmp_imm(2, STATE_ON)` → `cmp_imm(2, STATE_OFF)` (null AKE at `0x00`).
   - Bus-off stub `build_busenc_stub` (`:2330–2331`): `cmp_imm(3, STATE_ON);
     bne(skip)` → `cmp_imm(3, STATE_OFF)` (clear `BUSENC_ENABLE_BIT` at `0x00`).
   Update every `flag[..]==STATE_ON` doc-comment (and `engine/mod.rs:120` +
   `flag[RawRead]==3` legacy notes) to `==STATE_OFF` in lockstep.
2. **Speed stub** `build_speed_stub` (`:2044–2099`): the "unlimited" arm compares
   `STATE_ON` (`:2063`, and the r0-variant `:2089`); change both to `STATE_OFF`
   (`0x00`=max). Non-`0x00`/non-`0xFF` bytes remain the literal cap, so the cap path
   is already `0x01–0xFE` — only the max sentinel moves.
3. **Region stub** `build_region_stub` (`:2148–2158`): free arm `cmp_imm(3,
   STATE_ON)` → `cmp_imm(3, REGION_FREE)` (`0x0F`); keep locked at `STATE_OFF`; DVD
   range `cmp_imm(3, 0x11)`/`0x19` → `0x01`/`0x09`; BD range `cmp_imm(3,
   REGION_BD_A)` picks up `0x0A` and `REGION_BD_C + 1` → `0x0D` automatically once
   the consts change. **Watch the overlap:** DVD `0x01–0x08` now collides with the
   toggle `STATE_ON = 0x01` numerically — Region is a valued feature so this is fine,
   but the stub must test `REGION_FREE`/locked/DVD/BD ranges explicitly (it already
   does) and never fold Region through the generic ON path.
4. **`Uhd`/`Bd` stubs unchanged** — `build_uhd_stub*` (`:2393,2494–2497`) keep
   `STATE_ON`=accept / `STATE_OFF`=refuse; `build_bd_stub` (`:2542`) keeps refuse at
   `STATE_OFF`. No edit; only confirm the KAT still matches.
5. **Boot hook → `RESET(from-flash)`** (`emit_boot_init` `:3023`, `build_flag_reset`
   `:2975–2994`): today the boot stub writes `STATE_PASSTHROUGH` into every flag.
   New boot stub must (a) read the flash **config block** (§8) from the allowlist
   region, (b) validate `magic`/`checksum`, (c) on valid, copy the 7 saved state
   bytes into `FLAG_TABLE_BASE+0x01..=0x07`, (d) on empty/invalid, fall back to the
   existing all-`0xFF` write. Ship (d) first (identical to current behaviour) so the
   boot path is spec-shaped before SAVE exists. Keep the `BootInitSite::
   ClassicUnconfirmed` fail-closed gate.
6. **RESET handler mode byte** (`:1866–1879`): the dispatch currently writes
   `STATE_PASSTHROUGH` unconditionally after `cmp_imm(4, Verb::Reset)`. Add a
   `cdb[6]` (`CDB_STATE`) test: `0xFF` → the existing all-`0xFF` sweep; `0x00` →
   re-run the boot config-load path (reload saved table). RAM-only either way (§4.2).
7. **SAVE verb (`0x0B`)** — new dispatch arm alongside `FlashWrite` (`:1897`): serialise
   `magic + version + flag[0x01..=0x07] + checksum` and **erase→program** it to the
   config block at `FLASHWRITE_ALLOW_LO` (`0x1C4000`). Reuse the PROGRAM routine
   recovered by `find_flash_program` (`0x13da2a`), the allowlist bound check
   (`:251–257`), and `emit_be_word_to_response` for the ok/fail reply.
8. **Runtime flash *erase* primitive — the one hardware-unproven blocker.** PROGRAM
   only clears bits (`1→0`) into an already-erased cell, so SAVE cannot rewrite the
   block without an **erase-to-`0xFF`** step first (§8). The engine must RE-recover a
   callable erase entry near PROGRAM (`0x13da2a`) — distinct from the **decoy erase
   routine at `0x8faa`** that shares PROGRAM's prologue (`FLASH_PROGRAM_SIG`,
   `:177–185`) — and prove it on a sacrificial drive against the safe gap
   `0x1C4000–0x1D7000`. Until that lands, gate SAVE off (like `HRL_WIPE_ARMED`,
   `:707`): the serialiser/record codegen can exist and be unit-tested, but no image
   ships the SAVE detour and boot stays on the all-`0xFF` fallback.

### 14.4 Combo tester + `fmkv-caps`
1. **`phases.rs` ARM/EXPECT** — flip the unlock features to `STATE_OFF` and re-encode
   the valued ones:
   - `phase0` 0.5 arm-all (`:235–241`): `Hrl/Ake/Bus` from `STATE_ON` → `STATE_OFF`
     (Speed/Region/Uhd non-OEM values too — see below); Bd stays `STATE_OFF`.
   - `phase_a`: A1/A2 `Hrl` (`:275,320`), A3 `Ake` (`:349`), A6 `Bus`+`Hrl` (`:407`)
     → `STATE_OFF`. A4 Speed (`:377`) `STATE_ON` → `0x00` (max). A5 Region-free
     (`:386`) `STATE_ON` → `REGION_FREE` (`0x0F`). A5b (`:390–403`): `REGION_BD_A`
     now `0x0A`, `REGION_DVD_BASE + 1` now `0x01`; EXPECT string "`0x2A` then `0x11`"
     → "`0x0A` then `0x01`". A8 BD tri-state (`:446–481`) unchanged (`STATE_ON`/
     `STATE_OFF` already correct).
   - `phase_b`: B2/B3 `Hrl`/`Bus` (`:526,559–562`), B4 `Ake`/`Bus` (`:589–595`) →
     `STATE_OFF`; keep `Uhd = STATE_ON`. B6 UHD tri-state unchanged.
   - The `import` list (`:16–19`) needs `REGION_FREE` added (and any renamed const).
2. **New phases**: add a `SAVE`/`RESET-mode` phase (SET a non-OEM profile → `save()`
   → power-cycle the drive → re-open → GET all seven == the saved values, proving
   §4/§8 persistence) and a `RESET --to flash`/`--to oem` pair. This is the only
   part that exercises the new verbs end-to-end and the erase blocker.
3. **`main.rs`**: add a `save` subcommand and give `Reset` (`:74,157,295`) a `--to
   oem|flash` arg wired to `reset(mode)`. `parse_state_byte` (`:349`) stays raw-hex
   (encoding-agnostic — no word table to change).
4. **Full-combo (matrix) mode** — optional but recommended (§12): today the tester is
   per-feature + layered scenarios, not a 3⁷ sweep. Add an opt-in `--matrix` that
   iterates the independent state domains and GET-verifies each, to catch encoding
   regressions the scripted phases miss.
5. **`fmkv-caps`** — **no encoding change**: it is read-only and never issues a
   freemkv vendor SET/GET; its "Read Speed" row uses the stock MMC `Drive::set_speed`
   (`speed.rs:44`), not `Feature::Speed`. Leave as-is; only re-verify its prose if it
   references the old polarity.

### 14.5 Test plan (`FW_FEATURE_TEST_PLAN_1.7.2.md`)
Restate the cheat-sheet (`:36–41`) and phase tables to the new wire: `SET 05 00`/
`SET 06 00`/`SET 07 00` for Hrl/Ake/Bus unlock (was `01`); Region `SET 02 0F` free,
`SET 02 01` DVD-1, `SET 02 0A` BD-A (was `01`/`11`/`2A`); Speed `SET 01 00` = max
(was `01`). Update 0.5 (`:80`), A1–A6 (`:89–97`), A5b EXPECT (`:96`), B1–B4
(`:109–113`). Drop/replace the "known no-op OFFs" note (`:47–50`) — under the new
polarity `0x00` **is** the unlock direction for Hrl/Ake/Bus, so the caveat now
applies to the OEM (`0x01`/`0xFF`) side, not OFF. Add plan rows for `SAVE` +
`RESET --to oem|flash` + the power-cycle persistence check.

### 14.6 Both website docs (human copy, not hex-first)
Frame these as user-readable capability copy; put the raw CDBs in the reference
block only. **Both** pages need the same target; note they have drifted from each
other, so they are not a copy-paste of one diff.

- **`marketing/…/firmware-tools.md`** (already verb/feature-shaped, OLD encodings):
  - Feature table (`:234–240`) and the "what each feature does" prose (`:270–294`):
    Speed `00`=max/uncapped (`01–FE`=cap); Region `0F`=free, `01–08`=DVD, `0A–0C`=BD
    (drop `01`/`11`/`2A`); Hrl/Ake/Bus **`00`=the unlock** (skip / null / de-bussed),
    `01`=on (OEM-like), `FF`=OEM.
  - Verb table (`:216–222`): add **Save `0x0B`** ("persist the live feature table to
    flash"); give **Reset** the two modes (`--to oem` / `--to flash`, `cdb[6]`).
  - Replace the "Honesty note — some OFFs are OEM-equivalent no-ops" paragraph
    (`:250–255`): OFF is now the working unlock direction for Hrl/Ake/Bus.
  - Add the **default unlock profile** table (§9.1) and a `save`/`reset --to` row to
    the CLI examples (`:363–402`).
- **`freemkv.github.io/…/firmware-tools.md`** (entirely OLD "sub-function" model):
  a larger rewrite — replace the whole `Sub-function table` / "Raw Read" / 24-bit
  alloc content (`:172–324` region) with the verb/feature ABI: verbs
  Identity/Set/Get/Reset/**Save**/DumpAll at `cdb[4]`, feature at `cdb[5]`, state at
  `cdb[6]`, **16-bit** alloc at `cdb[7..9]` (it currently documents state at `cdb[5]`
  and 24-bit alloc at `cdb[6..8]`). Then apply the same feature/state encodings as
  marketing. Fold "Raw Read (`0x04`)" into the `Ake`=off (+ `Bus`=off) feature story;
  drop the "sub-functions `0x05–0x08` reserved" block (those are real features now).
- **Cross-page drift to reconcile:** the pages disagree on the frame (`cdb[5]`
  state + 24-bit alloc on `github.io` vs `cdb[6]` state + 16-bit alloc on marketing),
  the capability list (`github.io` "Region-free / Raw Read" vs marketing's seven
  features), the `n/a` example ("Raw Read on a DVD-only drive" vs "UHD on a DVD-only
  drive"), and the Identity reply (marketing adds "+ state table"). Converge both on
  the marketing structure, then apply the new encodings so they end identical.
