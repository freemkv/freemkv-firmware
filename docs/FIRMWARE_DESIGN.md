# freemkv firmware (`fmkvfw`) — design spec

> **Status:** v0.1 draft — feature list and gate model. Offsets are from the
> working reverse-engineering map of an LG `HL-DT-ST BD-RE BU40N` (rev 1.0x,
> MediaTek MT19xx) and **must be re-confirmed per firmware variant** before use.
> This document describes *authoring* (X→Y modification) and is the companion to
> `freemkv-flash`, which only **transports** an image to/from the drive.

---

## 1. Scope and non-goals

`fmkvfw` is a modified drive-controller firmware that removes the drive-side
**transport / access-control policing** so that ordinary host software can read a
protected disc. It is the firmware counterpart to the transport-unlock class of
custom firmware.

**In scope — the drive-side gates we open:**

1. Raw / untruncated sector reads (no drive-side descramble, full capacity).
2. Read-speed / riplock removal.
3. Host-certificate approval (stop enforcing the AACS drive–host AKE + host
   revocation list).
4. Bus-encryption neutralization (return sectors in the clear on the bus).
5. Exposure of the protected read surface (Volume ID, and the other gated
   values in §6) without a compliant authenticated session.

**Explicitly NOT in scope — the content layer:**

- **We do not decrypt AACS content.** The drive never descrambles the AACS
  payload; it hands out AACS-ciphertext sectors. MKB → Media Key →
  `Kvu = AES-G(Km, VID)` → title keys → AES-CBC content decrypt is done entirely
  in **host software** (libfreemkv), unchanged by this firmware.
- We touch **transport/auth policy only**. Conflating the two layers is the most
  common mistake in this space; keep them separate at all times.

---

## 2. The two-layer model (why the bypass is "cheap")

There are two independent cryptographic layers on a protected Blu-ray:

| Layer | What it protects | Who removes it |
|---|---|---|
| **Content encryption** (AACS proper) | The `.m2ts` payload, AES-128-CBC under title/unit keys | **Host software** — never the drive |
| **Transport / access control** | Gates the VID + protected values behind a drive–host AKE; optionally wraps sectors in a second AES layer on the bus ("bus encryption") | **This firmware** |

The values we want (VID etc.) are **not encrypted at rest** — they are plaintext
values living in a physically privileged region (the ROM-Mark; see §6) that the
drive *refuses to surface* without a valid, unrevoked host certificate. The
barrier is **firmware policy, not physics or at-rest crypto**: the silicon can
already read those regions. Field evidence: a documented firmware hack patched a
**single** authentication-validation branch and the drive then returned the VID
**in the clear, no auth, no encryption**. That one-branch result is the whole
thesis of this design — most gates are a policy flag-flip, not a crypto break.

---

## 2a. Delivery model — single firmware, CDB-activated, zero blobs

**Decision: one self-contained flashed image per model, OEM-identical until a
vendor CDB activates it. All feature code is baked into the image. No runtime
blob upload. No per-drive profile database.**

Contrast with the transport-unlock firmware class, which is a **two-stage**
design: a flash-resident image that is OEM-identical until a vendor CDB enables
an extra command, *plus* a **runtime microcode blob uploaded into drive RAM every
session** to do the actual unlock. Because that RAM blob targets model-specific
addresses, that design needs **~200 per-model blobs** (a `profiles.json`-style
database). That two-stage shape exists for *its* constraints — one host tool
covering a large drive fleet **without** redistributing or flashing per-model
firmware. It keeps the drive unmodified on flash (RAM-only unlock).

**freemkv does not share those constraints.** We already flash per-model
(`freemkv-flash`), so we fold the per-model work into the **build**, not the
runtime:

| | Transport-unlock class | **freemkv (`fmkvfw`)** |
|---|---|---|
| Flashed image | OEM + activation CDB only | OEM + **all feature code baked in** |
| Runtime unlock | RAM blob uploaded each session | **none** — code already resident |
| Per-model handling | ~200 runtime blobs (`profiles.json`) | **N flashed images**, one per model, each self-contained (offsets compiled in at build time) |
| Activation | vendor CDB | vendor CDB (same idea) |

The 200-blob runtime database collapses to "N flashed images, each
self-contained." The per-model address differences that a RAM blob resolves at
runtime are resolved **at build time** instead.

### Why not literally one image for all MT1959 drives — "same chip, different firmware"

The 2 MB image is two parts glued together:

- **Chipset-generic logic** — SCSI/USB command dispatch, the AACS/auth path,
  riplock, raw-read handling. This is the MT1959 SoC part and is **largely shared
  across every MT1959 drive.** *This is the only part `fmkvfw` modifies.*
- **Per-model mechanism code + data** — servo/DSP tuning for the specific optical
  pickup, spindle/sled/focus/tracking loops, calibration tables,
  `speed_zone_table`/`speed_calc_table`, INQUIRY identity, per-batch fixes (the
  1.00→1.04 revs). **Differs per model because the physical mechanism differs** —
  a BU40N and a WH16NS60 have different pickups/motors even though both are
  MT1959. Flashing one model's servo params onto another mechanism bricks it.

So "one firmware per chipset" is true **only at the level we touch**:

> **`fmkvfw` = [model X's own stock image] + [one shared chipset-wide
> activation+feature patch] = X++ after the activation CDB.**

We **inherit X** (the per-model servo/mechanism/calibration — never rewritten,
preserved byte-for-byte) and we **own the `++`** (one shared patch-set,
retargeted to each model's offsets at build time). "1 MTK firmware" = **one
codebase of modifications**, not one literal image. `X → X++` (OEM-behaving until
the activation CDB) holds per model.

This is exactly why the transport-unlock class delivers `++` as a RAM overlay —
so it rides on top of any model's mechanism firmware without touching servo code.
Their "one shared microcode" *is* this "1 MTK firmware" concept; we bake it into
each model's image at build time rather than inject at runtime. The premise —
that `++` is chipset-generic and only the per-model *addressing* differs — is what
the runtime-blob corpus lets us validate (shared loader/scaffolding + small
per-model constants; the encrypted payload's *shape*, not its instructions, which
still need a live RAM dump).

### Why keep the CDB activation gate (vs. always-on)
1. **Stealth / safety.** Until activated, the drive is behaviorally identical to
   OEM — normal players and drive self-tests see a stock drive; nothing unlocks
   unless freemkv explicitly asks. Avoids breaking ordinary playback / other
   software.
2. **It reuses the handshake libfreemkv already speaks.** The unlock path already
   has `unlock_init_value` / `unlock_response_size` / `*_cdb` fields — our
   activation CDB *is* that handshake, host-side unchanged. And `fmkv-caps`'
   "LibreDrive runtime: Yes/No" row already detects whether activation
   succeeded, so the tester exercises this gate for free.

### Activation flow
```
vendor activation CDB  ->  free-space handler sets in-RAM `unlocked` flag
                       ->  handler fills response buffer (magic + version)
feature gates (§3) all check `unlocked` before applying:
   1 host-cert approve   2 VID release   3 bus-enc AES no-op
   4 raw reads           5 speed / riplock
```
All of this is **plaintext patch + free-space code + re-CMAC** — the encrypted
1 KB stage-1 is never touched or replaced.

### Honest scope line
The **framework** (single image, CDB flips a flag, features gate on it) is the
easy, decided part. Of the five features, **speed (#5) and raw reads (#4) are
well-understood**; **host-cert-approve (#1) and VID-release (#2) are the
frontier** — they require calling the drive's *sealed* AACS/VID routines by entry
address at the right moment (§4.3, §9), not yet proven on hardware. This delivery
model doesn't change that difficulty; it gives those two a clean place to live.

---

## 3. Feature list — the five gates

| # | Gate | Mechanism class | Location | Status |
|---|---|---|---|---|
| 1 | Raw reads (untruncated, no descramble) | opcode whitelist + format register | **plaintext-patchable** | mapped |
| 2 | Read speed / riplock | speed-cap constant | **plaintext-patchable** | mapped |
| 3 | Host-cert approval (skip AKE + HRL) | policy deny-branch flip | **plaintext gate → sealed path** | mapped (flags) |
| 4 | Bus-encryption neutralize | read-path AES stage → no-op | **TBD (plaintext vs sealed)** | **design fixed (§5); locus to confirm** |
| 5 | Protected read surface (VID/PMSN/…) | consequence of #3 + filter drop | mixed | partial (§6) |

### Working offset map (BU40N 1.0x — re-confirm per variant)

- **Raw reads:** opcodes `0xAD` / `0xC0` whitelist at `FUN_0014282c` (whitelist
  body ≈ `0x142988`); raw-sector format via the sector-format hardware register
  on the stock read path (internal raw bit `0x80`).
- **Riplock/speed:** stock-1.00 speed cap near `0x01BB06`.
- **Host-cert policy gates (flag-flip candidates):**
  - gate 1 — `FUN_0014282c`, deny branch at `0x1429b2`, flag `0x02000c6f`
  - gate 2 — `FUN_00148774`, deny branch at `0x14894c`, flag `0x02000cdb`
- **Sealed AACS/VID/bus-enc:** OTFAD-sealed bank `0x11080–0x13fff`, reachable in
  plaintext only via the hook `FUN_000ca74c`. The **key derivation** and cert
  crypto are sealed; the **enforcement decision** appears to be a plaintext flag
  check we can flip (gates above).

**Key architectural principle:** *call the sealed routines by their entry
addresses; do not reimplement or decrypt them.* Free-space code can invoke the
sealed AACS/VID/descramble entry points directly without ever reading their
plaintext. We open gates and re-route calls; we never need the sealed bank's
cleartext.

---

## 4. Per-gate detail

### 4.1 Raw reads
Stock firmware truncates reported capacity below the UHD threshold
(~25,000,000 sectors ≈ 50 GB) and de-scrambles/limits sector reads. The read
handler already contains a raw path (re-spoof to `READ(12)` `0xA8`, set internal
raw bit `0x80`, program the sector-format register for full raw sectors). Gate =
ensure the vendor/raw opcodes reach that path (opcode whitelist) and that
capacity is reported untruncated. **Plaintext-patchable.**

### 4.2 Read speed / riplock
A speed-cap constant throttles video-sector reads for playback smoothness —
unrelated to AACS. Patch the constant. **Plaintext-patchable.** (Do not confuse
this with any security gate.)

### 4.3 Host-certificate approval
Stock firmware runs the AKE: verifies the host cert's AACS-LA signature and
checks the Host ID against the disc's revocation list (HRL), aborting on failure.
We force the enforcement decision to "approved" so any/no host cert proceeds and
the HRL check can never reject — which also means the drive can never be
"revoked" by a newer disc. The signature/crypto stays sealed and untouched; we
flip the **plaintext policy flag** guarding it (gates 1/2 above). This is the
one-branch result from §2.

### 4.4 Bus encryption — see §5 (design fixed).

### 4.5 Protected read surface
Once §4.3 stops withholding, the drive will emit the VID (and, behind the same
AKE or the command filter, the other values in §6) on request. Re-enable any
vendor/raw read opcodes the stock ATAPI command filter blocks.

---

## 5. Bus encryption — design decision

**Chosen approach: no-op the AES (leave the advertised capability alone).**

Bus encryption is **opt-in and negotiated per session** — it only activates when
the drive cert, host cert, and disc content cert all set their bus-enc flag *and*
the AKE derives the Read Data Key (RDK) that does the AES-CBC sector wrapping. If
the drive never reaches that state, `READ(10)` returns sectors **unwrapped**
(plaintext-on-bus AACS-ciphertext), and reads work normally.

Two candidate mechanisms were considered:

1. **Clear the capability bit** — rejected. The bus-enc capability lives in the
   **AACS-LA-signed drive certificate**; flipping the bit invalidates the
   signature.
2. **Force the read-path encrypt stage to identity (no-op the AES)** — **chosen.**
   The drive keeps *advertising* bus-enc (cert untouched, signature intact), but
   the per-sector AES-CBC step over the 2032-byte body is replaced with a
   pass-through. A host that believes bus-enc is active still receives plaintext.

**Why (2):** robustness. Software that assumes returned sectors are bus-encrypted
(because the drive still advertises the capability) will nonetheless read correct
plaintext — no host-side special-casing required. It also avoids touching the
signed certificate at all.

**Open item — locus of the AES stage.** The sector-encrypt step is a bulk
hardware-AES operation on the read DMA path; the **RDK derivation** is sealed in
the OTFAD bank, but the **apply/enable** of the AES over a sector is likely a
plaintext register/flag on the read path. Confirm against the firmware map
whether the no-op can be done in the plaintext read path (preferred — a register
write or a branch to skip the AES stage) or whether it requires re-routing
through the sealed hook `FUN_000ca74c`. This is the single most important thing
to pin before implementing gate 4.

---

## 6. The gated read surface (what else opens with the gate)

Opening §4.3 + dropping the command filter exposes more than the VID. The tester
(`fmkv-caps`) should read **all** of these back to prove MK↔OEM parity.

All the AACS-gated values ride **`READ DISC STRUCTURE` (`0xAD`, Media Type BD =
`0001b`)** with an **AACS-extension format code** in the `0x80–0x84` namespace,
each returned 16 B value + 16 B MAC over the AKE bus key. The base BDA format
codes (`0x00–0xFF`) are a *separate* namespace and are not AACS-gated.

| Value | Command + format | Gate | Notes |
|---|---|---|---|
| **Volume ID (VID)** | `0xAD` fmt **`0x80`** (16B+MAC) | AACS-Auth | per *title*, ROM-Mark; plaintext at rest; feeds `Kvu`. **Confirmed.** |
| **PMSN** | `0xAD` fmt **`0x81`** (16B+MAC) | AACS-Auth | per *disc*, unique. On BD this **is** the BCA serial — there is **no base `0x03` BCA code** on BD (unlike DVD). Per-disc identifier — gate behind a flag in the tester's default output. |
| **Media ID** | `0xAD` fmt **`0x82`** (16B+MAC) | AACS-Auth | enhanced/online/managed content. |
| **MKB** | `0xAD` fmt **`0x83`** *or* `/AACS/MKB_RO.inf` | **open** (filesystem) | drive path is AGID-gated + slow (~10 s); the UDF file is the practical source. Useless without the VID. |
| **Read/Write Data Key** (bus key) | `0xAD` fmt **`0x84`** | AACS-Auth | the RDK that does bus-enc; **moot** once §5 no-ops the AES. |
| **PIC / DI** (type, layers, capacity) | `0xAD` fmt **`0x00`** (4100 B) | **command-filter only** (not AACS) | disc type, layer count, true capacity. |
| **Bus-enc state** | `GET CONFIG 0x46`, AACS feature `0x0010` | open | tells you whether the drive intends to bus-encrypt — a good tester probe. |
| **Content Cert / CRL / Hash Table** | UDF files in `/AACS/` | open (needs raw read) | `Content000.cer`, `ContentHash000.tbl`, `CPSUnit*.cci`. |
| **Full/untruncated capacity** | `0xAD` fmt `0x00`; `READ CAPACITY 0x25`/`0x9E` | command-filter (UHD truncation) | see §4.1. |
| **Raw sectors / data zone** | `READ(10/12)` `0x28`/`0xA8` | command-filter (+ bus enc) | see §4.1. |

Everything in the `0x80`–`0x84` AACS namespace opens together once §4.3 stops
enforcing the AKE (the drive approves any host); the base codes + capacity + raw
sectors open when the command filter is dropped (§4.1). So the two firmware gates
(§4.3 approve-any-host, §4.1 drop-filter) between them expose this **entire**
table — no value needs its own dedicated gate.

> **Note — Binding Nonce** is a BD-R/RE managed-copy concern (AGID + LBA/len, no
> fixed format byte), not part of the BD-ROM rip surface; ignored here.

**VID vs PMSN vs MKB — do not conflate:** VID = per-title, ROM-Mark, feeds the
key ladder. PMSN = per-disc, BCA, a serial. MKB = an open filesystem file. Some
secondary sources loosely say "VID may be in the BCA" — that is a conflation;
authoritative placement is VID→ROM-Mark, PMSN→BCA.

---

## 7. Build & sign model (summary)

- **Base:** the stock 2 MB image for the target model. We modify in place; we do
  not author from scratch and we do not need the sealed bank's plaintext.
- **Toolchain:** `arm-none-eabi-gcc` compiles new C into a small `.o`; `armips`
  takes the stock image + the `.o` + a small `.asm` patch script and emits the
  patched 2 MB image.
  - **Case A** — retarget a call: rewrite 2–4 bytes in the base image (branch a
    stock call at a gate to "approved"/to the sealed entry we want).
  - **Case B** — overlay new code in free space and rewrite a branch to point at
    it (for logic that doesn't fit a 2–4-byte edit).
- **Integrity:** the image carries an AES-CMAC over defined regions. After
  patching we **re-compute the CMAC** over the affected region(s) so the image
  passes the firmware's own integrity check. (The mask-ROM → flash handoff and
  the OTFAD-sealed bank are inherited unchanged.)
- **Layout:** scatter/region table preserved; pad to 2 MB. Per-unit calibration
  (`rom_1F0000`, 64 KiB) is per-drive and must be preserved across flash — it is
  never part of an authored image.

---

## 8. Test oracle

Functional proof uses a real disc and freemkv rip as the oracle, driven by the
read-only capability tester:

- **`fmkv-caps <dev>`** prints the capability matrix (LibreDrive, Host Cert, Bus
  Encryption, Read Speed, Raw Reads, Volume ID [+ PMSN/BCA as §6 lands]). Built
  on libfreemkv; issues no writes.
- **MK↔OEM round-trip** (each flash is irreversible, mandatory pre-flash backup):
  1. `fmkv-caps` on the MK-flashed drive + protected disc → expect all gates open.
  2. `freemkv-flash flash` to stock OEM (backup first) — irreversible flash #1.
  3. `fmkv-caps` on OEM, same disc → expect every row to flip (enforced/off).
     This is the proof-of-difference artifact.
  4. `freemkv-flash flash` back to MK (backup first) — irreversible flash #2.
  5. `fmkv-caps` again → matrix returns to baseline; closes the loop.

As each `fmkvfw` gate is implemented, its row in `fmkv-caps` is the pass/fail
gate for that feature — the firmware build is TDD'd against the tester.

---

## 9. Open questions / research status

- [ ] **Gate 4 locus** — is the bus-enc AES apply-stage no-op-able in the
  plaintext read path, or only via the sealed hook? (§5) — *highest priority.*
- [x] **PMSN/BCA/PIC command detail** — resolved (§6): all AACS values via
  `0xAD` fmt `0x80–0x84`; BD has no BCA code (BCA serial = PMSN `0x81`); PIC/DI =
  `0xAD` fmt `0x00` (command-filter only). Both firmware gates expose the lot.
- [ ] **Per-variant offset re-confirmation** — the §3 map is BU40N 1.0x; every
  offset must be re-derived for any other variant before flashing.
- [ ] **Gate flags 1/2 validation** — confirm flipping `0x02000c6f`/`0x02000cdb`
  yields VID release with no other side effects, on hardware.
