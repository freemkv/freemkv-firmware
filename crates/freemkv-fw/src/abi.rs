//! The freemkv vendor-command ABI — the single source of truth for the wire
//! frame, owned by freemkv-fw (the tool that controls the firmware). The only
//! other place this ABI lives is the freemkv-unlock host crate, which mirrors
//! it (and wraps it in an ergonomic `FirmwareControl` API); the neutral flasher
//! (freemkv-flash) knows nothing about it.
//!
//! A freemkv command is a **hijack of the standard SCSI `READ BUFFER` (`0x3C`)
//! command**, discriminated by an OEM-unused mode. `READ BUFFER` is chosen
//! because it is a standard opcode the USB/UAS bridge passes through unmodified
//! (a bare vendor opcode is rejected by the bridge with `DID_ERROR`), and it
//! returns data through an existing DMA path.
//!
//! # Grammar: `verb [feature] [state]`
//!
//! The command surface is a small set of **verbs** operating on a flat namespace
//! of **features**, each holding a **state**. Every feature flag is a uniform
//! **tri-state**: [`STATE_PASSTHROUGH`] (`0xFF`, OEM — the firmware does not touch
//! that subsystem), [`STATE_ON`] (`0x01`, feature armed/active), and [`STATE_OFF`]
//! (`0x00`, feature actively disabled — real capability off). Some features layer
//! richer states on top (an explicit Speed cap byte, the Region force-region
//! block), but the three canonical values mean the same thing everywhere.
//!
//! At power-on the drive's SRAM flag table reads all-`0x00`, which under this
//! grammar would mean "every feature OFF". The firmware's always-on boot-init hook
//! therefore writes [`STATE_PASSTHROUGH`] (`0xFF`) into every flag at boot, so a
//! freshly powered drive is byte-behaviour-identical to OEM until the host changes
//! a flag — the invariant that keeps a flashed drive stealthy. [`Verb::Reset`]
//! with [`RESET_TO_OEM`] returns every feature to passthrough (the same all-`0xFF`
//! state); with [`RESET_TO_FLASH`] it reloads the saved flash config block instead.
//!
//! ```text
//!   cdb[0]    = 0x3C  (READ BUFFER)          ← standard opcode; bridge-safe
//!   cdb[1]    = 0x0E  (KNOCK_MODE)           ← OEM's jump table rejects modes >= 0x0E
//!   cdb[2..4] = KNOCK (or DEBUG_KNOCK)       ← defence-in-depth signature
//!   cdb[4]    = Verb                         ← IDENTITY / SET / GET / RESET / DUMPALL
//!   cdb[5]    = Feature id                   ← SET/GET only (else 0)
//!   cdb[6]    = State byte                   ← SET only (else 0)
//!   cdb[7..9] = allocation length (16-bit big-endian)  ← data-returning verbs
//!   cdb[9]    = control (0)
//! ```
//!
//! [`Verb::DumpAll`] is the one exception to the field layout: it carries a 32-bit
//! RAM address big-endian in `cdb[5..9]` (no feature/state/alloc), and the handler
//! always commits a fixed [`MEMREAD_LEN`]-byte window.
//!
//! The full discriminator is the 4-byte prefix `READ_BUFFER_OPCODE || KNOCK_MODE
//! || KNOCK` (or `... || DEBUG_KNOCK` for the debug-only verbs): a standard
//! opcode plus the OEM-unused mode plus the two-byte knock. OEM's `0x3C`
//! handler rejects mode `0x0E` at its own jump-table bound, so the knock bytes
//! never confuse it; the freemkv handler intercepts mode `0x0E` and tail-calls
//! the original handler for every other mode, leaving OEM `READ BUFFER`
//! behaviour byte-identical.

/// Standard SCSI `READ BUFFER` opcode — the command freemkv hijacks.
pub const READ_BUFFER_OPCODE: u8 = 0x3C;

/// The freemkv sub-command mode at `cdb[1]`. OEM's `READ BUFFER` jump table
/// dispatches modes `0x00..=0x0D` and rejects `>= 0x0E`, and nothing in the fleet
/// uses `0x0E`, so it is collision-free.
pub const KNOCK_MODE: u8 = 0x0E;

/// Two-byte knock at `cdb[2..4]` ("C0DE") — the *safe* knock, carried by every
/// durable verb (Identity/Set/Get/Reset/DumpAll/FlashWrite/Save). A CDB whose
/// mode is [`KNOCK_MODE`] but whose knock is not this value is routed to a
/// different, more-restricted dispatch (currently only [`DEBUG_KNOCK`] +
/// [`Verb::Call`]), so a typo on the verb byte cannot cross the safe/debug line.
pub const KNOCK: [u8; 2] = [0xC0, 0xDE];

/// Two-byte knock at `cdb[2..4]` — the *debug* knock, distinct from the safe
/// [`KNOCK`] by construction (`assert_ne!(KNOCK, DEBUG_KNOCK)` in the ABI tests).
/// The only frame that authorizes debug-only verbs ([`Verb::Call`], [`Verb::Poke`],
/// [`Verb::Reboot`]).
/// The fw's dispatch never crosses knocks, so a typo of a safe verb vs a debug
/// verb under the wrong knock always falls through to the zeroed reply — Call,
/// Poke, and Reboot can never be accidentally invoked via [`KNOCK`], and no safe
/// verb can be accidentally invoked via [`DEBUG_KNOCK`].
pub const DEBUG_KNOCK: [u8; 2] = [0xDE, 0xB9];

/// Response-framing magic that leads a self-identifying reply: [`Verb::Identity`]
/// answers `RESP_MAGIC` + version + the current feature-state table.
pub const RESP_MAGIC: &[u8] = b"freemkv";

/// Reserved vendor sense (KEY / ASC / ASCQ) for freemkv error signalling, kept
/// for handler error paths.
#[allow(dead_code)]
pub const SENSE_IDENTITY: [u8; 3] = [0x09, 0xF0, 0x00];

/// Length of the Volume ID the host reads back via `READ DISC STRUCTURE`
/// (`0xAD`, format `0x80`) after an AACS unlock, in bytes.
pub const VID_LEN: usize = 16;

/// Length of a freemkv (READ BUFFER) CDB.
pub const CDB_LEN: usize = 10;

/// Offset of the opcode byte (`cdb[0]`).
pub const CDB_OPCODE: usize = 0;
/// Offset of the mode/knock byte (`cdb[1]`).
pub const CDB_MODE: usize = 1;
/// Offset of the first knock byte (`cdb[2]`, `cdb[3]`).
pub const CDB_KNOCK: usize = 2;
/// Offset of the verb byte (`cdb[4]`).
pub const CDB_VERB: usize = 4;
/// Offset of the feature-id byte (`cdb[5]`) — SET/GET only.
pub const CDB_FEATURE: usize = 5;
/// Offset of the state byte (`cdb[6]`) — SET only.
pub const CDB_STATE: usize = 6;
/// Offset of the 16-bit big-endian allocation length (`cdb[7..9]`).
pub const CDB_ALLOC_LEN: usize = 7;

/// Minimum data-in allocation length any freemkv vendor command may request.
///
/// **Hardware-confirmed (LG BU40N on freemkv firmware):** the drive's `READ
/// BUFFER` hijack ABORTS (SCSI Check Condition, sense key Aborted Command) any
/// vendor command whose data-in allocation length is too small — 0, 1, and 2
/// bytes all abort, while 16 and 64 both succeed. The knock handler needs a
/// data-in transfer of at least ~16 bytes to run; sub-16-byte transfers are
/// rejected before the verb executes. We floor every builder at `64` — it
/// matches [`MEMREAD_LEN`] and the IDENTITY caller's allocation, and is safely
/// above the ~16-byte minimum.
///
/// This affects only the wire transfer size, not the command's meaning: the
/// verb/feature/state ride in the CDB, so a larger data-in buffer is harmless.
/// For [`Verb::Get`] the state byte is still read from data offset 0.
pub const MIN_ALLOC_LEN: u16 = 64;

/// Feature state: **passthrough / OEM** (`0xFF`) — the firmware does not touch
/// this subsystem, so behaviour is exactly as the drive shipped. The value the
/// always-on boot hook writes into every flag at power-on, and the value
/// [`Verb::Reset`] restores everywhere. An image with all features at passthrough
/// is byte-behaviour-identical to OEM (stealth). This is the OEM leg of the
/// uniform `0xFF` / `0x01` / `0x00` tri-state.
pub const STATE_PASSTHROUGH: u8 = 0xFF;

/// Feature state: explicit **off / disabled** (`0x00`) — actively force the
/// capability off, even on a drive that ships it enabled (e.g. BD genuinely
/// refuses a disc, Speed caps at the floor). Distinct from [`STATE_PASSTHROUGH`]
/// (which merely leaves the subsystem untouched).
///
/// `0x00` is also the drive's power-on SRAM value; the always-on boot-init hook
/// overwrites every flag with [`STATE_PASSTHROUGH`] at boot, so a gate only ever
/// sees `0x00` (OFF) when the host has explicitly set it — never at power-on. That
/// boot hook is exactly what makes `0x00 == OFF` safe (the earlier design had to
/// reserve `0x00` as an OEM alias because there was no boot hook).
pub const STATE_OFF: u8 = 0x00;

/// Feature state: explicit **on / enabled** (the generic "activate" value; some
/// features define richer states — see [`Feature`]).
pub const STATE_ON: u8 = 0x01;

/// [`Verb::Reset`] mode (rides in the state slot `cdb[6]`): reload the saved flash
/// config block back into the RAM feature-state table, discarding any un-saved RAM
/// changes. Marker-gated — a never-saved drive (NV slot-0 marker `0xFF`) loads the
/// baked create-time defaults instead. The non-destructive "revert to last SAVE".
pub const RESET_TO_FLASH: u8 = 0x00;

/// [`Verb::Reset`] mode (rides in the state slot `cdb[6]`): restore the baked
/// per-create **defaults** (the create-time `DEFAULT_FLAGS`, e.g. UHD/BD on) into
/// the RAM feature-state table. RAM-only — does not touch flash. This is what a
/// never-saved drive boots to.
pub const RESET_TO_DEFAULTS: u8 = 0x01;

/// [`Verb::Reset`] mode (rides in the state slot `cdb[6]`): TRUE OEM. Forces every
/// feature to [`STATE_PASSTHROUGH`] (`0xFF`) in RAM **and** writes the NV config
/// block all-`0xFF` — marker included — so the drive is byte-for-byte identical to
/// a never-saved/never-configured drive (no trace it was ever set). Because the
/// marker is then `0xFF`, the NEXT boot loads the baked defaults, exactly like a
/// fresh drive. (The NV write is the same SAVE flash primitive with an all-`0xFF`
/// payload; op=1 RMW preserves the OEM region record at `+0x4B0`.)
pub const RESET_TO_OEM: u8 = 0xFF;

/// The verb selector in `cdb[4]`. These numeric values ARE the wire protocol and
/// must not drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[allow(dead_code)]
pub enum Verb {
    /// Status/ping — returns [`RESP_MAGIC`] + version + the feature-state table.
    /// Ignores feature/state.
    Identity = 0x01,
    /// Set one feature (`cdb[5]`) to a state (`cdb[6]`).
    Set = 0x02,
    /// Read one feature's (`cdb[5]`) current state back in the data-in payload.
    Get = 0x03,
    /// Restore the RAM feature-state table. The mode rides in `cdb[6]` (the state
    /// slot): [`RESET_TO_FLASH`] (`0x00`) reloads the saved config (marker-gated),
    /// [`RESET_TO_DEFAULTS`] (`0x01`) restores the baked create-time defaults, and
    /// [`RESET_TO_OEM`] (`0xFF`) forces true OEM passthrough in RAM AND blanks the NV
    /// block (traceless). Ignores feature.
    Reset = 0x04,
    /// Diagnostic RAM peek: [`MEMREAD_LEN`] bytes at the 32-bit address packed
    /// big-endian in `cdb[5..9]`. Read-only.
    DumpAll = 0x09,
    /// **TEMPORARY diagnostic** flash-write probe: program a single byte
    /// (`cdb[9]`) to the 32-bit flash offset packed big-endian in `cdb[5..9]`,
    /// via the OEM flash PROGRAM routine. The firmware hard-range-checks the
    /// destination against a compile-time allowlist and refuses any offset
    /// outside the safe non-CMAC gap, so this verb can physically only touch one
    /// erased scratch region. Exists to prove the drive's flash-write path on
    /// hardware; it is NOT part of the durable host ABI and will be removed once
    /// the primitive generalizes to boot-config init / SAVE / HRL-wipe. Replies
    /// with the echoed offset (4 bytes BE) followed by the routine's status word
    /// (4 bytes BE) at data offset 0. See [`build_flashwrite_cdb`].
    FlashWrite = 0x0A,
    /// Persist the whole RAM feature-state table to the flash config block. This is
    /// the ONLY verb that writes the config to flash: [`Verb::Set`] and
    /// [`Verb::Reset`] touch RAM only, so a host's changes stay volatile until a
    /// `Save` commits them (and survive a power cycle only once saved). Ignores
    /// feature/state. See [`build_save_cdb`].
    Save = 0x0B,
    /// **Debug-knock only.** Interactive fw-exploration `blx target` primitive.
    /// `CDB[5..9]` = 32-bit target VA (big-endian); `CDB[9]` = single u8 that
    /// is loaded into r0 as the sole register argument (r1..r3 are undefined).
    /// The handler ORs the thumb bit into the address and does `blx target`.
    /// Returns a zeroed data buffer. Refused under the safe [`KNOCK`]; only
    /// executed under [`DEBUG_KNOCK`]. Non-durable / diagnostic: it does not
    /// appear in the durable feature grammar. See [`build_call_cdb`].
    Call = 0x0C,
    /// **Debug-knock only.** Poke a single byte to an arbitrary address.
    /// `CDB[5..9]` = 32-bit target address (big-endian, RAM or MMIO);
    /// `CDB[9]` = byte value to store. The handler does `*(u8*)target = value`
    /// with NO bounds check. Refused under the safe [`KNOCK`]. Intended for
    /// interactive discovery of MMIO/state-cell control on a live drive without
    /// reflashing (pair with [`Verb::DumpAll`] for the read side). Non-durable
    /// / diagnostic. See [`build_poke_cdb`].
    Poke = 0x0D,
    /// Debug-knock only. Invokes the firmware's boot function entry with r0=4 to
    /// force the cold path (BSS clear + C-runtime data init + full post-init
    /// sequence). Recovers a wedged drive without a power cycle (SCSI target
    /// briefly returns Aborted Command mid-reboot, then comes back ~5s later;
    /// the safe-knock verb chain is re-armed to its power-on defaults). The
    /// target VA is baked into the emitted handler at build time (resolved from
    /// the boot-init signature = `boot_init_site - 0x10`), so no CDB arguments
    /// are carried beyond the verb byte. See [`build_reboot_cdb`].
    ///
    /// # Drive-side hardware ceiling on chained reboots (BU40N 1.00, measured)
    ///
    /// This verb is a **soft re-entry** into the firmware's own boot function,
    /// not a hardware CPU/SATA reset. The drive can absorb ~5 of these in a
    /// session; the ~6th chained reboot at any spacing (measured up to a 60 s
    /// gap with a sustained-stability probe) drops the drive to
    /// `DID_BAD_TARGET` at the SATA layer, and only a physical power-cycle
    /// to the drive recovers. The `DID_BAD_TARGET` symptom is precise: the
    /// endpoint is *gone from the bus*, which is a physical-layer failure —
    /// **the SATA PHY / link OOB negotiation FSM**, not the AACS coprocessor
    /// (which IS re-initialised on every reboot via
    /// `boot_function_entry` → `0x00044874` → `aacs_session_reset`
    /// (`0x000CAE18`), verified by static trace of the fixture image).
    ///
    /// **Do not chase a stronger in-firmware reset primitive.** A prior
    /// static disassembly over the OEM image confirmed:
    ///
    /// * **Zero `SControl.DET` writes exist anywhere in the image** — there
    ///   is no software path in Thumb or ARM state that renegotiates the
    ///   SATA link OOB. The PHY is brought up once by the C-runtime scatter-
    ///   load + `.init_array` at `0x0001B768` (reached only from the true
    ///   power-on reset vector) and never re-armed.
    /// * No reachable watchdog-feed register write.
    /// * No SoC-level RESET / `AIRCR` write reachable from Thumb.
    /// * The strongest software-side candidate — the mode-init trampoline at
    ///   VA `0x0013DE00` (ARM state; disables IRQ+FIQ, re-runs the full
    ///   C-runtime including every `.init_array` constructor) — is strictly
    ///   stronger than `boot_function_entry(r0=4)` but still does not cycle
    ///   the SATA PHY. It would not clear the accumulating link-layer state
    ///   either.
    ///
    /// So the accumulating state lives outside the ARM CPU's writable
    /// register domain, in the SATA PHY / link FSM. Only cycling SATA power
    /// to the drive (i.e. shutting down the host and cutting drive power)
    /// clears it.
    ///
    /// Callers that need to chain more than ~4 reboots per session must
    /// budget a physical power-cycle between rounds. Test suites should cap
    /// at ≤4 chained reboots per run.
    Reboot = 0x0F,
}

/// The feature selector in `cdb[5]` for [`Verb::Set`] / [`Verb::Get`]. Each feature
/// is an independent flag persisted in the firmware flag table, defaulting to
/// [`STATE_PASSTHROUGH`]. These numeric values ARE the wire protocol.
///
/// Features are orthogonal: the familiar "modes" are just combinations —
/// e.g. OEM-style UHD rip = [`Feature::Uhd`]=on + [`Feature::Hrl`]=off +
/// [`Feature::Encryption`]=off; full bypass = [`Feature::Encryption`]=off
/// (+ [`Feature::Uhd`]=on for a UHD disc). Under the migrated spec the bypass
/// direction is uniformly [`STATE_OFF`] (`0x00`) for HRL/Encryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[allow(dead_code)]
pub enum Feature {
    /// Read-speed / riplock ceiling. [`STATE_PASSTHROUGH`] (`0xFF`) = OEM ramp;
    /// [`STATE_OFF`] (`0x00`) = speed control off, i.e. the cap is lifted and the
    /// drive runs uncapped at maximum throughput (see [`SPEED_MAX`]); `0x01..=0xFE` =
    /// an explicit speed cap (the byte IS the cap, lower is slower). Note the OFF
    /// direction: "off" means the *limiter* is off, so OFF is the fastest state.
    Speed = 0x01,
    /// Region (RPC) control. [`STATE_PASSTHROUGH`] (`0xFF`) = drive's own region
    /// logic; [`STATE_OFF`] (`0x00`) = region-locked (nothing plays — the genuine
    /// OFF); [`REGION_DVD_BASE`]` + N` (`0x01..=0x08`) = force DVD region 1..8;
    /// [`REGION_BD_A`]/`_B`/`_C` (`0x0A`/`0x0B`/`0x0C`) = force BD region A/B/C;
    /// [`REGION_FREE`] (`0x0F`) = region-free (any disc plays).
    Region = 0x02,
    /// UHD (AACS 2.0) capability gate (the disc-classifier mode gate).
    /// [`STATE_PASSTHROUGH`] (`0xFF`) = OEM (as shipped); [`STATE_OFF`] (`0x00`) = No
    /// (refuse UHD — the classifier routes UHD discs into the mode-1 bucket the
    /// REPORT KEY gate refuses); [`STATE_ON`] (`0x01`) = Yes (accept UHD — the mode
    /// gate is neutralized so the drive engages UHD discs). The value mapping is
    /// unchanged: `0x01` accepts/enables, `0x00` refuses. The genuine No is emitted
    /// on the version-compare classifier shape; on the byte-extraction classifier
    /// shape No is reserved (== OEM) pending further RE (the class there is derived
    /// from several disc-version fields, not a single hookable value).
    Uhd = 0x03,
    /// Blu-ray (AACS 1.0) capability gate. [`STATE_PASSTHROUGH`] (`0xFF`) = OEM (BD
    /// engaged as shipped); [`STATE_OFF`] (`0x00`) = No (force-refuse BD discs — the
    /// drive raises its own `6F` refusal sense); [`STATE_ON`] (`0x01`) = Yes (accept
    /// BD — an enable direction, not a no-op). The boot hook guarantees `0xFF` at
    /// power-on, so an unarmed image never sees `0x00` here and stays
    /// OEM-behaviour-identical — which is what lets BD use the uniform `0x00` OFF
    /// instead of the old distinct `0x02` sentinel.
    Bd = 0x04,
    /// Host Revocation List handling on the cert path. [`STATE_PASSTHROUGH`]
    /// (`0xFF`) = OEM enforce; [`STATE_OFF`] (`0x00`) = off (skip the HRL lookup —
    /// revoked certs accepted, non-destructive); [`STATE_ON`] (`0x01`) = on (enforce
    /// the HRL). Polarity note: OFF now means "skip" — the pre-migration spec put
    /// skip on `0x01`. `0x02` is a reserved/internal deferred value (see the
    /// `pub(crate)` [`HRL_WIPE_ONCE`]) that is NOT part of the host-facing ABI.
    Hrl = 0x05,
    /// Content encryption / drive-host AKE (single consolidated feature — hardware
    /// proved on BU40N/MT1959 that toggling this alone de-busses content reads).
    /// [`STATE_PASSTHROUGH`] (`0xFF`) = OEM real handshake; [`STATE_OFF`] (`0x00`)
    /// = off (null/bypass — the drive acts pre-authenticated, no handshake
    /// performed, content reads back de-bussed); [`STATE_ON`] (`0x01`) = on
    /// (require the real handshake). Polarity note: OFF means "null/bypass".
    /// Wire id `0x07` is retired (was `Bus`, proved inert as a datapath lever).
    Encryption = 0x06,
}

/// [`Feature::Hrl`] internal deferred state: one-time PERMANENT wipe of the flash
/// HRL to valid-empty. **NOT part of the host-facing wire ABI** — it is
/// `pub(crate)` and referenced only by the gated-off firmware wipe codegen (see
/// `HRL_WIPE_ARMED`, default `false`). Kept at `0x02` so the deferred codegen
/// stays compilable; the wire only exposes HRL `skip` (`0x01`).
#[allow(dead_code)]
pub(crate) const HRL_WIPE_ONCE: u8 = 0x02;

// The old `STATE_BD_DISABLE` (`0x02`) sentinel is RETIRED: with the always-on
// boot hook writing `0xFF` into every flag at power-on, `0x00` is a safe OFF value
// (an unarmed image never sees it at boot), so BD force-refuse now uses the uniform
// [`STATE_OFF`] like every other feature — no feature-specific sentinel.

/// [`Feature::Speed`] state: speed control OFF — the read-speed cap is lifted and
/// the drive runs uncapped at maximum throughput. This is the [`STATE_OFF`]
/// (`0x00`) leg of Speed: "off" is the *limiter* being off, i.e. maximum speed.
/// `0x01..=0xFE` are explicit caps and `0xFF` is the OEM ramp.
pub const SPEED_MAX: u8 = 0x00;

/// [`Feature::Region`] state: base for the DVD region scheme. DVD region N encodes
/// as `REGION_DVD_BASE + N`, so `0x01..=0x08` = DVD region 1..8. BD regions live in
/// the same low-nibble block (`0x0A..=0x0C`, see [`REGION_BD_A`]) and [`REGION_FREE`]
/// (`0x0F`) is region-free; `0x00` itself is region-locked (nothing plays).
pub const REGION_DVD_BASE: u8 = 0x00;

/// [`Feature::Region`] state: force BD region A. BD regions A/B/C encode as
/// `0x0A`/`0x0B`/`0x0C`, sharing the low-nibble block with the DVD `0x0N` scheme
/// ([`REGION_DVD_BASE`]) and [`REGION_FREE`] (`0x0F`).
pub const REGION_BD_A: u8 = 0x0A;
/// [`Feature::Region`] state: force BD region B.
pub const REGION_BD_B: u8 = 0x0B;
/// [`Feature::Region`] state: force BD region C.
pub const REGION_BD_C: u8 = 0x0C;

/// [`Feature::Region`] state: region-free — any disc plays regardless of its region
/// code. Sits in the region low-nibble block above the DVD (`0x01..=0x08`) and BD
/// (`0x0A..=0x0C`) values.
pub const REGION_FREE: u8 = 0x0F;

/// Build a 10-byte host CDB for a safe verb over the `READ_BUFFER_OPCODE ||
/// KNOCK_MODE || KNOCK || verb || …` frame. Debug-only verbs use their own
/// builders ([`build_call_cdb`], [`build_poke_cdb`]) since they carry
/// [`DEBUG_KNOCK`] instead of [`KNOCK`].
///
/// `feature`/`state` land at `cdb[5]`/`cdb[6]` (0 when the verb ignores them);
/// `alloc_len` is the data-in buffer size, 16-bit big-endian at `cdb[7..9]`.
/// For [`Verb::DumpAll`] use [`build_memread_cdb`] instead (different field layout).
#[allow(dead_code)]
pub fn build_cdb(
    verb: Verb,
    feature: Option<Feature>,
    state: Option<u8>,
    alloc_len: u16,
) -> [u8; CDB_LEN] {
    let mut cdb = [0u8; CDB_LEN];
    cdb[CDB_OPCODE] = READ_BUFFER_OPCODE;
    cdb[CDB_MODE] = KNOCK_MODE;
    cdb[CDB_KNOCK..CDB_KNOCK + 2].copy_from_slice(&KNOCK);
    cdb[CDB_VERB] = verb as u8;
    cdb[CDB_FEATURE] = feature.map(|f| f as u8).unwrap_or(0);
    cdb[CDB_STATE] = state.unwrap_or(0);
    cdb[CDB_ALLOC_LEN] = (alloc_len >> 8) as u8;
    cdb[CDB_ALLOC_LEN + 1] = alloc_len as u8;
    cdb
}

/// Build a `SET feature = state` CDB. Requests a [`MIN_ALLOC_LEN`]-byte data-in
/// even though SET returns no payload: the drive aborts sub-16-byte transfers
/// (HW-confirmed — see [`MIN_ALLOC_LEN`]). The feature/state ride in the CDB.
#[allow(dead_code)]
pub fn build_set_cdb(feature: Feature, state: u8) -> [u8; CDB_LEN] {
    build_cdb(Verb::Set, Some(feature), Some(state), MIN_ALLOC_LEN)
}

/// Build a `GET feature` CDB. Requests a [`MIN_ALLOC_LEN`]-byte data-in (the
/// drive aborts a 1-byte transfer — HW-confirmed, see [`MIN_ALLOC_LEN`]); the
/// current state byte is read back from data offset 0.
#[allow(dead_code)]
pub fn build_get_cdb(feature: Feature) -> [u8; CDB_LEN] {
    build_cdb(Verb::Get, Some(feature), None, MIN_ALLOC_LEN)
}

/// Build a `RESET` CDB. `mode` rides in the state slot (`cdb[6]`):
/// [`RESET_TO_FLASH`] (`0x00`) reloads the saved flash config into RAM,
/// [`RESET_TO_OEM`] (`0xFF`) forces every feature to passthrough. Requests a
/// [`MIN_ALLOC_LEN`]-byte data-in for the same HW min-transfer reason as
/// [`build_set_cdb`].
#[allow(dead_code)]
pub fn build_reset_cdb(mode: u8) -> [u8; CDB_LEN] {
    build_cdb(Verb::Reset, None, Some(mode), MIN_ALLOC_LEN)
}

/// Build a `SAVE` CDB (persist the RAM feature-state table to the flash config
/// block — the only verb that writes config to flash). Requests a
/// [`MIN_ALLOC_LEN`]-byte data-in for the same HW min-transfer reason as
/// [`build_reset_cdb`].
#[allow(dead_code)]
pub fn build_save_cdb() -> [u8; CDB_LEN] {
    build_cdb(Verb::Save, None, None, MIN_ALLOC_LEN)
}

/// Build an `IDENTITY` CDB. `alloc_len` sizes the magic+version+state reply.
#[allow(dead_code)]
pub fn build_identity_cdb(alloc_len: u16) -> [u8; CDB_LEN] {
    build_cdb(Verb::Identity, None, None, alloc_len)
}

/// Bytes returned by one [`Verb::DumpAll`] memory read (fixed 64-byte window).
pub const MEMREAD_LEN: usize = 64;

/// Build a 10-byte CDB for [`Verb::DumpAll`]: read [`MEMREAD_LEN`] bytes at the
/// 32-bit `addr`, packed big-endian into `cdb[5..9]`.
#[allow(dead_code)]
pub fn build_memread_cdb(addr: u32) -> [u8; CDB_LEN] {
    let mut cdb = [0u8; CDB_LEN];
    cdb[CDB_OPCODE] = READ_BUFFER_OPCODE;
    cdb[CDB_MODE] = KNOCK_MODE;
    cdb[CDB_KNOCK..CDB_KNOCK + 2].copy_from_slice(&KNOCK);
    cdb[CDB_VERB] = Verb::DumpAll as u8;
    cdb[5] = (addr >> 24) as u8;
    cdb[6] = (addr >> 16) as u8;
    cdb[7] = (addr >> 8) as u8;
    cdb[8] = addr as u8;
    cdb
}

/// Build a 10-byte CDB for [`Verb::FlashWrite`] (TEMPORARY flash-write probe):
/// program the single byte `val` to the 32-bit flash `off`, packed big-endian
/// into `cdb[5..9]`, with `val` in `cdb[9]`. Mirrors [`build_memread_cdb`]'s
/// address layout, adding the value byte in the trailing control slot.
///
/// The firmware refuses any `off` outside its compile-time safe-cell allowlist
/// (see the MT1959 engine handler), so this builder cannot direct a write
/// outside the erased non-CMAC gap regardless of the `off` passed here.
#[allow(dead_code)]
pub fn build_flashwrite_cdb(off: u32, val: u8) -> [u8; CDB_LEN] {
    let mut cdb = [0u8; CDB_LEN];
    cdb[CDB_OPCODE] = READ_BUFFER_OPCODE;
    cdb[CDB_MODE] = KNOCK_MODE;
    cdb[CDB_KNOCK..CDB_KNOCK + 2].copy_from_slice(&KNOCK);
    cdb[CDB_VERB] = Verb::FlashWrite as u8;
    cdb[5] = (off >> 24) as u8;
    cdb[6] = (off >> 16) as u8;
    cdb[7] = (off >> 8) as u8;
    cdb[8] = off as u8;
    cdb[9] = val;
    cdb
}

/// Build a 10-byte CDB for [`Verb::Call`]: `blx target(r0)` where `target` is
/// packed big-endian in `cdb[5..9]` and the u8 `r0` register argument rides in
/// `cdb[9]`. Carries the [`DEBUG_KNOCK`] at `cdb[2..4]` — the ONLY
/// frame the fw honours for Call. The handler ORs the thumb bit into the
/// address at runtime. r1..r3 are undefined at callee entry.
#[allow(dead_code)]
pub fn build_call_cdb(target: u32, r0: u8) -> [u8; CDB_LEN] {
    let mut cdb = [0u8; CDB_LEN];
    cdb[CDB_OPCODE] = READ_BUFFER_OPCODE;
    cdb[CDB_MODE] = KNOCK_MODE;
    cdb[CDB_KNOCK..CDB_KNOCK + 2].copy_from_slice(&DEBUG_KNOCK);
    cdb[CDB_VERB] = Verb::Call as u8;
    cdb[5] = (target >> 24) as u8;
    cdb[6] = (target >> 16) as u8;
    cdb[7] = (target >> 8) as u8;
    cdb[8] = target as u8;
    cdb[9] = r0;
    cdb
}

/// Build a 10-byte CDB for [`Verb::Poke`]: write a single byte `val` to the
/// arbitrary 32-bit address `target` (RAM or MMIO). Target is packed
/// big-endian in `cdb[5..9]` and `val` rides in `cdb[9]`. Carries the
/// [`DEBUG_KNOCK`] at `cdb[2..4]`. NO bounds check on the address —
/// this is a diagnostic primitive for on-drive state discovery, not a durable
/// verb.
#[allow(dead_code)]
pub fn build_poke_cdb(target: u32, val: u8) -> [u8; CDB_LEN] {
    let mut cdb = [0u8; CDB_LEN];
    cdb[CDB_OPCODE] = READ_BUFFER_OPCODE;
    cdb[CDB_MODE] = KNOCK_MODE;
    cdb[CDB_KNOCK..CDB_KNOCK + 2].copy_from_slice(&DEBUG_KNOCK);
    cdb[CDB_VERB] = Verb::Poke as u8;
    cdb[5] = (target >> 24) as u8;
    cdb[6] = (target >> 16) as u8;
    cdb[7] = (target >> 8) as u8;
    cdb[8] = target as u8;
    cdb[9] = val;
    cdb
}

/// Build a 10-byte CDB for [`Verb::Reboot`]: force the firmware boot function's
/// cold path (soft-reboot the controller). Carries the [`DEBUG_KNOCK`] at
/// `cdb[2..4]`. NO arguments are transmitted on the wire — the target VA is
/// baked into the emitted handler at build time (per-image, resolved from the
/// boot-init signature). Requests a [`MIN_ALLOC_LEN`]-byte data-in like every
/// other durable-shape verb: the drive returns Aborted Command mid-reboot
/// anyway, so callers should tolerate a rejection on this send and re-probe
/// identity after a short delay.
#[allow(dead_code)]
pub fn build_reboot_cdb() -> [u8; CDB_LEN] {
    let mut cdb = [0u8; CDB_LEN];
    cdb[CDB_OPCODE] = READ_BUFFER_OPCODE;
    cdb[CDB_MODE] = KNOCK_MODE;
    cdb[CDB_KNOCK..CDB_KNOCK + 2].copy_from_slice(&DEBUG_KNOCK);
    cdb[CDB_VERB] = Verb::Reboot as u8;
    cdb[CDB_ALLOC_LEN] = (MIN_ALLOC_LEN >> 8) as u8;
    cdb[CDB_ALLOC_LEN + 1] = MIN_ALLOC_LEN as u8;
    cdb
}

/// Whether a device data response leads with [`RESP_MAGIC`].
#[allow(dead_code)]
pub fn verify_response(bytes: &[u8]) -> bool {
    bytes.starts_with(RESP_MAGIC)
}

#[cfg(test)]
#[path = "abi_tests.rs"]
mod tests;
