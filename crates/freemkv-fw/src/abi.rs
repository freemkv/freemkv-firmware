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
//! of **features**, each holding a **state**. Every feature defaults to
//! [`STATE_PASSTHROUGH`] — the firmware does not touch that subsystem, so an
//! unarmed image is byte-behaviour-identical to OEM. [`Verb::Reset`] returns every
//! feature to passthrough. Explicit states force a specific behaviour.
//!
//! ```text
//!   cdb[0]    = 0x3C  (READ BUFFER)          ← standard opcode; bridge-safe
//!   cdb[1]    = 0x0E  (KNOCK_MODE)           ← OEM's jump table rejects modes >= 0x0E
//!   cdb[2..4] = 0xC0 0xDE (KNOCK)            ← defence-in-depth signature
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
//! The full discriminator is the 4-byte prefix `3C 0E C0 DE`: standard opcode +
//! OEM-unused mode + knock. OEM's `0x3C` handler rejects mode `0x0E` at its own
//! jump-table bound, so the knock bytes never confuse it; the freemkv handler
//! intercepts mode `0x0E` and tail-calls the original handler for every other
//! mode, leaving OEM `READ BUFFER` behaviour byte-identical.

/// Standard SCSI `READ BUFFER` opcode — the command freemkv hijacks.
pub const READ_BUFFER_OPCODE: u8 = 0x3C;

/// The freemkv sub-command mode at `cdb[1]`. OEM's `READ BUFFER` jump table
/// dispatches modes `0x00..=0x0D` and rejects `>= 0x0E`, and nothing in the fleet
/// uses `0x0E`, so it is collision-free.
pub const KNOCK_MODE: u8 = 0x0E;

/// Two-byte knock at `cdb[2..4]` ("C0DE") — a defence-in-depth signature behind
/// the mode discriminator.
pub const KNOCK: [u8; 2] = [0xC0, 0xDE];

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

/// Feature state: **passthrough** — the firmware does not touch this subsystem,
/// so behaviour is exactly as the drive shipped (OEM). The boot default of every
/// feature flag, and the value [`Verb::Reset`] restores everywhere. An image with
/// all features at passthrough is byte-behaviour-identical to OEM (stealth).
pub const STATE_PASSTHROUGH: u8 = 0xFF;

/// Feature state: explicit **off / disabled** (force the OEM-off behaviour rather
/// than merely leaving the subsystem untouched). Distinct from
/// [`STATE_PASSTHROUGH`]: `OFF` forces disabled even on a drive that ships the
/// capability enabled.
pub const STATE_OFF: u8 = 0x00;

/// Feature state: explicit **on / enabled** (the generic "activate" value; some
/// features define richer states — see [`Feature`]).
pub const STATE_ON: u8 = 0x01;

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
    /// Restore every feature to [`STATE_PASSTHROUGH`] (out-of-the-box behaviour).
    /// Ignores feature/state.
    Reset = 0x04,
    /// Diagnostic RAM peek: [`MEMREAD_LEN`] bytes at the 32-bit address packed
    /// big-endian in `cdb[5..9]`. Read-only.
    DumpAll = 0x09,
}

/// The feature selector in `cdb[5]` for [`Verb::Set`] / [`Verb::Get`]. Each feature
/// is an independent flag persisted in the firmware flag table, defaulting to
/// [`STATE_PASSTHROUGH`]. These numeric values ARE the wire protocol.
///
/// Features are orthogonal: the familiar "modes" are just combinations —
/// e.g. OEM-style UHD rip = [`Feature::Uhd`]=on + [`Feature::Hrl`]=skip +
/// [`Feature::Bus`]=off; full bypass = [`Feature::Ake`]=null + [`Feature::Bus`]=off
/// (+ [`Feature::Uhd`]=on for a UHD disc).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[allow(dead_code)]
pub enum Feature {
    /// Read-speed / riplock ceiling. `passthrough` = OEM ramp; `0x01` = unlocked
    /// (max); any other value is treated as an explicit speed cap byte.
    Speed = 0x01,
    /// Region (RPC) control. `passthrough` = drive's own region logic;
    /// [`STATE_ON`] (`0x01`) = region-free (RPC-1); `0x11..=0x18` = force DVD region
    /// 1..8; [`REGION_BD_A`]/`_B`/`_C` = force BD region A/B/C.
    Region = 0x02,
    /// UHD (AACS 2.0) capability gate (the disc-classifier mode gate). `passthrough`
    /// = as shipped; [`STATE_ON`] = force enabled (mode gate neutralized so the drive
    /// engages UHD discs). [`STATE_OFF`] is a reserved/OEM no-op here: only the enable
    /// direction is emitted (the classifier stub arms solely on [`STATE_ON`]).
    Uhd = 0x03,
    /// Blu-ray (AACS 1.0) capability gate. `passthrough`/[`STATE_OFF`] (boot)/
    /// [`STATE_ON`] = OEM (BD engaged as shipped — the enable direction is a
    /// reserved/no-op, since OEM already engages BD); [`STATE_BD_DISABLE`] (`0x02`) =
    /// force-refuse BD discs. The disable value is a distinct sentinel (NOT `0x00`,
    /// the SRAM boot value) so an unarmed image is OEM-behaviour-identical.
    Bd = 0x04,
    /// Host Revocation List handling on the cert path. `passthrough`/[`STATE_OFF`]
    /// = OEM enforce; [`STATE_ON`] (`0x01`) = skip the HRL lookup (revoked certs
    /// accepted, non-destructive). `0x01` (skip) is the only HRL state exposed on
    /// the wire. `0x02` is a reserved/internal deferred value (see the
    /// `pub(crate)` [`HRL_WIPE_ONCE`]) that is NOT part of the host-facing ABI.
    Hrl = 0x05,
    /// Drive-host AKE. `passthrough`/[`STATE_OFF`] = OEM real handshake;
    /// [`STATE_ON`] (`0x01`) = null (bypass the handshake; drive acts
    /// pre-authenticated).
    Ake = 0x06,
    /// In-transit AACS bus encryption. `passthrough`/[`STATE_OFF`] = OEM (bus
    /// encryption on); [`STATE_ON`] (`0x01`) = off (content returned de-bussed).
    Bus = 0x07,
}

/// [`Feature::Hrl`] internal deferred state: one-time PERMANENT wipe of the flash
/// HRL to valid-empty. **NOT part of the host-facing wire ABI** — it is
/// `pub(crate)` and referenced only by the gated-off firmware wipe codegen (see
/// `HRL_WIPE_ARMED`, default `false`). Kept at `0x02` so the deferred codegen
/// stays compilable; the wire only exposes HRL `skip` (`0x01`).
#[allow(dead_code)]
pub(crate) const HRL_WIPE_ONCE: u8 = 0x02;

/// [`Feature::Bd`] state: **force-refuse** BD (AACS 1.0) discs (`0x02`). A distinct
/// sentinel — deliberately NOT [`STATE_OFF`] (`0x00`, which is the SRAM boot value
/// of every flag cell) — so an unarmed/boot image leaves BD engaged (OEM). It is a
/// feature-specific state that is neither the boot `0x00` nor the passthrough
/// `0xFF` default. See [`Feature::Bd`].
pub const STATE_BD_DISABLE: u8 = 0x02;

/// [`Feature::Region`] state: force BD region A. (`0x2A`/`0x2B`/`0x2C` = A/B/C; the
/// `0x2X` block is the BD region scheme, `0x1X` the DVD 1..8 scheme.)
pub const REGION_BD_A: u8 = 0x2A;
/// [`Feature::Region`] state: force BD region B.
pub const REGION_BD_B: u8 = 0x2B;
/// [`Feature::Region`] state: force BD region C.
pub const REGION_BD_C: u8 = 0x2C;

/// Build a 10-byte host CDB for a verb over the `3C 0E C0 DE …` frame.
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

/// Build a `RESET` CDB (all features → passthrough). Requests a
/// [`MIN_ALLOC_LEN`]-byte data-in for the same HW min-transfer reason as
/// [`build_set_cdb`].
#[allow(dead_code)]
pub fn build_reset_cdb() -> [u8; CDB_LEN] {
    build_cdb(Verb::Reset, None, None, MIN_ALLOC_LEN)
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

/// Whether a device data response leads with [`RESP_MAGIC`].
#[allow(dead_code)]
pub fn verify_response(bytes: &[u8]) -> bool {
    bytes.starts_with(RESP_MAGIC)
}

#[cfg(test)]
#[path = "abi_tests.rs"]
mod tests;
