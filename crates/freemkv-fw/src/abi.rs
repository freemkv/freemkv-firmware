//! The freemkv vendor-command ABI — the single source of truth for the wire
//! frame, owned by freemkv-fw (the tool that controls the firmware). The only
//! other place this ABI lives is the freemkv-unlock host crate, which mirrors
//! it; the neutral flasher (freemkv-flash) knows nothing about it.
//!
//! A freemkv command is a **hijack of the standard SCSI `READ BUFFER` (`0x3C`)
//! command**, discriminated by an OEM-unused mode. `READ BUFFER` is chosen
//! because it is a standard opcode the USB/UAS bridge passes through unmodified
//! (a bare vendor opcode is rejected by the bridge with `DID_ERROR`), it returns
//! data through an existing DMA path.
//!
//! ```text
//!   cdb[0]      = 0x3C  (READ BUFFER)         ← standard opcode; bridge-safe
//!   cdb[1]      = 0x0E  (KNOCK_MODE)          ← OEM's jump table rejects modes ≥ 0x0E
//!   cdb[2..4]   = 0xC0 0xDE (KNOCK)           ← defence-in-depth signature
//!   cdb[4]      = SubFn
//!   cdb[5]      = per-feature state byte (0x00 = OEM, 0x01 = patched; Speed uses
//!                 it as a cap value, DumpAll as the address high byte)
//!   cdb[6..9]   = allocation length (24-bit big-endian) — the NATIVE READ BUFFER
//!                 position, so the transport sizes the data-in transfer correctly
//!   cdb[9]      = control (0)
//! ```
//!
//! The full discriminator is the 4-byte prefix `3C 0E C0 DE`: standard opcode +
//! OEM-unused mode + knock. OEM's `0x3C` handler rejects mode `0x0E` at its own
//! jump-table bound, so the knock bytes never confuse it; the freemkv handler
//! intercepts mode `0x0E` and tail-calls the original handler for every other
//! mode, leaving OEM `READ BUFFER` behaviour byte-identical.

/// Standard SCSI `READ BUFFER` opcode — the command freemkv hijacks.
pub const READ_BUFFER_OPCODE: u8 = 0x3C;

/// The freemkv sub-command mode at `cdb[1]`. OEM's `READ BUFFER` jump table
/// dispatches modes `0x00..=0x0D` and rejects `≥ 0x0E`, and nothing in the fleet
/// uses `0x0E`, so it is collision-free.
pub const KNOCK_MODE: u8 = 0x0E;

/// Two-byte knock at `cdb[2..4]` ("C0DE") — a defence-in-depth signature behind
/// the mode discriminator.
pub const KNOCK: [u8; 2] = [0xC0, 0xDE];

/// Reserved vendor sense (KEY / ASC / ASCQ) for freemkv error signalling.
/// (Identity now answers with the [`RESP_MAGIC`] data payload, not a sense; this
/// is kept for error paths.)
#[allow(dead_code)]
pub const SENSE_IDENTITY: [u8; 3] = [0x09, 0xF0, 0x00];

/// Response-framing magic that leads the self-identifying reply:
/// [`SubFn::Identity`] answers `RESP_MAGIC` + version. Other sub-functions are
/// lean/raw (no prefix). Host-side helpers use [`verify_response`].
pub const RESP_MAGIC: &[u8] = b"freemkv";

/// NOT READY / MEDIUM NOT PRESENT sense (key `0x02`, ASC `0x3A`, ASCQ `0x00`),
/// kept for handler error paths. (The Raw Read approve no longer stages the VID
/// itself — the host reads it via `0xAD` — so this is currently unused in-handler.)
#[allow(dead_code)]
pub const SENSE_NO_MEDIUM: [u8; 3] = [0x02, 0x3A, 0x00];

/// Length of the Volume ID the host reads back via `READ DISC STRUCTURE`
/// (`0xAD`, format `0x80`) after a Raw Read approve, in bytes.
pub const VID_LEN: usize = 16;

/// Length of a freemkv (READ BUFFER) CDB.
pub const CDB_LEN: usize = 10;

/// Offset of the opcode byte (`cdb[0]`).
pub const CDB_OPCODE: usize = 0;
/// Offset of the mode/knock byte (`cdb[1]`).
pub const CDB_MODE: usize = 1;
/// Offset of the first knock byte (`cdb[2]`, `cdb[3]`).
pub const CDB_KNOCK: usize = 2;
/// Offset of the sub-function byte (`cdb[4]`).
pub const CDB_SUBFN: usize = 4;
/// Offset of the per-feature state byte (`cdb[5]`).
pub const CDB_STATE: usize = 5;
/// Offset of the 24-bit big-endian allocation length (`cdb[6..9]`).
pub const CDB_ALLOC_LEN: usize = 6;

/// State byte value that deactivates a feature (clears its RAM flag → OEM).
pub const STATE_OFF: u8 = 0x00;

/// State byte value that activates a feature (sets its RAM flag).
#[allow(dead_code)]
pub const STATE_ON: u8 = 0x01;

/// The sub-function selector in `cdb[4]`. These numeric values ARE the wire
/// protocol and must not drift.
///
/// [`SubFn::Identity`] is the ping ("is this freemkv?"): the firmware returns
/// [`RESP_MAGIC`] + version. The others are typed capabilities; reads ignore
/// the per-feature state byte, toggleable features consume it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[allow(dead_code)]
pub enum SubFn {
    /// Status/ping — returns [`RESP_MAGIC`] + version.
    Identity = 0x01,
    /// Read-speed / riplock ceiling. `cdb[5]` IS the cap: `0x00` = OEM, `0xFF` = max.
    Speed = 0x02,
    /// DVD region (RPC) free. Toggle: `cdb[5]==0x01` on, `0x00` OEM.
    Region = 0x03,
    /// Raw Read — the transport-unlock command. `cdb[5]` is persisted to
    /// `flag[0x04]` and read by two build-time OEM-code trampolines. Two distinct
    /// unlock modes plus OEM off:
    ///   `0x00` — OEM enforcement (both trampolines replicate stock behaviour).
    ///   `0x01` — "cert is valid": the Gate-A trampoline at the VID producer's own
    ///            `cmp auth,#6` gate forces the authed path, so an unlocker issues a
    ///            BARE `READ DISC STRUCTURE` (`0xAD` fmt `0x80`) and gets the VID with
    ///            NO host cert and NO AKE. The one-command unlock path.
    ///   `0x02` — "accept any host cert, revoked or not": the AKE trampoline forces a
    ///            FAILED host-cert verify to AKE state `6` (accept). The host still
    ///            drives the real AKE (`0xA3`/`0xA4`) and may present a revoked (or
    ///            any) cert; the drive accepts it, the bus key is established, and a
    ///            normal `0xAD` read returns the VID. Only defeats revocation/verify.
    RawRead = 0x04,
    // 0x05 unassigned.
    /// Diagnostic RAM peek: 64 bytes at the 32-bit address packed big-endian in
    /// `cdb[5..9]`. Read-only. Parked at `0x09` after the `0x05`–`0x08` gap.
    DumpAll = 0x09,
}

/// Build a 10-byte host CDB for a freemkv command (the `3C 0E C0 DE …` frame).
///
/// `state` is the per-feature state byte at `cdb[5]` (`None` → [`STATE_OFF`],
/// correct for [`SubFn::Identity`], which ignores it). `alloc_len` is the
/// response-buffer size, stored 24-bit big-endian at `cdb[6..9]` (the native
/// READ BUFFER allocation-length position). Host-side helper.
#[allow(dead_code)]
pub fn build_cdb(sub: SubFn, state: Option<u8>, alloc_len: u16) -> [u8; CDB_LEN] {
    let mut cdb = [0u8; CDB_LEN];
    cdb[CDB_OPCODE] = READ_BUFFER_OPCODE;
    cdb[CDB_MODE] = KNOCK_MODE;
    cdb[CDB_KNOCK..CDB_KNOCK + 2].copy_from_slice(&KNOCK);
    cdb[CDB_SUBFN] = sub as u8;
    cdb[CDB_STATE] = state.unwrap_or(STATE_OFF);
    // 24-bit big-endian allocation length at cdb[6..9].
    cdb[CDB_ALLOC_LEN] = 0;
    cdb[CDB_ALLOC_LEN + 1] = (alloc_len >> 8) as u8;
    cdb[CDB_ALLOC_LEN + 2] = alloc_len as u8;
    cdb
}

/// Bytes returned by one [`SubFn::DumpAll`] memory read (the firmware handler
/// always commits a fixed 64-byte window).
pub const MEMREAD_LEN: usize = 64;

/// Build a 10-byte CDB for [`SubFn::DumpAll`]: read [`MEMREAD_LEN`] bytes at the
/// 32-bit `addr`, packed big-endian into `cdb[5..9]`. Host-side helper.
#[allow(dead_code)]
pub fn build_memread_cdb(addr: u32) -> [u8; CDB_LEN] {
    let mut cdb = [0u8; CDB_LEN];
    cdb[CDB_OPCODE] = READ_BUFFER_OPCODE;
    cdb[CDB_MODE] = KNOCK_MODE;
    cdb[CDB_KNOCK..CDB_KNOCK + 2].copy_from_slice(&KNOCK);
    cdb[CDB_SUBFN] = SubFn::DumpAll as u8;
    cdb[5] = (addr >> 24) as u8;
    cdb[6] = (addr >> 16) as u8;
    cdb[7] = (addr >> 8) as u8;
    cdb[8] = addr as u8;
    cdb
}

/// Whether a device data response leads with [`RESP_MAGIC`] (a data-returning
/// freemkv reply). Host-side helper.
#[allow(dead_code)]
pub fn verify_response(bytes: &[u8]) -> bool {
    bytes.starts_with(RESP_MAGIC)
}

#[cfg(test)]
#[path = "abi_tests.rs"]
mod tests;
