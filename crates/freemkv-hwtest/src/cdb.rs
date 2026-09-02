//! The freemkv knock CDB assembler.
//!
//! One place builds the `3C 0E C0 DE …` frame, so the wire framing cannot drift
//! between test steps. Mirrors the authoritative ABI in
//! `freemkv-fw/src/abi.rs` (`build_cdb` / `build_memread_cdb`); the constants
//! here are copied from that file, which is the single source of truth.

/// Standard SCSI `READ BUFFER` opcode — the command freemkv hijacks (`cdb[0]`).
pub const READ_BUFFER_OPCODE: u8 = 0x3C;
/// The freemkv sub-command mode at `cdb[1]`; OEM rejects modes `>= 0x0E`.
pub const KNOCK_MODE: u8 = 0x0E;
/// Two-byte knock at `cdb[2..4]` ("C0DE").
pub const KNOCK: [u8; 2] = [0xC0, 0xDE];
/// Length of a freemkv (READ BUFFER) CDB.
pub const CDB_LEN: usize = 10;

/// Response-framing magic leading the Identity reply (`b"freemkv"`).
pub const RESP_MAGIC: &[u8] = b"freemkv";

/// Sub-function selectors (`cdb[4]`). These numeric values ARE the wire protocol.
/// The full set is documented here for readers and used by tests; only
/// `IDENTITY` and `DUMP_ALL` are referenced by the runner (other sub-functions
/// reach the wire via YAML `knock.subfn`).
#[allow(dead_code)]
pub mod subfn {
    /// Status/ping — returns `b"freemkv <version>"`.
    pub const IDENTITY: u8 = 0x01;
    /// Read-speed / riplock ceiling (`cdb[5]` is the cap; `0xFF` = max).
    pub const SPEED: u8 = 0x02;
    /// DVD region (RPC) free (toggle).
    pub const REGION: u8 = 0x03;
    /// Raw Read — transport unlock (`0x00` OEM / `0x01` cert-valid / `0x02` AKE).
    pub const RAW_READ: u8 = 0x04;
    /// Diagnostic RAM peek: 64 bytes at the 32-bit address in `cdb[5..9]`.
    pub const DUMP_ALL: u8 = 0x09;
}

/// Every knock returns a fixed 64-byte data-in reply (`CLEAR_LEN` in the fw).
/// Reading fewer or NONE desyncs the transfer and hangs the drive — so this is
/// the only allocation length a knock may use.
pub const KNOCK_ALLOC: usize = 64;

/// Build a standard 10-byte freemkv knock CDB:
/// `3C 0E C0 DE <subfn> <state> <alloc_hi> <alloc_mid> <alloc_lo> 00`.
///
/// `alloc_len` is stored 24-bit big-endian at `cdb[6..9]` (the native READ
/// BUFFER allocation-length position). For every knock this MUST be
/// [`KNOCK_ALLOC`] (64); see the module note on desync.
pub fn assemble_knock(subfn: u8, state: u8, alloc_len: usize) -> [u8; CDB_LEN] {
    let mut cdb = [0u8; CDB_LEN];
    cdb[0] = READ_BUFFER_OPCODE;
    cdb[1] = KNOCK_MODE;
    cdb[2..4].copy_from_slice(&KNOCK);
    cdb[4] = subfn;
    cdb[5] = state;
    let a = alloc_len as u32;
    cdb[6] = (a >> 16) as u8;
    cdb[7] = (a >> 8) as u8;
    cdb[8] = a as u8;
    cdb
}

/// Build a `DumpAll` (subfn `0x09`) CDB: read 64 bytes of RAM at the 32-bit
/// `addr`, packed big-endian into `cdb[5..9]` (overlapping the alloc-length
/// field — the firmware always commits a fixed 64-byte window regardless).
pub fn assemble_dumpall(addr: u32) -> [u8; CDB_LEN] {
    let mut cdb = [0u8; CDB_LEN];
    cdb[0] = READ_BUFFER_OPCODE;
    cdb[1] = KNOCK_MODE;
    cdb[2..4].copy_from_slice(&KNOCK);
    cdb[4] = subfn::DUMP_ALL;
    cdb[5] = (addr >> 24) as u8;
    cdb[6] = (addr >> 16) as u8;
    cdb[7] = (addr >> 8) as u8;
    cdb[8] = addr as u8;
    cdb
}

/// Parse a whitespace-separated hex-byte string (e.g. `"3c 00 00 00"`) into a
/// CDB byte vector. Accepts optional `0x` prefixes and mixed case.
pub fn parse_hex_cdb(s: &str) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::new();
    for tok in s.split_whitespace() {
        let t = tok
            .strip_prefix("0x")
            .or_else(|| tok.strip_prefix("0X"))
            .unwrap_or(tok);
        let b = u8::from_str_radix(t, 16)
            .map_err(|e| anyhow::anyhow!("bad hex byte {tok:?} in CDB: {e}"))?;
        out.push(b);
    }
    if out.is_empty() {
        anyhow::bail!("empty CDB hex string");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_knock_frame() {
        // The canonical identity knock the shell issued as `3c 0e c0 de 01 00 …`
        // with a 64-byte data-in phase.
        let cdb = assemble_knock(subfn::IDENTITY, 0x00, KNOCK_ALLOC);
        assert_eq!(
            cdb,
            [0x3C, 0x0E, 0xC0, 0xDE, 0x01, 0x00, 0x00, 0x00, 0x40, 0x00]
        );
    }

    #[test]
    fn speed_max_knock_frame() {
        let cdb = assemble_knock(subfn::SPEED, 0xFF, KNOCK_ALLOC);
        assert_eq!(
            cdb,
            [0x3C, 0x0E, 0xC0, 0xDE, 0x02, 0xFF, 0x00, 0x00, 0x40, 0x00]
        );
    }

    #[test]
    fn alloc_len_is_24bit_big_endian() {
        let cdb = assemble_knock(subfn::RAW_READ, 0x01, 0x01_2345);
        assert_eq!(&cdb[6..9], &[0x01, 0x23, 0x45]);
    }

    #[test]
    fn dumpall_packs_addr_big_endian() {
        let cdb = assemble_dumpall(0x0200_0E40);
        assert_eq!(
            cdb,
            [0x3C, 0x0E, 0xC0, 0xDE, 0x09, 0x02, 0x00, 0x0E, 0x40, 0x00]
        );
    }

    #[test]
    fn hex_cdb_roundtrip() {
        assert_eq!(
            parse_hex_cdb("3c 00 00 00 00 00 00 00 00 00").unwrap(),
            vec![0x3C, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(parse_hex_cdb("0xAD 0x01").unwrap(), vec![0xAD, 0x01]);
        assert!(parse_hex_cdb("").is_err());
        assert!(parse_hex_cdb("zz").is_err());
    }
}
