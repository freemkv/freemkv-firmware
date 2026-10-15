//! Guard: `freemkv-flash`'s backup-read mirror of the injected command wire
//! format must stay byte-identical to the canonical `freemkv_fw::abi` builders,
//! so the modify tool and the flasher never disagree on the Identity / DumpAll
//! CDBs. `freemkv-fw` depends on `freemkv-flash` (not the reverse), so this
//! cross-crate check lives here, on the owning side.

use freemkv_flash::backends::mtk::fwdump;
use freemkv_fw::abi;

#[test]
fn identity_cdb_matches_canonical_abi() {
    for alloc in [16u16, 64, 96, 256, u16::MAX] {
        assert_eq!(
            fwdump::identity_cdb(alloc),
            abi::build_identity_cdb(alloc),
            "Identity CDB drifted from freemkv_fw::abi (alloc={alloc})"
        );
    }
}

#[test]
fn memread_cdb_matches_canonical_abi() {
    for addr in [0u32, 0x3000, 0x1E_D000, 0x1F_FFC0, 0x0020_0000, u32::MAX] {
        assert_eq!(
            fwdump::memread_cdb(addr),
            abi::build_memread_cdb(addr),
            "DumpAll CDB drifted from freemkv_fw::abi (addr={addr:#x})"
        );
    }
}
