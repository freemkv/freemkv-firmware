//! Declarative flash instruction sets — the per-family/brand flash recipe as data.
//!
//! This is the flash analogue of the modify tool's per-chipset lever set: a
//! single generic engine drives whichever [`crate::flashset::FlashInstructionSet`] the detected
//! chipset selects. It never replaces the proven [`crate::drive::mtk`] execution
//! path — instead [`crate::flashset::FlashInstructionSet::mt1959`] describes that path
//! *declaratively*, and the golden CDB KAT in `flashset_tests` proves the
//! declarative form renders **byte-identical** CDBs to the live `mtk` builders,
//! so the catalog can never silently drift from what actually executes.
//!
//! Sources of truth (per the campaign's sources-of-truth rule): the MT1959
//! recipe is our hardware-proven path; the 18-brand catalog is transcribed from
//! the firmware/flasher-derived recipes at
//! `firmware-hoard/cdrinfo/<Brand>/cdb.json` (which cite flasher `.exe` /
//! firmware-image RE and the XFlash oracle — never DVDFab or forum models).
//! Every recipe has `host_side_key = false`: no brand needs a host secret, so a
//! generic verbatim writer is never crypto-blocked.

use crate::drive::Family;

/// How CDBs reach the drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// SPTI `IOCTL_SCSI_PASS_THROUGH_DIRECT` — the pass-through our
    /// [`crate::platform::ScsiDevice`] issues. Buildable + issuable now.
    Spti,
    /// Legacy ASPI (`SendASPI32Command`) — a transport our SPTI seam cannot
    /// drive without an ASPI layer.
    Aspi,
    /// A MediaTek kernel driver DIOC (`MTKFLASH` / `Mtk.SYS`) — a private
    /// device-io-control path we cannot issue.
    MtkKernelDioc,
}

/// How far a recipe can actually be taken with freemkv-flash's transport and
/// our hardware proof. Gates real execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlashStatus {
    /// Proven on real hardware AND issuable now. Only MT1959 today.
    Executable,
    /// Recipe fully known and issuable over SPTI, but NOT hardware-verified by
    /// us — allowed for `info`/dry-run/plan only; a real `--execute` is refused.
    CatalogOnly,
    /// The recipe needs a transport we cannot issue (ASPI / kernel DIOC) —
    /// refused, with a clear message, even in dry-run execute.
    TransportGated,
}

impl FlashStatus {
    /// Whether a real (destructive) flash may proceed for this status.
    pub fn is_executable(self) -> bool {
        matches!(self, FlashStatus::Executable)
    }

    /// Short label for `info` / plans.
    pub fn label(self) -> &'static str {
        match self {
            FlashStatus::Executable => "executable (hardware-proven)",
            FlashStatus::CatalogOnly => "catalog-only (dry-run/plan; not hardware-verified)",
            FlashStatus::TransportGated => "transport-gated (needs a driver we cannot issue)",
        }
    }
}

/// Data direction of one step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    /// No data phase (e.g. TEST UNIT READY).
    None,
    /// Data-in (drive → host).
    In,
    /// Data-out (host → drive).
    Out,
}

/// How a step's CDB bytes are produced (fixed, or templated on offset/len).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tmpl {
    /// A constant CDB.
    Fixed(&'static [u8]),
    /// MT1959 STREAM (`3B 06`): `[3B 06 00 O O O 00 L L 00 00 00]`,
    /// offset u24 big-endian at [3..6], len u16 big-endian at [7..9].
    Mt1959Stream,
    /// MT1959 READBACK (`3C 06`): `[3C 06 00 O O O L L L 00]`,
    /// offset u24 at [3..6], len u24 at [6..9].
    Mt1959Readback,
}

/// One CDB in a flash recipe.
#[derive(Debug, Clone, Copy)]
pub struct FlashStep {
    /// Short label (`PROBE`, `PREPARE`, `STREAM`, `COMMIT`…).
    pub label: &'static str,
    /// Plain-language purpose.
    pub purpose: &'static str,
    /// Data direction.
    pub dir: Dir,
    /// The response-check gate that must hold before continuing.
    pub gate: &'static str,
    /// True for the per-chunk streaming step (issued once per chunk).
    pub per_chunk: bool,
    tmpl: Tmpl,
}

impl FlashStep {
    /// Render this step's CDB bytes for an absolute `offset` and transfer `len`
    /// (both ignored by `Fixed` steps).
    pub fn render(&self, offset: u32, len: u32) -> Vec<u8> {
        match self.tmpl {
            Tmpl::Fixed(b) => b.to_vec(),
            Tmpl::Mt1959Stream => vec![
                0x3B,
                0x06,
                0x00,
                (offset >> 16) as u8,
                (offset >> 8) as u8,
                offset as u8,
                0x00,
                (len >> 8) as u8,
                len as u8,
                0x00,
                0x00,
                0x00,
            ],
            Tmpl::Mt1959Readback => vec![
                0x3C,
                0x06,
                0x00,
                (offset >> 16) as u8,
                (offset >> 8) as u8,
                offset as u8,
                (len >> 16) as u8,
                (len >> 8) as u8,
                len as u8,
                0x00,
            ],
        }
    }
}

/// A complete, declarative flash recipe for one chipset family.
#[derive(Debug, Clone, Copy)]
pub struct FlashInstructionSet {
    /// Human name (`"MediaTek MT1959"`).
    pub name: &'static str,
    /// The silicon family this set drives.
    pub family: Family,
    /// How CDBs are delivered.
    pub transport: Transport,
    /// The firmware-write opcode (e.g. `0x3B` WRITE BUFFER).
    pub write_opcode: u8,
    /// No brand needs a host-side key — always `false`.
    pub host_side_key: bool,
    /// Execution tier.
    pub status: FlashStatus,
    /// The ordered CDB handshake with per-step response gates.
    pub steps: &'static [FlashStep],
}

const MT1959_STEPS: &[FlashStep] = &[
    FlashStep {
        label: "PROBE",
        purpose: "READ BUFFER mode 6 @ 0x1EC000 — read the identity page",
        dir: Dir::In,
        gate: "0x100 bytes returned",
        per_chunk: false,
        tmpl: Tmpl::Fixed(&[
            0x3C, 0x06, 0x00, 0x1E, 0xC0, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ]),
    },
    FlashStep {
        label: "READY",
        purpose: "TEST UNIT READY — poll until the drive accepts the download",
        dir: Dir::None,
        gate: "GOOD (or a benign not-ready reason)",
        per_chunk: false,
        tmpl: Tmpl::Fixed(&[0x00; 12]),
    },
    FlashStep {
        label: "PREPARE",
        purpose: "WRITE BUFFER mode 1 — enter-download / pre-erase (CDB[9]=0x0B)",
        dir: Dir::Out,
        gate: "GOOD (strict — must land before any stream)",
        per_chunk: false,
        tmpl: Tmpl::Fixed(&[
            0x3B, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00,
        ]),
    },
    FlashStep {
        label: "STREAM",
        purpose: "WRITE BUFFER mode 6 — download 16 KiB at the big-endian offset",
        dir: Dir::Out,
        gate: "GOOD per chunk",
        per_chunk: true,
        tmpl: Tmpl::Mt1959Stream,
    },
    FlashStep {
        label: "COMMIT",
        purpose: "WRITE BUFFER mode 7 — save microcode (magic 1B 12 in CDB[10..11])",
        dir: Dir::Out,
        gate: "GOOD",
        per_chunk: false,
        tmpl: Tmpl::Fixed(&[
            0x3B, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1B, 0x12,
        ]),
    },
    FlashStep {
        label: "STATUS",
        purpose: "REQUEST SENSE — progress/status poll",
        dir: Dir::In,
        gate: "no hard error",
        per_chunk: false,
        tmpl: Tmpl::Fixed(&[
            0x03, 0x00, 0x00, 0x10, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]),
    },
    FlashStep {
        label: "READBACK",
        purpose: "READ BUFFER mode 6 — read back a CMAC-protected range to verify",
        dir: Dir::In,
        gate: "informational (identity read is authoritative)",
        per_chunk: false,
        tmpl: Tmpl::Mt1959Readback,
    },
];

impl FlashInstructionSet {
    /// The proven MediaTek MT1959 recipe (the hardware-executed path). The golden
    /// KAT asserts these steps render byte-identical to `drive::mtk`'s builders.
    pub const fn mt1959() -> Self {
        FlashInstructionSet {
            name: "MediaTek MT1959",
            family: Family::Mtk,
            transport: Transport::Spti,
            write_opcode: 0x3B,
            host_side_key: false,
            status: FlashStatus::Executable,
            steps: MT1959_STEPS,
        }
    }

    /// The instruction set for a classified drive [`Family`]. MTK returns the
    /// executable MT1959 recipe; other silicon families have no executable set
    /// yet (their brand recipes live in [`crate::flashset::CATALOG`], catalog-only).
    pub fn for_family(family: Family) -> Option<Self> {
        match family {
            Family::Mtk => Some(Self::mt1959()),
            _ => None,
        }
    }
}

/// A per-brand catalog entry — the declarative "how to flash this brand" summary
/// transcribed from `cdrinfo/<Brand>/cdb.json`. Byte-level step templates are
/// only materialised for the executable MT1959 family (above); brand entries
/// carry the recipe at the documented granularity (transport, opcode, step
/// count, gate discipline, status) so the catalog is complete and honest without
/// claiming hardware proof we do not have.
#[derive(Debug, Clone, Copy)]
pub struct BrandRecipe {
    /// Vendor brand.
    pub brand: &'static str,
    /// Delivery transport.
    pub transport: Transport,
    /// Firmware-write opcode.
    pub write_opcode: u8,
    /// Always false (no brand needs a host secret).
    pub host_side_key: bool,
    /// Number of steps in the ordered handshake.
    pub steps: u8,
    /// Whether an XFlash-oracle trace corroborates the recipe.
    pub oracle_verified: bool,
    /// Execution tier.
    pub status: FlashStatus,
    /// One-line note (opcode family / lineage).
    pub note: &'static str,
}

/// The 18-brand declarative flash catalog (from `cdrinfo/<Brand>/cdb.json`),
/// plus MediaTek MT1959 as the one executable, hardware-proven family.
///
/// Tiers: MT1959 = `Executable`; the SPTI single-data-out families are
/// `CatalogOnly` (buildable + dry-run, not hardware-verified); the ASPI-primary
/// families are `TransportGated` (we cannot issue their transport). `host_side_key`
/// is false on every one.
pub const CATALOG: &[BrandRecipe] = &[
    // The executable family (our proven path; LG/Asus UHD recipes are the same 0x3B handshake).
    BrandRecipe {
        brand: "MediaTek MT1959",
        transport: Transport::Spti,
        write_opcode: 0x3B,
        host_side_key: false,
        steps: 7,
        oracle_verified: true,
        status: FlashStatus::Executable,
        note: "WRITE BUFFER 3B 01/06/07 — hardware-proven",
    },
    // SPTI single-data-out brands: recipe known + issuable, not hardware-verified → catalog-only.
    BrandRecipe {
        brand: "LG",
        transport: Transport::Spti,
        write_opcode: 0x3B,
        host_side_key: false,
        steps: 6,
        oracle_verified: false,
        status: FlashStatus::CatalogOnly,
        note: "WRITE BUFFER (MTK lineage; == MT1959 handshake)",
    },
    BrandRecipe {
        brand: "Asus",
        transport: Transport::Spti,
        write_opcode: 0x3B,
        host_side_key: false,
        steps: 7,
        oracle_verified: false,
        status: FlashStatus::CatalogOnly,
        note: "WRITE BUFFER (UHD recipe == MT1959 handshake)",
    },
    BrandRecipe {
        brand: "LiteOn",
        transport: Transport::Spti,
        write_opcode: 0x3B,
        host_side_key: false,
        steps: 5,
        oracle_verified: true,
        status: FlashStatus::CatalogOnly,
        note: "WRITE BUFFER 3B 05 (XFlash oracle: IDENTIFY/ERASE/WRITE/RESET)",
    },
    BrandRecipe {
        brand: "Plextor",
        transport: Transport::Spti,
        write_opcode: 0x3B,
        host_side_key: false,
        steps: 5,
        oracle_verified: true,
        status: FlashStatus::CatalogOnly,
        note: "WRITE BUFFER; modern SATA = Mtk (XFlash oracle)",
    },
    BrandRecipe {
        brand: "Sony",
        transport: Transport::Spti,
        write_opcode: 0xF2,
        host_side_key: false,
        steps: 6,
        oracle_verified: true,
        status: FlashStatus::CatalogOnly,
        note: "0x3B (old) or 0xF2 (MediaTek) (XFlash oracle)",
    },
    BrandRecipe {
        brand: "BENQ",
        transport: Transport::Spti,
        write_opcode: 0x3B,
        host_side_key: false,
        steps: 6,
        oracle_verified: false,
        status: FlashStatus::CatalogOnly,
        note: "WRITE BUFFER (Philips/Nexperia lineage)",
    },
    BrandRecipe {
        brand: "Pioneer",
        transport: Transport::Spti,
        write_opcode: 0x3B,
        host_side_key: false,
        steps: 6,
        oracle_verified: false,
        status: FlashStatus::CatalogOnly,
        note: "WRITE BUFFER, multiplexed mode",
    },
    BrandRecipe {
        brand: "Panasonic",
        transport: Transport::Spti,
        write_opcode: 0xEA,
        host_side_key: false,
        steps: 5,
        oracle_verified: false,
        status: FlashStatus::CatalogOnly,
        note: "0xEA (Matsushita vendor); encrypted-at-rest, streamed verbatim",
    },
    BrandRecipe {
        brand: "Samsung",
        transport: Transport::Spti,
        write_opcode: 0xFF,
        host_side_key: false,
        steps: 6,
        oracle_verified: false,
        status: FlashStatus::CatalogOnly,
        note: "0xFF (vendor; subcommand in CDB[2])",
    },
    BrandRecipe {
        brand: "Sanyo",
        transport: Transport::Spti,
        write_opcode: 0x3B,
        host_side_key: false,
        steps: 3,
        oracle_verified: false,
        status: FlashStatus::CatalogOnly,
        note: "WRITE BUFFER (80/A0 flag)",
    },
    BrandRecipe {
        brand: "Mitsumi",
        transport: Transport::Spti,
        write_opcode: 0x3B,
        host_side_key: false,
        steps: 4,
        oracle_verified: false,
        status: FlashStatus::CatalogOnly,
        note: "WRITE BUFFER (Philips) + 0xE6 unlock",
    },
    BrandRecipe {
        brand: "AOpen",
        transport: Transport::Spti,
        write_opcode: 0x42,
        host_side_key: false,
        steps: 5,
        oracle_verified: false,
        status: FlashStatus::CatalogOnly,
        note: "0x42 (BenQ family) or 0xE3/0xE4 (Ricoh family)",
    },
    BrandRecipe {
        brand: "TDK",
        transport: Transport::Spti,
        write_opcode: 0x3B,
        host_side_key: false,
        steps: 3,
        oracle_verified: false,
        status: FlashStatus::CatalogOnly,
        note: "inherited from OEM (rebadge)",
    },
    // ASPI-primary brands: transport we cannot issue → transport-gated.
    BrandRecipe {
        brand: "NEC",
        transport: Transport::Aspi,
        write_opcode: 0xCB,
        host_side_key: false,
        steps: 5,
        oracle_verified: false,
        status: FlashStatus::TransportGated,
        note: "0xCB (vendor); status 0xCC; ASPI + aspisim",
    },
    BrandRecipe {
        brand: "Optiarc",
        transport: Transport::Aspi,
        write_opcode: 0xCB,
        host_side_key: false,
        steps: 5,
        oracle_verified: true,
        status: FlashStatus::TransportGated,
        note: "0xCB (vendor); status 0xCC; ASPI (XFlash oracle)",
    },
    BrandRecipe {
        brand: "Ricoh",
        transport: Transport::Aspi,
        write_opcode: 0xAA,
        host_side_key: false,
        steps: 5,
        oracle_verified: false,
        status: FlashStatus::TransportGated,
        note: "0xAA WRITE(12) / 0xE2 (vendor); ASPI + spti",
    },
    BrandRecipe {
        brand: "Teac",
        transport: Transport::Aspi,
        write_opcode: 0xEA,
        host_side_key: false,
        steps: 4,
        oracle_verified: false,
        status: FlashStatus::TransportGated,
        note: "0xEA (native vendor); verify 0xC8; ASPI->spti on newer",
    },
    BrandRecipe {
        brand: "Yamaha",
        transport: Transport::Aspi,
        write_opcode: 0x3B,
        host_side_key: false,
        steps: 4,
        oracle_verified: false,
        status: FlashStatus::TransportGated,
        note: "WRITE BUFFER; ASPI primary (SendASPI32Command)",
    },
];

/// Look up a brand's recipe (case-insensitive) in [`CATALOG`].
pub fn brand_recipe(brand: &str) -> Option<&'static BrandRecipe> {
    CATALOG.iter().find(|r| r.brand.eq_ignore_ascii_case(brand))
}

#[cfg(test)]
#[path = "flashset_tests.rs"]
mod tests;
