//! Platform engines: the *knowledge* half of the tool.
//!
//! The [`crate::thumb`] toolkit supplies platform-neutral verbs (find / read /
//! modify / insert / assemble). An **engine** supplies the platform-specific
//! knowledge those verbs operate on — the scanner signature that proves the
//! dispatch-record format, the CDB base, the sense-setter, the handler to
//! hijack — all *derived from the image*, never hardcoded.
//!
//! Adding support for a new controller (MT1939, Pioneer/Renesas) is therefore a
//! new [`Engine`] implementation, never new patching logic. [`detect`] picks the
//! right engine from an image's chip family; unsupported families return a clear
//! error rather than a wrong guess. This mirrors the flash-side `DriveFamily`
//! split: one engine per chip, all sharing the dumb toolkit.

use anyhow::{bail, Result};

use crate::family::{self, ChipFamily};
use crate::thumb::CommandRecord;

pub mod mt1959;
pub mod mt1959_build;
pub mod pioneer;

/// The result of building freemkv firmware from an OEM image: the re-signed
/// image plus the grounded facts used to build it, so a caller (and the KAT) can
/// assert exactly what was found and changed.
#[derive(Debug, Clone)]
pub struct CreateReport {
    /// The re-signed freemkv image.
    pub image: Vec<u8>,
    /// Scanner entry the record format + `cdb_base` were proven from.
    pub scanner_entry: u32,
    /// CDB base derived from the scanner.
    pub cdb_base: u32,
    /// Sense-setter routine derived from the scanner.
    pub sense_setter: u32,
    /// The hijacked dispatch record (the standard opcode whose handler we repoint).
    pub record: CommandRecord,
    /// Injection address of the freemkv handler.
    pub handler_va: u32,
    /// Bytes of the injected handler.
    pub handler_bytes: Vec<u8>,
    /// OEM Volume-ID producer entry (subfn 0x03 calls it to stage the clear VID).
    pub vid_producer: u32,
    /// The producer's clear-VID scratch buffer (runtime address, read by 0x03).
    pub vid_out_buf: u32,
    /// OEM per-AGID AKE gate-setter primitive (0x03 opens the gate through it).
    pub vid_gate_setter: u32,
    /// `SetDiscMode` dispatcher — the Bus Encryption (0x04) hook point (see report).
    pub setdiscmode: u32,
    /// Speed (0x02) ramp-ceiling gate anchor (the `ldr r1,[pc]` of the ramp
    /// self-ceiling test); the detour replaces the `cmp/bhi` at `gate+4`.
    pub speed_gate: u32,
    /// Injection address of the Speed (0x02) flag-gated ceiling trampoline.
    pub speed_stub_va: u32,
    /// OEM RPC-state emitter anchor for Region-free (0x05); the detour replaces
    /// the RPCScheme store at `region_emitter+14`.
    pub region_emitter: u32,
    /// Injection address of the Region-free (0x05) flag-gated emitter trampoline.
    pub region_stub_va: u32,
    /// AACS AKE accept-gate anchor for Raw Read (0x04); the detour replaces the
    /// RESET state writer (`movs r1,#1; b <back>`) at `ake_gate+12`.
    pub ake_gate: u32,
    /// Injection address of the Raw Read (0x04) flag-gated AKE accept trampoline.
    pub ake_stub_va: u32,
    /// The VID producer's own gate site (`cmp r0,#6; bne <deny>`), detoured by the
    /// Gate-A trampoline. `VID_GATE_SIG` match+18.
    pub gatea_gate: u32,
    /// Injection address of the Raw Read (0x04) flag-gated producer Gate-A
    /// trampoline (the bare-`0xAD`, no-AKE path).
    pub gatea_stub_va: u32,
    /// The VID producer deny block's sense-setup site (`movs r2,#2; movs r1,#0x6f`
    /// at the OEM deny target + 0x10), detoured to the deny-path AACS-reset stub
    /// (Option C) so a failed-cert deny idles the engine.
    pub deny_reset_gate: u32,
    /// Injection address of the Raw Read (0x04) deny-path AACS-reset trampoline.
    pub deny_stub_va: u32,
    /// File offset of the downgrade-enable (DE) byte written unconditionally.
    pub de_off: u32,
    /// SRAM flag-table base actually used by this build (currently the provisional
    /// placeholder; see `FLAG_BASE_PLACEHOLDER`).
    pub flag_base: u32,
    /// The provably-free SRAM cell the build-time scanner independently derived
    /// from THIS image (for audit / eventual placeholder swap). Not yet consumed
    /// as the flag base — reported so the swap is a one-liner once validated.
    pub free_sram_cell: u32,
}

/// The platform-specific knowledge the toolkit verbs are pointed at. One
/// implementation per controller family.
pub trait Engine {
    /// Human label, e.g. `"MT1959"`.
    fn name(&self) -> &'static str;

    /// Build freemkv firmware from an OEM `image`: prove the find against the
    /// drive's own code, inject the handler, repoint the hijacked record, and
    /// re-sign. Fails loudly (never guesses) if the image isn't a recognised,
    /// unambiguous target for this engine.
    fn create(&self, image: &[u8]) -> Result<CreateReport>;
}

/// Select the engine for `image`'s detected chip family, or fail cleanly if the
/// family is unidentified or not yet supported.
pub fn detect(image: &[u8]) -> Result<Box<dyn Engine>> {
    let chip = family::detect_chip(image)?;
    for_family(chip.family)
}

/// Select the engine for a known chip family.
pub fn for_family(fam: ChipFamily) -> Result<Box<dyn Engine>> {
    match fam {
        ChipFamily::Mt1959 => Ok(Box::new(mt1959::Mt1959Engine)),
        // MT1939 shares the toolkit but not the MT1959 SRAM map; its engine is
        // not implemented yet, so refuse rather than apply MT1959 addresses.
        ChipFamily::Mt1939 => bail!(
            "no modification engine for {} yet — freemkv-fw currently modifies {} only; the \
             toolkit is platform-neutral, but this controller needs its own engine (SRAM map / \
             hook points)",
            fam,
            ChipFamily::Mt1959.label(),
        ),
    }
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
