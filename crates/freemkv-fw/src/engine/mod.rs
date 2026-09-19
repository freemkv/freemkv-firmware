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

use anyhow::Result;

use crate::family::{self, ChipFamily};
use crate::thumb::CommandRecord;

pub mod audit;
pub mod core;
pub mod lever;
pub mod mt1939;
pub mod mt1939_classic;
pub mod mt1939_modern;
pub mod mt1959;
pub mod pioneer;
pub mod profile;

pub use lever::ModifyReport;

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
    /// Always-on boot-init hook site — the cold/warm-boot convergence `bl <orig_init>`
    /// (the `bmi` target of the `BOOT_INIT_SIG` anchor, the first call AFTER the
    /// cold-boot SRAM clear; `0x13d428` on BU40N) replaced by a `bl` to the boot-init
    /// stub, which tail-calls `orig_init`. The stub fills the flag table with the
    /// baked per-create `DEFAULT_FLAGS` (UHD/BD ship `STATE_ON`, the rest `0xFF`
    /// passthrough) and then overlays the persisted config only when the NV slot-0
    /// saved-marker says one exists. No default is `0x00`, so a freshly powered drive
    /// still never boots a feature to OFF (the invariant that keeps tri-state
    /// `0x00 == OFF` safe). Detouring here, not the pre-clear reload, keeps the SRAM
    /// clear from wiping the flag table.
    pub boot_init_site: u32,
    /// Injection address of the always-on boot-init trampoline.
    pub boot_stub_va: u32,
    /// OEM Volume-ID producer entry (subfn 0x03 calls it to stage the clear VID).
    pub vid_producer: u32,
    /// The producer's clear-VID scratch buffer (runtime address, read by 0x03).
    pub vid_out_buf: u32,
    /// OEM per-AGID AKE gate-setter primitive (0x03 opens the gate through it).
    pub vid_gate_setter: u32,
    /// `SetDiscMode` dispatcher — the read-datapath disc-mode anchor. Located and
    /// proven unique, but DELIBERATELY NOT wired: bus-off is done the MK way instead,
    /// by clearing the bus-encryption enable bit of the read-datapath MMIO register on
    /// the AACS opcode-0x45 path (see `busenc_detour_site`). Reported for audit /
    /// future use.
    pub setdiscmode: u32,
    /// Speed (0x02) ramp-ceiling gate anchor (the `ldr r1,[pc]` of the ramp
    /// self-ceiling test); the detour replaces the `cmp/bhi` at `gate+4`.
    pub speed_gate: u32,
    /// Injection address of the Speed (0x02) flag-gated ceiling trampoline.
    pub speed_stub_va: u32,
    /// OEM RPC-state emitter anchor for Region-free (0x03); the detour replaces
    /// the `frame[4]` store at `region_emitter+6`.
    pub region_emitter: u32,
    /// Injection address of the Region-free (0x03) flag-gated emitter trampoline.
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
    /// AACS opcode-0x45 (Read Data Key) arm detour site for Raw Read `04 03` "data
    /// clear" (drive-side bus-encryption removal, MK-style); the detour replaces the
    /// arm's leading `bl <key-prog>`, and the stub clears the bus-enc enable bit of
    /// the read-datapath MMIO register when `flag[RawRead]==3`.
    pub busenc_detour_site: u32,
    /// Injection address of the Raw Read `04 03` bus-off (MK-style bit-clear)
    /// trampoline.
    pub busenc_stub_va: u32,
    /// Raw Read `04 03` UHD mode-gate neutralizer detour site — the disc-version
    /// classifier prologue's reload (`ldr r0,[sp,#0x38]`, `UHD_CLASSIFIER_SIG`
    /// match+6). The stub replays the reload and, when `flag[RawRead]==3`, zeros the
    /// disc-version so a UHD (AACS 2.0) disc dodges the mode-1 refusal — the MK-style
    /// classifier hook. `0` when not wired (classifier prologue not the known shape).
    pub uhd_classifier_site: u32,
    /// Injection address of the Raw Read `04 03` UHD mode-gate neutralizer trampoline.
    /// `0` when not wired.
    pub uhd_stub_va: u32,
    /// `Feature::Bd` REPORT KEY refuse detour site — the mode-0 class check
    /// (`ldrb r0,[r2,#7]; cmp r0,#2`, `BD_GATE_SIG` `anchor+16`). The stub replays the
    /// class load and, when `flag[Bd]==STATE_OFF`, forces the OEM deny path so the
    /// drive refuses a BD disc; unarmed it replays OEM (stealth). `0` when not wired
    /// (REPORT KEY gate not the known shape).
    pub bd_gate_site: u32,
    /// Injection address of the `Feature::Bd` BD-refuse trampoline. `0` when not wired.
    pub bd_stub_va: u32,
    /// The three HRL-skip cert-path detour sites (`flag[Feature::Hrl]==STATE_ON`):
    /// each a `cmp r0,#0; bne <6F/00>` replaced by a `bl` to the shared HRL-skip
    /// stub. Empty when the HRL cert path is not the known shape (lever MISS).
    pub hrl_sites: Vec<u32>,
    /// Injection address of the shared HRL-skip trampoline. `0` when not wired.
    pub hrl_stub_va: u32,
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
    /// unambiguous target for this engine. Strict / all-or-nothing — used by the
    /// KAT and by callers that want the full grounded [`CreateReport`].
    fn create(&self, image: &[u8]) -> Result<CreateReport>;

    /// Never-abort MODIFY: apply every lever this engine + the image's capability
    /// support, and report each one's outcome. Aborts the whole run only when the
    /// image is undetectable or nothing at all can be built. This is the
    /// user-facing path (`freemkv-fw create`): it "modifies what it can and
    /// reports what it did" rather than refusing on the first missing signature.
    fn modify(&self, image: &[u8]) -> Result<ModifyReport>;
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
        // MT1939 shares the toolkit + the (byte-identical) CMAC scheme but not the
        // MT1959 SRAM map / hook points. Its full engine is pending; today it can
        // still apply the family-agnostic downgrade-enable byte via `modify`, and
        // reports the rest as pending — so it is no longer opaquely refused.
        ChipFamily::Mt1939 => Ok(Box::new(mt1939::Mt1939Engine)),
    }
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
