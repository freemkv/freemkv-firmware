//! MediaTek **MT1939-classic** ("MT1939 Boot Code") lineage builder.
//!
//! Classic silicon has its own scanner (`0x182e8`, CDB base in **r5**), dispatch
//! table window (`~0x1a4000`), inline sense, and boot-init leaf helper. This module
//! holds the classic-only create/modify orchestration and the classic-specific emit
//! helpers; every shared finder / stub builder / `build_handler` lives in
//! [`super::core`]. All methods hang off the shared [`Mt1959Engine`] type.

use anyhow::{anyhow, bail, Context, Result};

use freemkv_flash::cmac;

use super::core::*;
use super::lever::{HookReport, LeverId, LeverReport, ModifyReport, Validation};
use super::mt1959::Mt1959Engine;
use super::CreateReport;
use crate::abi;
use crate::boot::BootSettings;
use crate::family::{Capability, ChipInfo};
use thumb_asm::{self as thumb, Asm, CommandTable};

// UH12NS30 JBC5 variant of `VID_GATE_SIG_CLASSIC`: the first state-pointer load
// goes through r7. State byte and CMP/BNE offsets are identical.
const VID_GATE_SIG_CLASSIC_R7: &[(u16, u16)] = &[
    (0x7aa8, 0xffff),
    (0x4900, 0xff00),
    (0x0980, 0xffff),
    (0x4f00, 0xff00),
    (0x1840, 0xffff),
    (0x6839, 0xffff),
    (0x0400, 0xffff),
    (0x0c00, 0xffff),
    (0x1808, 0xffff),
    (0x4900, 0xff00),
    (0x0200, 0xffff),
    (0x6809, 0xffff),
    (0x0a00, 0xffff),
    (0x1840, 0xffff),
    (0x7800, 0xffff),
    (0x2806, 0xffff),
    (0xd100, 0xff00),
];

// WH16NS48 1.D3 keeps the authenticated response construction between the
// success and rejection writers (OEM 0x181c08..0x181c6e). Bind both complete
// response arms, their common call and both state-setter calls below.
const AKE_GATE_SIG_CLASSIC_SPLIT: &[(u16, u16)] = &[
    (0x7aa8, 0xffff),
    (0x0980, 0xffff),
    (0x2106, 0xffff),
    (0xf000, 0xf800),
    (0xf800, 0xf800),
    (0x7aa8, 0xffff),
    (0x0980, 0xffff),
    (0x2802, 0xffff),
    (0xd200, 0xff00),
    (0x7aa8, 0xffff),
    (0x0980, 0xffff),
    (0x1980, 0xffff),
    (0x6821, 0xffff),
    (0x0400, 0xffff),
    (0x0c00, 0xffff),
    (0x1808, 0xffff),
    (0x6839, 0xffff),
    (0x0200, 0xffff),
    (0x0a00, 0xffff),
    (0x1840, 0xffff),
    (0x7801, 0xffff),
    (0xe000, 0xf800),
    (0x2100, 0xffff),
    (0x4800, 0xff00),
    (0xe000, 0xf800),
    (0x7aa8, 0xffff),
    (0x0980, 0xffff),
    (0x2101, 0xffff),
    (0xf000, 0xf800),
    (0xf800, 0xf800),
    (0x7aa8, 0xffff),
    (0x0980, 0xffff),
    (0x2802, 0xffff),
    (0xd200, 0xff00),
    (0x7aa8, 0xffff),
    (0x0980, 0xffff),
    (0x1980, 0xffff),
    (0x6821, 0xffff),
    (0x0400, 0xffff),
    (0x0c00, 0xffff),
    (0x1808, 0xffff),
    (0x6839, 0xffff),
    (0x0200, 0xffff),
    (0x0a00, 0xffff),
    (0x1840, 0xffff),
    (0x7801, 0xffff),
    (0xe000, 0xf800),
    (0x2100, 0xffff),
    (0x4800, 0xff00),
    (0xf000, 0xf800),
    (0xf800, 0xf800),
];

/// Attach the conversion hook to RawRead; an applied conversion makes the
/// lever Applied so the auditor checks its atomic group.
fn attach_classic_conversion(levers: &mut [LeverReport], conversion: HookReport, count: u32) {
    if let Some(raw_read) = levers.iter_mut().find(|l| l.id == LeverId::RawRead) {
        raw_read.hooks.push(conversion);
        raw_read.facts.push(("uhd_conversion_count", count));
        if count > 0 && raw_read.outcome != super::lever::LeverOutcome::Applied {
            // Keep the gate-miss cause visible once the lever reads as Applied.
            if let super::lever::LeverOutcome::SignatureNotFound { detail } = &raw_read.outcome {
                let note = HookReport::unavailable("rawread-gates", detail.clone());
                raw_read.hooks.push(note);
            }
            raw_read.outcome = super::lever::LeverOutcome::Applied;
        }
    }
}

impl Mt1959Engine {
    pub(super) fn emit_media_conversion_classic(
        &self,
        source: &[u8],
        out: &mut Vec<u8>,
        flags: u32,
    ) -> (HookReport, u32) {
        let result = super::mt1939_uhd::UhdConversionPlan::inspect(source)
            .and_then(|plan| plan.apply(source, out, flags));
        match result {
            Ok(count) => (
                HookReport::applied(
                    "uhd-conversion",
                    format!(
                        "complete media group: classic {count} source-bound helpers; software qualification pending"
                    ),
                ),
                count as u32,
            ),
            Err(e) => (
                HookReport::unavailable("uhd-conversion", format!("0 conversion edits: {e:#}")),
                0,
            ),
        }
    }
    /// Thumb-1 selector detour: choose the native maximum only when enabled.
    /// The library proves every leaf path reaches this tail and binds RMAX to
    /// its native setter and the selector consumer to OPTM. No write speed or
    /// hardware/media maximum initializer is changed.
    pub fn build_speed_stub_classic(&self, flag_base: u32, maximum_cell: u32) -> Result<Vec<u8>> {
        let mut a = Asm::new();
        let oem = a.label();
        // The Thumb-1 entry saves the native LR before BL overwrites it.
        a.push(8);
        a.mov_reg(3, 13);
        a.ldr_imm(3, 3, 4);
        a.mov_reg(14, 3);
        a.pop(8);
        a.add_sp(4);
        a.push(2);
        a.ldr_lit(1, flag_base + abi::Feature::Speed as u32);
        a.ldrb_imm(1, 1, 0);
        a.cmp_imm(1, abi::STATE_ON);
        a.bne(oem);
        a.ldr_lit(1, maximum_cell);
        a.ldrb_imm(1, 1, 0);
        a.cmp_imm(1, 0);
        a.beq(oem);
        a.cmp_imm(1, 48);
        a.bhi(oem);
        a.mov_reg(0, 1);
        a.bind(oem);
        a.pop(2);
        a.lsls_imm(0, 0, 24);
        a.lsrs_imm(0, 0, 24);
        a.bx(14);
        a.finish().map_err(anyhow::Error::from)
    }

    fn emit_speed_classic(
        &self,
        image: &[u8],
        out: &mut [u8],
        flag_base: u32,
    ) -> Result<Vec<(&'static str, u32)>> {
        let role = mediatek_optical::image::analysis::ClassicSpeed::detect(image)
            .map_err(|e| anyhow!("native read-speed selector: {e}"))?;
        let bytes = self.build_speed_stub_classic(flag_base, role.maximum_cell())?;
        let va = self.free_space(out, bytes.len())?;
        let branch = thumb::encode_bl(role.site() + 2, va)
            .ok_or_else(|| anyhow!("classic Speed tail branch out of range"))?;
        let mut entry = Asm::new();
        entry.push(0x100);
        let mut entry = entry.finish()?;
        entry.truncate(2); // finish pads the instruction-only fragment to four bytes.
        entry.extend_from_slice(&branch);
        let mut candidate = out.to_vec();
        thumb::write(&mut candidate, va as usize, &bytes);
        thumb::write(&mut candidate, role.site(), &entry);
        crate::install_guard::verify_branch(
            &candidate,
            role.site() + 2,
            thumb::BranchKind::Bl,
            va,
            "classic Speed",
        )?;
        out.copy_from_slice(&candidate);
        Ok(vec![
            ("speed_tail_site", role.site() as u32),
            ("speed_stub_va", va),
            ("speed_selector", role.entry() as u32),
            ("speed_maximum_cell", role.maximum_cell()),
            ("speed_optimum_cell", role.optimum_cell()),
            ("speed_consumer", role.consumer() as u32),
        ])
    }

    /// The **classic**-generation per-AGID session-struct base. The classic VID
    /// producer reads the AGID selector from the CDB base the scanner loads into
    /// `r5` (`ldrb r0,[r5,#0xa]`), so the struct base IS the CDB base — NOT the
    /// `ldr r7,[pc]` literal [`Self::find_vid_agid_struct`] recovers, which on a
    /// classic image resolves to a *different* SRAM cell and would make the
    /// Gate-A `04 01` rearm poke the wrong bytes. Derived per image via
    /// [`Self::find_cdb_base`]; never hardcoded.
    pub fn find_vid_agid_struct_classic(&self, image: &[u8]) -> Result<u32> {
        self.find_cdb_base(image)
    }

    /// **Classic**-generation Raw Read (0x04) AKE accept-gate trampoline (`04 02`).
    /// Entered by a `bl` that replaces the classic reject writer `lsrs r0,r0,#6;
    /// movs r1,#1` (4 bytes at `AKE_GATE_SIG_CLASSIC`'s `match+6`) — unlike the
    /// MT1959 reject writer, the classic one folds the `lsrs` (AGID compute) into
    /// the replaced bytes, so the stub REPLAYS it. It then forces `r1 = 6` when
    /// `flag[Ake]==STATE_OFF` (accept any host cert) else the OEM `1` (reject), and
    /// falls through to the shared OEM `bl set_agid_state` call at `back`
    /// (`match+0xa`) that BOTH arms converge on — a single clean call, so the
    /// store happens through the OEM primitive unchanged. `r2` scratch; `r0`=AGID
    /// preserved. `04 01` does NOT act here (that is the Gate-A bare-read path).
    pub(crate) fn build_ake_stub_classic(&self, flag_base: u32, back: u32) -> Result<Vec<u8>> {
        let mut a = Asm::new();
        let accept = a.label();
        let done = a.label();
        a.lsrs_imm(0, 0, 6); // replay the overwritten `lsrs r0,r0,#6` (r0 = AGID)
        a.ldr_lit(2, flag_base + abi::Feature::Encryption as u32); // r2 = &flag[Encryption]
        a.ldrb_imm(2, 2, 0); // r2 = AKE flag byte
        a.cmp_imm(2, abi::STATE_OFF); // 0x00 = null AKE / bypass (accept any/revoked host cert); ON/OEM = real handshake
        a.beq(accept);
        a.movs_imm(1, 1); // OEM (00/0xFF): reset to state 1 on a failed cert verify
        a.b(done);
        a.bind(accept);
        a.movs_imm(1, 6); // forced: state 6 (AKE authenticated)
        a.bind(done);
        a.ldr_lit(2, back | 1); // -> shared OEM `bl set_agid_state` call site
        a.bx(2);
        a.finish().map_err(anyhow::Error::from)
    }

    /// MT1939-**classic** create: the classic analogue of [`Self::build_report`],
    /// which assumes modern table windows and `FLAG_TABLE_BASE` and fails the
    /// flag-table SRAM assert on classic. Uses the base finders proven 17/17 in
    /// `mt1939-classic-identity-base.md` and mirrors the base tier of
    /// [`Self::build_modify_classic`], producing a [`CreateReport`].
    ///
    /// Installs the command handler, repoints its record and re-signs CMAC.
    /// The boot hook initializes the requested settings before feature hooks run;
    /// if it cannot be installed, the report contains no feature hooks.
    ///
    /// Feature availability follows the emitted hooks. Read speed uses the native
    /// selector/RMAX contract, not the modern ramp gate. Media conversion requires
    /// the complete source-bound group; physical reading remains unqualified.
    pub fn build_report_classic(&self, image: &[u8]) -> Result<CreateReport> {
        self.build_report_classic_with_defaults(image, &BootSettings::standard())
    }

    pub(crate) fn build_report_classic_with_defaults(
        &self,
        image: &[u8],
        defaults: &BootSettings,
    ) -> Result<CreateReport> {
        // Idempotency: a re-fed freemkv image reports the existing base unchanged.
        if is_freemkv_patched(image) {
            bail!("image already carries a freemkv base (classic); nothing to create");
        }

        // ---- BASE (mandatory) — classic finders, all PROVEN 17/17.
        let analysis = mediatek_optical::image::analysis::ImageAnalysis::inspect(image);
        let commands = analysis
            .commands()
            .context("classic base: native command ownership")?;
        let scanner_entry = commands.scanner().entry() as u32;
        let cdb_base = commands.scanner().cdb();
        analysis.response().context("classic base: response I/O")?;
        // Report anchor only (build_handler never uses it); classic raises sense
        // inline, so the modern shape legitimately misses. 0 when absent.
        let sense_setter = Self::sense_setter_at(image, commands.scanner().entry()).unwrap_or(0);

        // Classic 0x3C dispatch table (~0x1a4000) is outside the modern
        // find_live_record windows.
        let record = Self::live_record_from(commands, abi::READ_BUFFER_OPCODE)
            .context("classic base: live 0x3C dispatch record")?;

        // Modern FLAG_TABLE_BASE collides with live classic SRAM; derive a free
        // cell from this image.
        let ram = super::sram::SramPlacement::inspect(image);
        let flag_base = ram
            .candidate()
            .context("classic base: free SRAM cell for the flag table")?;
        ram.assert_free(
            flag_base,
            super::core::FLASHWRITE_SCRATCH_OFF + 1,
            "classic flag table and flash scratch",
        )?;

        // No classic reboot function entry is qualified. Its caller site has no
        // fixed offset to a function prologue, so leave the reboot verb inert.
        let boot_function_entry: u32 = 0;
        let handler_bytes = self
            .build_handler_from_analysis(
                &analysis,
                record.handler,
                flag_base,
                boot_function_entry,
                identity_blob(),
                defaults,
            )
            .context("classic base: assembling the 3C-0E handler")?;

        let mut out = image.to_vec();
        let handler_va = self.free_space(&out, handler_bytes.len() + 16)?;
        thumb::write(&mut out, handler_va as usize, &handler_bytes);

        // ---- FEATURE emits: boot hook first, then classic feature stubs. Facts
        //      default to unwired (0 / empty), so a miss leaves that feature off
        //      the advertised set while the base still ships.
        let mut boot_init_site = 0u32;
        let mut boot_stub_va = 0u32;
        let mut region_emitter = 0u32;
        let mut region_stub_va = 0u32;
        let mut ake_gate = 0u32;
        let mut ake_stub_va = 0u32;
        let mut gatea_gate = 0u32;
        let mut gatea_stub_va = 0u32;
        let mut deny_reset_gate = 0u32;
        let mut vid_producer = 0u32;
        let mut uhd_classifier_site = 0u32;
        let mut uhd_stub_va = 0u32;
        let mut bd_gate_site = 0u32;
        let mut bd_stub_va = 0u32;
        let mut speed_tail_site = 0;
        let mut speed_stub_va = 0;
        let mut hrl_sites: Vec<u32> = Vec::new();
        let mut hrl_stub_va = 0u32;
        let mut uhd_conversion_count = 0;

        // SAFETY COUPLING: the boot-init hook writes 0xFF into every flag byte at
        // power-on, which makes the tri-state `0x00 == OFF` invariant the feature
        // stubs rely on hold on a freshly powered drive. Emit it first; if it
        // fails, ship a BARE base (handler + record repoint + CMAC) -- a feature
        // stub without the 0xFF-fill would boot with every feature OFF. Feature
        // emits inside the success arm are otherwise best-effort.
        if let Ok((site, va)) = self
            .resolve_boot_init_pair(image)
            .and_then(|pair| self.emit_boot_init(image, &mut out, flag_base, pair, defaults))
        {
            boot_init_site = site;
            boot_stub_va = va;

            if let Ok(facts) = self.emit_speed_classic(image, &mut out, flag_base) {
                speed_tail_site = facts
                    .iter()
                    .find(|(k, _)| *k == "speed_tail_site")
                    .unwrap()
                    .1;
                speed_stub_va = facts.iter().find(|(k, _)| *k == "speed_stub_va").unwrap().1;
            }

            // Region-free: same emit as `build_modify_classic`.
            if let Ok((emitter, va)) = self.emit_region_classic(&mut out, flag_base) {
                region_emitter = emitter;
                region_stub_va = va;
            }

            // Raw read: Gate-A (`04 01`) + AKE accept (`04 02`), no deny detour
            // (deny stays OEM). Same emit as `build_modify_classic`.
            if let Ok(facts) = self.emit_rawread_classic(image, &mut out, flag_base) {
                let fact = |k: &str| {
                    facts
                        .iter()
                        .find(|(n, _)| *n == k)
                        .map(|(_, v)| *v)
                        .unwrap_or(0)
                };
                gatea_gate = fact("gatea_gate");
                gatea_stub_va = fact("gatea_stub_va");
                ake_gate = fact("ake_gate");
                ake_stub_va = fact("ake_stub_va");
                deny_reset_gate = fact("deny");
                vid_producer = fact("vid_producer");
            }

            // UHD / BD: modern AACS detours, best-effort. Classic has no
            // disc-mode/class REPORT-KEY accept gate (BD acceptance is purely
            // AKE-gated) and its refusal is generic auth-gated inline sense with no
            // unique anchor, so both finders self-guard (unique match + landmark
            // re-verify), resolve 0x on all 17 images and wire nothing. Classic UHD
            // recognition/read behavior remains unproven.
            if let Ok((site, bytes)) = self.uhd_gate_detour(image, flag_base) {
                if let Some(stub_va) = self.commit_classic_detour(&mut out, site, &bytes) {
                    uhd_classifier_site = site as u32;
                    uhd_stub_va = stub_va;
                }
            }
            if let Ok((site, bytes)) = self.bd_detour(image, flag_base) {
                if let Some(stub_va) = self.commit_classic_detour(&mut out, site, &bytes) {
                    bd_gate_site = site as u32;
                    bd_stub_va = stub_va;
                }
            }
            // HRL: modern hrl_skip_detour misses (lookup body diverges at the 10th
            // halfword); emit_hrl_classic finds it via HRL_LOOKUP_SIG_CLASSIC and
            // bails (unwired) on any cert-site or 6F-deny-head mismatch.
            if let Ok((sites, stub_va)) = self.emit_hrl_classic(image, &mut out, flag_base) {
                hrl_sites = sites;
                hrl_stub_va = stub_va;
            }
            uhd_conversion_count = self
                .emit_media_conversion_classic(image, &mut out, flag_base)
                .1;
        }

        // DE is an identity-page byte, not a tri-state flag, so it does not depend
        // on the boot 0xFF-fill and is written even on the bare-base path.
        // Best-effort: no identity page, no DE.
        let de_off = self.find_de_byte(image).ok();
        if let Some(off) = de_off {
            out[off as usize] = 0xDE;
        }

        // Repoint the classic 0x3C record's handler; flags stay live.
        let table = CommandTable {
            base: 0,
            stride: STRIDE,
            opcode_off: 0,
            flags_off: 1,
            handler_off: 4,
            term_flag: TERM_FLAG,
            max_records: 1,
        };
        table.replace(&mut out, &record, handler_va | 1, None);
        debug_assert_eq!(out[record.off + 1], LIVE_FLAGS, "flags must remain live");

        let signed = cmac::resign(&out).map_err(|e| anyhow!("re-sign failed: {e}"))?;

        Ok(CreateReport {
            uhd_conversion_count,
            image: signed,
            scanner_entry,
            cdb_base,
            sense_setter,
            record,
            handler_va,
            handler_bytes,
            boot_init_site,
            boot_stub_va,
            boot_function_entry,
            vid_producer,
            vid_out_buf: 0,
            vid_gate_setter: 0,
            setdiscmode: 0,
            speed_gate: 0,
            speed_tail_site,
            speed_stub_va,
            region_emitter,
            region_stub_va,
            ake_gate,
            ake_stub_va,
            gatea_gate,
            gatea_stub_va,
            deny_reset_gate,
            // Classic ships no deny-reset detour (deny stays OEM) — stub 0.
            deny_stub_va: 0,
            uhd_classifier_site,
            uhd_stub_va,
            bd_gate_site,
            bd_stub_va,
            auth_cell_site: 0,
            auth_cell_stub_va: 0,
            auth_cell_refusal: false,
            hrl_sites,
            hrl_stub_va,
            de_off: de_off.unwrap_or(0),
            flag_base,
            free_sram_cell: flag_base,
        })
    }

    /// Place `bytes` in CMAC-covered free space and write a `bl` to it at `site`
    /// (replacing the OEM instruction there). Returns the stub VA, or `None` if
    /// free space or `bl` range fails (feature left unwired, base still ships).
    fn commit_classic_detour(&self, out: &mut [u8], site: usize, bytes: &[u8]) -> Option<u32> {
        self.commit_classic_detour_checked(out, site, bytes, thumb::decode_bl)
    }

    /// Writes into a copy and publishes it only after the decode-back check
    /// passes, so a refused detour leaves `out` byte-identical.
    fn commit_classic_detour_checked(
        &self,
        out: &mut [u8],
        site: usize,
        bytes: &[u8],
        decode: impl Fn(&[u8], usize) -> Option<u32>,
    ) -> Option<u32> {
        let stub_va = self.free_space(out, bytes.len() + 16).ok()?;
        let bl = thumb::encode_bl(site, stub_va)?;
        let mut staged = out.to_vec();
        thumb::write(&mut staged, stub_va as usize, bytes);
        thumb::write(&mut staged, site, &bl);
        // Emit-time decode-back guard: a failure is a graceful miss.
        if decode(&staged, site) != Some(stub_va) {
            return None;
        }
        out.copy_from_slice(&staged);
        Some(stub_va)
    }

    /// MT1939 classic-generation MODIFY: Identity (+DumpAll), Speed, Region-free,
    /// RawRead (Gate-A + AKE + HRL), media conversion and DE.
    ///
    /// Classic keeps MT1959's `opcode@0/flags@1/handler@4` dispatch record format
    /// and chip-agnostic response writer/commit routines, but uses a different
    /// SRAM map and table window. RawRead leaves the classic deny path
    /// byte-identical to OEM: its clear-output shape is inferred, and a wrong
    /// reply would desync the SCSI FIFO.
    ///
    /// Storage passes the static SRAM overlap checks and code is placed within
    /// authenticated erased space; the image re-signs and passes the structural
    /// detour audit. Runtime behavior on a real classic drive is unproven, hence
    /// the uniform `static-only` validation label.
    pub fn build_modify_classic(
        &self,
        image: &[u8],
        chip: &ChipInfo,
        cap: &Capability,
    ) -> Result<ModifyReport> {
        self.build_modify_classic_with_defaults(image, chip, cap, &BootSettings::standard())
    }

    pub(crate) fn build_modify_classic_with_defaults(
        &self,
        image: &[u8],
        chip: &ChipInfo,
        cap: &Capability,
        defaults: &BootSettings,
    ) -> Result<ModifyReport> {
        // Idempotency: a re-fed freemkv-modified classic image reports every lever
        // AlreadyPresent and returns byte-identical (see `build_modify`).
        if is_freemkv_patched(image) {
            return Ok(self.already_present_report(image, chip, cap, "MT1939"));
        }

        // Base prerequisites: scanner, CDB base (r5) and the response writer/commit
        // build_handler needs. If any is missing the caller degrades to DE-only.
        let analysis = mediatek_optical::image::analysis::ImageAnalysis::inspect(image);
        let commands = analysis
            .commands()
            .context("classic base: native command ownership")?;
        analysis.response().context("classic base: response I/O")?;

        // Classic dispatch table window (~0x1a4000, engine-scope §1).
        let record = Self::live_record_from(commands, abi::READ_BUFFER_OPCODE)
            .context("classic base: live 0x3C dispatch record")?;

        // Derive an unreferenced cell from this image; MT1959's FLAG_TABLE_BASE
        // does not fit the classic SRAM map.
        let ram = super::sram::SramPlacement::inspect(image);
        let flag_base = ram
            .candidate()
            .context("classic base: free SRAM cell for the flag table")?;
        ram.assert_free(
            flag_base,
            super::core::FLASHWRITE_SCRATCH_OFF + 1,
            "classic flag table and flash scratch",
        )?;

        // No classic reboot function entry is qualified. Its caller site has no
        // fixed offset to a function prologue, so leave the reboot verb inert.
        let boot_function_entry: u32 = 0;
        let handler_bytes = self
            .build_handler_from_analysis(
                &analysis,
                record.handler,
                flag_base,
                boot_function_entry,
                identity_blob(),
                defaults,
            )
            .context("classic base: assembling the 3C-0E handler")?;

        let mut out = image.to_vec();
        let handler_va = self.free_space(&out, handler_bytes.len() + 16)?;
        thumb::write(&mut out, handler_va as usize, &handler_bytes);

        // Report the installed boot hook so consumers expose only its actual controls.
        let boot_init_pair = self.resolve_boot_init_pair(image)?;
        let (boot_init_site, boot_stub_va) =
            self.emit_boot_init(image, &mut out, flag_base, boot_init_pair, defaults)?;

        let mut levers: Vec<LeverReport> = Vec::new();

        // Identity / vendor handler + DumpAll. `boot_function_entry` is 0 on classic
        // (Reboot arm is inert, see build_handler); recorded so the audit can skip
        // the Reboot-literal check.
        levers.push(LeverReport::applied(
            LeverId::Identity,
            vec![
                ("handler_va", handler_va),
                ("handler_len", handler_bytes.len() as u32),
                ("boot_init_site", boot_init_site),
                ("boot_stub_va", boot_stub_va),
                ("record_off", record.off as u32),
                ("flag_base", flag_base),
                ("boot_function_entry", boot_function_entry),
            ],
        ));

        levers.push(match self.emit_speed_classic(image, &mut out, flag_base) {
            Ok(facts) => LeverReport::applied(LeverId::Speed, facts),
            Err(e) => LeverReport::missed(LeverId::Speed, format!("{e:#}")),
        });

        levers.push({
            match self.emit_region_classic(&mut out, flag_base) {
                Ok((emitter, va)) => LeverReport::applied(
                    LeverId::RegionFree,
                    vec![("region_emitter", emitter), ("region_stub_va", va)],
                ),
                Err(e) => LeverReport::missed(LeverId::RegionFree, format!("{e:#}")),
            }
        });

        // Raw read: `04 01` (Gate-A bare-read) + `04 02` (AKE accept) reuse the
        // shared flag-gated stubs (Gate-A is byte-for-byte the MT1959 one); deny
        // stays OEM.
        //
        // HRL-skip is independently anchored and attempted even when a RawRead
        // helper misses (a relocated classic AACS block can lack the shared JB8
        // session-reset signature), matching CREATE. Both report through the
        // composite RawRead lever; HRL-only facts keep the detour visible to the
        // structural auditor.
        levers.push({
            let rawread = self.emit_rawread_classic(image, &mut out, flag_base);
            let hrl = self.emit_hrl_classic(image, &mut out, flag_base);
            let append_hrl_facts =
                |facts: &mut Vec<(&'static str, u32)>, result: &Result<(Vec<u32>, u32)>| {
                    if let Ok((sites, stub_va)) = result {
                        if *stub_va != 0 {
                            facts.push(("hrl_stub_va", *stub_va));
                            for (k, &site) in sites.iter().take(3).enumerate() {
                                facts.push((["hrl_site", "hrl_site2", "hrl_site3"][k], site));
                            }
                        }
                    }
                };
            match (rawread, hrl) {
                (Ok(mut facts), result) => {
                    append_hrl_facts(&mut facts, &result);
                    LeverReport::applied(LeverId::RawRead, facts)
                }
                (Err(_), Ok((sites, stub_va))) if stub_va != 0 => {
                    let mut facts = Vec::new();
                    append_hrl_facts(&mut facts, &Ok((sites, stub_va)));
                    LeverReport::applied(LeverId::RawRead, facts)
                }
                (Err(rawread_error), Err(hrl_error)) => LeverReport::missed(
                    LeverId::RawRead,
                    format!("{rawread_error:#}; classic HRL-skip also missed: {hrl_error:#}"),
                ),
                (Err(rawread_error), Ok(_)) => {
                    LeverReport::missed(LeverId::RawRead, format!("{rawread_error:#}"))
                }
            }
        });

        let (conversion, count) = self.emit_media_conversion_classic(image, &mut out, flag_base);
        attach_classic_conversion(&mut levers, conversion, count);

        levers.push(self.lever_de(image, &mut out, chip));

        // Repoint the classic 0x3C record's handler; flags stay live.
        let table = CommandTable {
            base: 0,
            stride: STRIDE,
            opcode_off: 0,
            flags_off: 1,
            handler_off: 4,
            term_flag: TERM_FLAG,
            max_records: 1,
        };
        table.replace(&mut out, &record, handler_va | 1, None);
        debug_assert_eq!(out[record.off + 1], LIVE_FLAGS, "flags must remain live");

        if !levers.iter().any(|l| l.outcome.is_effective()) {
            bail!("nothing modifiable on this classic MT1939 image");
        }

        let signed = cmac::resign(&out).map_err(|e| anyhow!("re-sign failed: {e}"))?;

        Ok(ModifyReport {
            engine: "MT1939",
            family: chip.family.label().to_string(),
            vendor: chip.vendor.clone(),
            model: chip.model.clone(),
            rev: chip.rev.clone(),
            vendor_specific: chip.vendor_specific.clone(),
            media: cap.media_class.label().to_string(),
            levers,
            image: signed,
            validation: Validation::StaticOnly,
        })
    }

    /// Region-free emission using the unique native RPC emitter grammar.
    /// Classic application layouts relocate it across the image.
    pub(crate) fn emit_region_classic(&self, out: &mut [u8], flag_base: u32) -> Result<(u32, u32)> {
        let region_emitter = self.find_region_emitter(out)?;
        let region_site = region_emitter as usize + 6;
        let region_bytes = self.build_region_stub(flag_base)?;
        let region_stub_va = self.free_space(out, region_bytes.len() + 16)?;
        let bl = thumb::encode_bl(region_site, region_stub_va)
            .ok_or_else(|| anyhow!("classic Region detour `bl` out of range"))?;
        thumb::write(out, region_stub_va as usize, &region_bytes);
        thumb::write(out, region_site, &bl);
        crate::install_guard::verify_branch(
            out,
            region_site,
            thumb::BranchKind::Bl,
            region_stub_va,
            "classic Region",
        )?;
        Ok((region_emitter, region_stub_va))
    }

    /// Raw-read emission for the MT1939 **classic** generation (mirrors
    /// [`Self::emit_rawread`]: validate read-only, then commit on a working copy).
    /// Emits the Gate-A `04 01` bare-read and AKE `04 02` accept detours but NO
    /// deny-reset detour: the classic deny path stays **byte-identical to OEM**
    /// (its clear-output shape is inferred; touching it risks a SCSI-FIFO desync).
    ///
    /// * Gate-A: the VID producer gate `cmp r0,#6; bne <deny>` sits at
    ///   `VID_GATE_SIG_CLASSIC`'s `match+30`/`+32` and the `bl` overwrites both;
    ///   reuses the shared [`Self::build_gatea_stub`] with `agid_struct` from the
    ///   CDB base ([`Self::find_vid_agid_struct_classic`]).
    /// * AKE: the reject writer `lsrs; movs r1,#1` at `AKE_GATE_SIG_CLASSIC`'s
    ///   `match+6`, returning into the shared `bl set_agid_state` at `match+0xa`.
    pub(crate) fn emit_rawread_classic(
        &self,
        image: &[u8],
        out: &mut Vec<u8>,
        flag_base: u32,
    ) -> Result<Vec<(&'static str, u32)>> {
        use super::mt1939::{masked_matches, AKE_GATE_SIG_CLASSIC, VID_GATE_SIG_CLASSIC};
        // Whole-image scan: see `classic_rawread_anchors`; the unique-match
        // checks below keep it safe.
        let lo = 0usize;
        let hi = image.len();

        // ---- validate (read-only) ----
        let mut vid_gates = masked_matches(image, VID_GATE_SIG_CLASSIC, lo, hi);
        vid_gates.extend(masked_matches(image, VID_GATE_SIG_CLASSIC_R7, lo, hi));
        vid_gates.sort_unstable();
        vid_gates.dedup();
        let vid_gate = match vid_gates.as_slice() {
            [one] => *one,
            hits => bail!(
                "classic VID gate matched {} time(s) in [0x{lo:x},0x{hi:x}) (want 1)",
                hits.len()
            ),
        };
        let gatea_cmp = vid_gate + 30;
        let cmp_hw = u16::from_le_bytes([image[gatea_cmp], image[gatea_cmp + 1]]);
        if cmp_hw != 0x2806 {
            bail!("classic VID gate `cmp r0,#6` not at 0x{gatea_cmp:x} (got 0x{cmp_hw:04x})");
        }
        let gatea_bne = gatea_cmp + 2;
        let bne_hw = u16::from_le_bytes([image[gatea_bne], image[gatea_bne + 1]]);
        if (bne_hw & 0xFF00) != 0xD100 {
            bail!("classic VID gate `bne` not at 0x{gatea_bne:x} (got 0x{bne_hw:04x})");
        }
        let mut d = (bne_hw & 0xFF) as i32;
        if d >= 0x80 {
            d -= 0x100;
        }
        let gatea_deny = (gatea_bne as i32 + 4 + d * 2) as u32;
        let gatea_authed = (gatea_cmp + 4) as u32;
        // AGID struct is the CDB base, not the modern r7 heuristic.
        let agid_struct = self.find_vid_agid_struct_classic(image)?;
        // De-bus latch clear, as on the modern path (see `build_gatea_stub`); an
        // image that cannot resolve it refuses rather than ship a Gate-A that
        // forces auth without clearing the latch.
        let classic_aacs_reset = self.find_aacs_session_reset(image)?;
        let gatea_bytes = self.build_gatea_stub(
            flag_base,
            agid_struct,
            gatea_authed,
            gatea_deny,
            classic_aacs_reset,
        )?;

        // Scratch clear-VID buffer: audit-only (no stub consumes it; the producer
        // stages the VID itself). It goes through the MODERN find_vid_gate, whose
        // window can miss a relocated AACS block (e.g. BE14NU40 1.01 ~0x180k), so
        // it is best-effort and never fails the emit.
        let vid_output = self.find_vid_producer(image).ok();

        // AKE accept gate (04 02), required unique. The reject writer folds the
        // `lsrs` (AGID compute) into the 4 replaced bytes.
        let mut ake_gates: Vec<_> = masked_matches(image, AKE_GATE_SIG_CLASSIC, lo, hi)
            .into_iter()
            .map(|gate| (gate, gate + 6))
            .collect();
        for gate in masked_matches(image, AKE_GATE_SIG_CLASSIC_SPLIT, lo, hi) {
            for (branch, target) in [(16, 44), (42, 46), (48, 98), (66, 94), (92, 96)] {
                let decoded = thumb::isa::decode_at(image, gate + branch)
                    .and_then(|instruction| instruction.branch_target());
                if decoded != Some((gate + target) as u32) {
                    bail!("classic split AKE response branches cross native arms");
                }
            }
            let success =
                thumb::decode_bl(image, gate + 6).context("classic split AKE success setter")?;
            let reject =
                thumb::decode_bl(image, gate + 56).context("classic split AKE reject setter")?;
            if success != reject {
                bail!("classic split AKE writers name different state setters");
            }
            ake_gates.push((gate, gate + 52));
        }
        let (ake, ake_site) = match ake_gates.as_slice() {
            [one] => *one,
            hits => bail!(
                "classic AKE gate matched {} time(s) in [0x{lo:x},0x{hi:x}) (want 1)",
                hits.len()
            ),
        };
        let lsrs_hw = u16::from_le_bytes([image[ake_site], image[ake_site + 1]]);
        let movs_hw = u16::from_le_bytes([image[ake_site + 2], image[ake_site + 3]]);
        if lsrs_hw != 0x0980 || movs_hw != 0x2101 {
            bail!(
                "classic AKE reject writer (lsrs r0,#6; movs r1,#1) not at 0x{ake_site:x} \
                 (got 0x{lsrs_hw:04x} 0x{movs_hw:04x})"
            );
        }
        let ake_back = (ake_site + 4) as u32; // native `bl set_agid_state` call site
        self.find_transition_state_setter(image)?;
        let ake_bytes = self.build_ake_stub_classic(flag_base, ake_back)?;

        // ---- commit on a working copy (atomic) ----
        let mut w = out.clone();
        let gatea_stub_va = self.free_space(&w, gatea_bytes.len() + 16)?;
        let gatea_bl = thumb::encode_bl(gatea_cmp, gatea_stub_va)
            .ok_or_else(|| anyhow!("classic Gate-A detour `bl` out of range"))?;
        thumb::write(&mut w, gatea_stub_va as usize, &gatea_bytes);
        thumb::write(&mut w, gatea_cmp, &gatea_bl);
        crate::install_guard::verify_branch(
            &w,
            gatea_cmp,
            thumb::BranchKind::Bl,
            gatea_stub_va,
            "classic Gate-A",
        )?;

        let ake_stub_va = self.free_space(&w, ake_bytes.len() + 16)?;
        let ake_bl = thumb::encode_bl(ake_site, ake_stub_va)
            .ok_or_else(|| anyhow!("classic AKE detour `bl` out of range"))?;
        thumb::write(&mut w, ake_stub_va as usize, &ake_bytes);
        thumb::write(&mut w, ake_site, &ake_bl);
        crate::install_guard::verify_branch(
            &w,
            ake_site,
            thumb::BranchKind::Bl,
            ake_stub_va,
            "classic AKE",
        )?;

        *out = w;
        let mut facts = vec![
            ("gatea_gate", gatea_cmp as u32),
            ("gatea_stub_va", gatea_stub_va),
            ("gatea_authed", gatea_authed),
            ("ake_site", ake_site as u32),
            ("ake_stub_va", ake_stub_va),
            ("ake_gate", ake as u32),
            ("deny", gatea_deny),
        ];
        if let Some((vid_producer, scratch)) = vid_output {
            facts.extend([("scratch", scratch), ("vid_producer", vid_producer)]);
        } else {
            // These helpers use the native producer and never access a clear
            // VID buffer directly. An unbound optional diagnostic is not RAM 0.
            facts.push(("scratch_not_used_by_helpers", 1));
        }
        Ok(facts)
    }

    /// Host-Revocation-List skip for the MT1939 **classic** cert path: the analogue
    /// of [`Self::hrl_skip_detour`], reusing [`Self::build_hrl_skip_stub`] (each
    /// detour `bl` replaces a `cmp r0,#0; bne <revoke>`, so on entry `lr` is the
    /// CLEAN fall-through and `r0` is the HRL result). Only the site finder
    /// differs: modern anchors on [`super::core::HRL_LOOKUP_SIG`] and an
    /// `ldrb r0,[r4,#2]` (`0x78A0`) revoke head; classic uses
    /// [`super::mt1939::HRL_LOOKUP_SIG_CLASSIC`] and `ldrb r0,[r5,#2]` (`0x78A8`),
    /// and one layout reaches the check via an unconditional `b` after the
    /// `bl <hrl>`, which this finder follows.
    ///
    /// A resolve requires ALL of:
    ///   1. the classic HRL lookup routine present and UNIQUE image-wide;
    ///   2. every `bl <hrl>` followed (within a short budget, across at most one
    ///      unconditional `b`) by `cmp r0,#0; bne <T>`, ALL sites agreeing on one `T`;
    ///   3. `T` carrying the version-invariant classic OEM revoke head
    ///      `ldrb r0,[r5,#2]; cmp r0,#0; bne …` immediately followed (head+6) by the
    ///      6F copy-protection sense `movs r0,#0x6f`.
    ///
    /// Any disagreement or missing landmark bails (HRL unwired) rather than
    /// corrupt the cert path. Commits on a working copy: every `bl` is
    /// range-checked before ANY is written. Returns `(cmp_site_offsets, stub_va)`.
    pub(crate) fn emit_hrl_classic(
        &self,
        image: &[u8],
        out: &mut Vec<u8>,
        flag_base: u32,
    ) -> Result<(Vec<u32>, u32)> {
        use super::mt1939::{masked_matches, HRL_LOOKUP_SIG_CLASSIC};

        // ---- locate the HRL lookup routine, required unique across native
        // translation orders. UH12 combines classic boot with modern HRL. ----
        let mut hrl_routines = masked_matches(image, HRL_LOOKUP_SIG_CLASSIC, 0, image.len());
        hrl_routines.extend(masked_matches(image, HRL_LOOKUP_SIG, 0, image.len()));
        let hrl = match hrl_routines.as_slice() {
            [one] => *one as u32,
            hits => bail!(
                "classic HRL lookup matched {} time(s) image-wide (want 1)",
                hits.len()
            ),
        };

        let hw = |o: usize| u16::from_le_bytes([image[o], image[o + 1]]);
        let bne_target = |o: usize| -> u32 {
            let d = (hw(o) & 0xFF) as i32;
            let d = if d >= 0x80 { d - 0x100 } else { d };
            (o as i32 + 4 + d * 2) as u32
        };

        // ---- check sites: `bl <hrl>` then `cmp r0,#0; bne <revoke>`, following at
        //      most one unconditional `b`. ALL sites must agree on one target. ----
        let mut sites: Vec<usize> = Vec::new();
        let mut revoke: Option<u32> = None;
        let mut o = 0usize;
        while o + 4 <= image.len() {
            if thumb::decode_bl(image, o) == Some(hrl) {
                let mut p = o + 4;
                let mut hopped = false;
                let mut steps = 0;
                while steps < 40 && p + 4 <= image.len() {
                    if hw(p) == 0x2800 && (hw(p + 2) & 0xFF00) == 0xD100 {
                        let t = bne_target(p + 2);
                        match revoke {
                            None => revoke = Some(t),
                            Some(prev) if prev == t => {}
                            Some(_) => {
                                bail!("classic HRL check sites disagree on the revoke target")
                            }
                        }
                        sites.push(p);
                        break;
                    }
                    let h = hw(p);
                    if !hopped && (h & 0xF800) == 0xE000 {
                        let d = (h & 0x7FF) as i32;
                        let d = if d >= 0x400 { d - 0x800 } else { d };
                        let Some(next) = usize::try_from(p as i64 + 4 + i64::from(d) * 2)
                            .ok()
                            .filter(|&n| n + 4 <= image.len())
                        else {
                            break;
                        };
                        p = next;
                        hopped = true;
                        steps += 1;
                        continue;
                    }
                    p += 2;
                    steps += 1;
                }
            }
            o += 2;
        }
        let revoke = revoke
            .ok_or_else(|| anyhow!("no classic HRL cert-path `cmp r0,#0; bne` site found"))?;
        if sites.is_empty() {
            bail!("classic HRL lookup located but no cert-check site resolved");
        }

        // ---- verify the revoke target's OEM head:
        //      `ldrb r0,[r5,#2]; cmp r0,#0; bne …; movs r0,#0x6f` (the 6F deny). ----
        let t = revoke as usize;
        let head_ok = t + 8 <= image.len()
            // The lookup's scheduling and its caller's register allocation are
            // independent: UH12 has modern lookup order with a classic r5 head.
            && matches!(hw(t), 0x78a8 | 0x78a0)
            && hw(t + 2) == 0x2800 // cmp  r0,#0
            && (hw(t + 4) & 0xFF00) == 0xD100 // bne  <loop>
            && hw(t + 6) == 0x206F; // movs r0,#0x6f   (6F copy-protection sense)
        if !head_ok {
            bail!("classic HRL revoke target 0x{revoke:x} lacks the OEM 6F-deny head — refusing");
        }

        let bytes = self.build_hrl_skip_stub(flag_base, revoke)?;

        // ---- commit on a working copy: range-check EVERY `bl` before any is
        //      written; a partial write would corrupt the cert path.
        let mut w = out.clone();
        let stub_va = self.free_space(&w, bytes.len() + 16)?;
        for &s in &sites {
            if thumb::encode_bl(s, stub_va).is_none() {
                bail!("classic HRL detour `bl` out of range at 0x{s:x}");
            }
        }
        thumb::write(&mut w, stub_va as usize, &bytes);
        for &s in &sites {
            let bl = thumb::encode_bl(s, stub_va).expect("range re-checked above");
            thumb::write(&mut w, s, &bl);
            crate::install_guard::verify_branch(
                &w,
                s,
                thumb::BranchKind::Bl,
                stub_va,
                "classic HRL-skip",
            )?;
        }
        *out = w;

        Ok((sites.iter().map(|&s| s as u32).collect(), stub_va))
    }
}

#[cfg(test)]
#[path = "mt1939_classic_tests.rs"]
mod tests;
