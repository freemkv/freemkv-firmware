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
use super::lever::{LeverId, LeverReport, ModifyReport, Validation};
use super::mt1959::Mt1959Engine;
use super::CreateReport;
use crate::abi;
use crate::family::{Capability, ChipInfo};
use crate::thumb::{self, Asm, CommandTable};

impl Mt1959Engine {
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
    /// `flag[Ake]==STATE_ON` (accept any host cert) else the OEM `1` (reject), and
    /// falls through to the shared OEM `bl set_agid_state` call at `back`
    /// (`match+0xa`) that BOTH arms converge on — a single clean call, so the
    /// store happens through the OEM primitive unchanged. `r2` scratch; `r0`=AGID
    /// preserved. `04 01` does NOT act here (that is the Gate-A bare-read path).
    pub(crate) fn build_ake_stub_classic(&self, flag_base: u32, back: u32) -> Result<Vec<u8>> {
        let mut a = Asm::new();
        let accept = a.label();
        let done = a.label();
        a.lsrs_imm(0, 0, 6); // replay the overwritten `lsrs r0,r0,#6` (r0 = AGID)
        a.ldr_lit(2, flag_base + abi::Feature::Ake as u32); // r2 = &flag[Ake]
        a.ldrb_imm(2, 2, 0); // r2 = AKE flag byte
        a.cmp_imm(2, abi::STATE_ON); // 0x01 = null AKE (accept any/revoked host cert)
        a.beq(accept);
        a.movs_imm(1, 1); // OEM (00/0xFF): reset to state 1 on a failed cert verify
        a.b(done);
        a.bind(accept);
        a.movs_imm(1, 6); // forced: state 6 (AKE authenticated)
        a.bind(done);
        a.ldr_lit(2, back | 1); // -> shared OEM `bl set_agid_state` call site
        a.bx(2);
        a.finish()
    }

    /// MT1939-**classic** create (bare base): the modern [`Self::build_report`]
    /// monolith is modern-shaped (modern table window, the `FLAG_TABLE_BASE`
    /// constant, modern `emit_*` windows) and dies on classic at the flag-table
    /// SRAM assert. This is its classic analogue — the same base every finder in
    /// `mt1939-classic-identity-base.md` proves 17/17, mirroring the base tier of
    /// [`Self::build_modify_classic`] but producing a [`CreateReport`].
    ///
    /// Ships the injected `0x3C-0E` handler (Identity / SET / GET / SAVE / RESET /
    /// DumpAll) + record repoint + CMAC re-sign. **No boot-init hook and no feature
    /// stubs**: the classic boot site is a hardware-unconfirmed leaf helper
    /// ([`Self::emit_boot_init`] fail-closes on it), and installing a power-on stub
    /// there could brick a classic drive. A *bare* base never needs it — nothing
    /// reads the flag table at boot; only explicit host verbs do — so the omission
    /// is safe (the cosmetic effect is that GET/Identity read uninitialised flag
    /// cells until the first RESET, not a brick). Feature stubs (which DO need the
    /// boot 0xFF-fill for tri-state safety) wait on the on-silicon boot blessing.
    pub fn build_report_classic(&self, image: &[u8]) -> Result<CreateReport> {
        // Idempotency: a re-fed freemkv image reports the existing base unchanged.
        if is_freemkv_patched(image) {
            bail!("image already carries a freemkv base (classic); nothing to create");
        }

        // ---- BASE (mandatory) — classic finders, all PROVEN 17/17.
        let scanner_entry = self
            .find_scanner_entry(image)
            .context("classic base: dispatch scanner not found")?;
        let cdb_base = self
            .find_cdb_base(image)
            .context("classic base: CDB base")?;
        self.find_response_writer(image)
            .context("classic base: response writer")?;
        self.find_response_commit(image)
            .context("classic base: response commit")?;
        // sense_setter is a REPORT anchor only (build_handler never uses it); the
        // classic scanner raises sense inline, so the modern shape legitimately
        // misses. Best-effort (0 when absent) — never blocks the base.
        let sense_setter = self.sense_setter(image).unwrap_or(0);

        // Classic 0x3C dispatch table lives in its own window (~0x1a4000), NOT the
        // modern find_live_record windows.
        const CLASSIC_TABLE_LO: usize = 0x001a_0000;
        const CLASSIC_TABLE_HI: usize = 0x001a_8000;
        let record = self
            .find_live_record_in(
                image,
                abi::READ_BUFFER_OPCODE,
                CLASSIC_TABLE_LO,
                CLASSIC_TABLE_HI,
            )
            .context("classic base: live 0x3C dispatch record")?;

        // Classic SRAM map differs from MT1959 — derive an unreferenced cell from
        // THIS image (the modern FLAG_TABLE_BASE collides with classic live SRAM).
        let flag_base = self
            .find_free_sram_cell(image)
            .context("classic base: free SRAM cell for the flag table")?;

        let handler_bytes = self
            .build_handler(image, record.handler, flag_base)
            .context("classic base: assembling the 3C-0E handler")?;

        let mut out = image.to_vec();
        let handler_va = self.free_space(&out, handler_bytes.len() + 16)?;
        thumb::write(&mut out, handler_va as usize, &handler_bytes);

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
            image: signed,
            scanner_entry,
            cdb_base,
            sense_setter,
            record,
            handler_va,
            handler_bytes,
            // Boot hook intentionally omitted on classic (hardware-gated) — see doc.
            boot_init_site: 0,
            boot_stub_va: 0,
            // No feature stubs in the bare classic base.
            vid_producer: 0,
            vid_out_buf: 0,
            vid_gate_setter: 0,
            setdiscmode: 0,
            speed_gate: 0,
            speed_stub_va: 0,
            region_emitter: 0,
            region_stub_va: 0,
            ake_gate: 0,
            ake_stub_va: 0,
            gatea_gate: 0,
            gatea_stub_va: 0,
            deny_reset_gate: 0,
            deny_stub_va: 0,
            busenc_detour_site: 0,
            busenc_stub_va: 0,
            uhd_classifier_site: 0,
            uhd_stub_va: 0,
            bd_gate_site: 0,
            bd_stub_va: 0,
            hrl_sites: Vec::new(),
            hrl_stub_va: 0,
            de_off: 0,
            flag_base,
            free_sram_cell: flag_base,
        })
    }

    /// MT1939 classic-generation MODIFY (Identity + Region-free + DE).
    ///
    /// The classic generation keeps MT1959's `opcode@0/flags@1/handler@4` dispatch
    /// record format and the same chip-agnostic response writer/commit routines
    /// (all resolve on classic images), but in a different SRAM map + table window.
    /// This wires the two levers whose emit is **structurally provable + self-
    /// verifying** on classic — the Identity vendor handler (which also enables
    /// DumpAll) and Region-free — plus the always-safe DE byte. RawRead and Speed
    /// stay reported-only: the classic clear-VID scratch/deny path is INFERRED and
    /// the classic ramp ceiling is unreversed, so they are NOT emitted.
    ///
    /// Every byte written is well-formed, lands in a provably-free SRAM cell /
    /// CMAC-covered free space, the image re-signs + self-verifies, and it passes
    /// the structural detour audit — so, being structurally valid, Identity +
    /// Region-free + DE are produced unconditionally (no flag). What is not yet
    /// proven is runtime behavior on a real classic drive; the whole report carries
    /// the uniform `static-only` validation label for that. Classic Raw-read is the
    /// one thing withheld here — not as "beta" but because it is structurally unsafe
    /// (its clear-output/deny path is INFERRED; a wrong reply desyncs the SCSI FIFO).
    pub fn build_modify_classic(
        &self,
        image: &[u8],
        chip: &ChipInfo,
        cap: &Capability,
    ) -> Result<ModifyReport> {
        // Idempotency: a re-fed freemkv-modified classic image reports every lever
        // AlreadyPresent and returns byte-identical (see `build_modify`).
        if is_freemkv_patched(image) {
            return Ok(self.already_present_report(image, chip, cap, "MT1959"));
        }

        // Base prerequisites (classic): scanner + CDB base (r5) + the chip-agnostic
        // response writer/commit that build_handler needs. If any is missing the
        // vendor handler can't be built → this classic build can't run (the caller
        // degrades to the DE-only path).
        self.find_scanner_entry(image)
            .context("classic base: dispatch scanner not found")?;
        self.find_cdb_base(image)
            .context("classic base: CDB base")?;
        self.find_response_writer(image)
            .context("classic base: response writer")?;
        self.find_response_commit(image)
            .context("classic base: response commit")?;

        // Classic dispatch table window (~0x1a4000, engine-scope §1).
        const CLASSIC_TABLE_LO: usize = 0x001a_0000;
        const CLASSIC_TABLE_HI: usize = 0x001a_8000;
        let record = self
            .find_live_record_in(
                image,
                abi::READ_BUFFER_OPCODE,
                CLASSIC_TABLE_LO,
                CLASSIC_TABLE_HI,
            )
            .context("classic base: live 0x3C dispatch record")?;

        // Provably-free SRAM cell for the freemkv flag table (classic SRAM map
        // differs from MT1959, so we do not reuse the MT1959 FLAG_TABLE_BASE
        // placeholder — we derive an unreferenced cell from THIS image).
        let flag_base = self
            .find_free_sram_cell(image)
            .context("classic base: free SRAM cell for the flag table")?;

        let handler_bytes = self
            .build_handler(image, record.handler, flag_base)
            .context("classic base: assembling the 3C-0E handler")?;

        let mut out = image.to_vec();
        let handler_va = self.free_space(&out, handler_bytes.len() + 16)?;
        thumb::write(&mut out, handler_va as usize, &handler_bytes);

        // Fail-closed: the classic (MT1939) prologue now RESOLVES via
        // BOOT_INIT_SIG_CLASSIC, but find_boot_init tags it ClassicUnconfirmed and
        // emit_boot_init BAILS on that (hardware-unconfirmed leaf-helper call-order) —
        // tri-state OFF (`0x00`) is unsafe without a boot hook to write `0xFF` at
        // power-on, and the shared feature stubs (Region-lock etc.) would otherwise boot
        // every classic drive into their OFF state. The caller (mt1939::modify) degrades
        // to the DE-only path. Lifting this is a one-line flip in emit_boot_init once the
        // classic site is blessed on silicon (see TODO(hw-confirm) there).
        let (_boot_init_site, _boot_stub_va) = self.emit_boot_init(image, &mut out, flag_base)?;

        let mut levers: Vec<LeverReport> = Vec::new();

        // Identity / vendor handler + DumpAll — structurally valid, self-verifies,
        // passes the structural audit → produced unconditionally (static-only label).
        levers.push(LeverReport::applied(
            LeverId::Identity,
            vec![
                ("handler_va", handler_va),
                ("record_off", record.off as u32),
                ("flag_base", flag_base),
            ],
        ));

        // Speed — the MT1959 ramp-ceiling gate (a byte `speed_index` in an SRAM
        // cell, `cmp #0x32; bhi <ramp-exit>`, incremented by a rate-limit counter)
        // does NOT exist on classic MT1939: RE of all 11 classic speed-miss images
        // finds no incrementing byte-index ramp and no `#0x32` ceiling anywhere in
        // the image. Classic read speed is a disc-type halfword clamp routed through
        // a shared limiter primitive (`~0x1b854` on BH16NS40 1.00, disc-type gated
        // max values 0x64/0xc8/0x190/0x1f4), with no single detourable ramp gate
        // matching the MT1959 stub contract. A residual miss by real architecture
        // difference, not a missing signature — see the fleet survey notes.
        levers.push(LeverReport::missed(
            LeverId::Speed,
            "MT1939 classic uses a disc-type halfword read-speed clamp (shared limiter \
             primitive, no byte speed_index ramp / no 0x32 ceiling) — no MT1959-style \
             ramp-ceiling gate exists to detour (residual RE miss)",
        ));

        // Region-free — REGION_EMIT_SIG transfers to classic in a higher window.
        // Structurally valid + self-verifies → produced unconditionally.
        levers.push(if cap.region_lockable {
            match self.emit_region_classic(&mut out, flag_base) {
                Ok((emitter, va)) => LeverReport::applied(
                    LeverId::RegionFree,
                    vec![("region_emitter", emitter), ("region_stub_va", va)],
                ),
                Err(e) => LeverReport::missed(LeverId::RegionFree, format!("{e:#}")),
            }
        } else {
            LeverReport::not_applicable(LeverId::RegionFree, "no region lever on this model")
        });

        // Raw read — classic MT1939 `04 01` (Gate-A bare-read) + `04 02` (AKE
        // accept). Both detours reuse the shared flag-gated stubs (the classic
        // Gate-A stub is byte-for-byte the MT1959 one); the deny path is left
        // byte-identical to OEM (no deny-reset detour). Structurally audited; the
        // static-only label already carries the pending-hardware-KAT caveat.
        levers.push(if cap.bd_aacs {
            match self.emit_rawread_classic(image, &mut out, flag_base) {
                Ok(facts) => LeverReport::applied(LeverId::RawRead, facts),
                Err(e) => LeverReport::missed(LeverId::RawRead, format!("{e:#}")),
            }
        } else {
            LeverReport::not_applicable(LeverId::RawRead, "no AACS/BD on this model")
        });

        // Downgrade-enable — proven/stable, any identity page.
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

    /// Region-free emission for the MT1939 classic window (mirrors [`Self::emit_region`]
    /// with the classic `REGION_EMIT_SIG` window, `~0x154000..0x157000`).
    pub(crate) fn emit_region_classic(&self, out: &mut [u8], flag_base: u32) -> Result<(u32, u32)> {
        let region_emitter = self.find_region_emitter_in(out, 0x0015_0000, 0x0016_0000)?;
        let region_site = region_emitter as usize + 6;
        let region_bytes = self.build_region_stub(flag_base)?;
        let region_stub_va = self.free_space(out, region_bytes.len() + 16)?;
        let bl = thumb::encode_bl(region_site, region_stub_va)
            .ok_or_else(|| anyhow!("classic Region detour `bl` out of range"))?;
        thumb::write(out, region_stub_va as usize, &region_bytes);
        thumb::write(out, region_site, &bl);
        Ok((region_emitter, region_stub_va))
    }

    /// Raw-read emission for the MT1939 **classic** window (mirrors
    /// [`Self::emit_rawread`]: validate read-only, then commit on a working copy).
    /// Emits the Gate-A `04 01` bare-read detour (always) and the AKE `04 02`
    /// accept detour, but NO deny-reset detour — the classic deny path is left
    /// **byte-identical to OEM** (its clear-output shape is inferred, so touching
    /// it risks a SCSI-FIFO desync). Returns the grounded facts.
    ///
    /// * Gate-A: the classic VID producer gate `cmp r0,#6; bne <deny>` sits at
    ///   `VID_GATE_SIG_CLASSIC`'s `match+30`/`+32`; the detour reuses the shared
    ///   [`Self::build_gatea_stub`] verbatim, with `agid_struct` from the CDB base
    ///   ([`Self::find_vid_agid_struct_classic`] — the classic finder fix).
    /// * AKE: the reject writer `lsrs; movs r1,#1` at `AKE_GATE_SIG_CLASSIC`'s
    ///   `match+6`, returning into the shared `bl set_agid_state` at `match+0xa`.
    pub(crate) fn emit_rawread_classic(
        &self,
        image: &[u8],
        out: &mut Vec<u8>,
        flag_base: u32,
    ) -> Result<Vec<(&'static str, u32)>> {
        use super::mt1939::{masked_matches, AKE_GATE_SIG_CLASSIC, VID_GATE_SIG_CLASSIC};
        const LO: usize = 0x0017_0000;
        const HI: usize = 0x0018_0000;

        // ---- validate (read-only) ----
        // Classic VID producer Gate-A, required unique.
        let vid_gate = match masked_matches(image, VID_GATE_SIG_CLASSIC, LO, HI).as_slice() {
            [one] => *one,
            hits => bail!(
                "classic VID gate matched {} time(s) in [0x{LO:x},0x{HI:x}) (want 1)",
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
        // Classic AGID struct = CDB base (the finder fix), NOT the r7 heuristic.
        let agid_struct = self.find_vid_agid_struct_classic(image)?;
        let gatea_bytes =
            self.build_gatea_stub(flag_base, agid_struct, gatea_authed, gatea_deny)?;

        // Scratch clear-VID buffer (audit-only: no stub consumes it — the producer
        // stages the clear VID there itself; pinned unique for the audit).
        let (vid_producer, scratch) = self.find_vid_producer(image)?;

        // Classic AKE accept gate (04 02), required unique. The reject writer folds
        // the `lsrs` (AGID compute) into the 4 replaced bytes.
        let ake = match masked_matches(image, AKE_GATE_SIG_CLASSIC, LO, HI).as_slice() {
            [one] => *one,
            hits => bail!(
                "classic AKE gate matched {} time(s) in [0x{LO:x},0x{HI:x}) (want 1)",
                hits.len()
            ),
        };
        let ake_site = ake + 6;
        let lsrs_hw = u16::from_le_bytes([image[ake_site], image[ake_site + 1]]);
        let movs_hw = u16::from_le_bytes([image[ake_site + 2], image[ake_site + 3]]);
        if lsrs_hw != 0x0980 || movs_hw != 0x2101 {
            bail!(
                "classic AKE reject writer (lsrs r0,#6; movs r1,#1) not at 0x{ake_site:x} \
                 (got 0x{lsrs_hw:04x} 0x{movs_hw:04x})"
            );
        }
        let ake_back = (ake + 0xa) as u32; // shared `bl set_agid_state` call site
        let ake_bytes = self.build_ake_stub_classic(flag_base, ake_back)?;

        // ---- commit on a working copy (atomic) ----
        let mut w = out.clone();
        let gatea_stub_va = self.free_space(&w, gatea_bytes.len() + 16)?;
        let gatea_bl = thumb::encode_bl(gatea_cmp, gatea_stub_va)
            .ok_or_else(|| anyhow!("classic Gate-A detour `bl` out of range"))?;
        thumb::write(&mut w, gatea_stub_va as usize, &gatea_bytes);
        thumb::write(&mut w, gatea_cmp, &gatea_bl);

        let ake_stub_va = self.free_space(&w, ake_bytes.len() + 16)?;
        let ake_bl = thumb::encode_bl(ake_site, ake_stub_va)
            .ok_or_else(|| anyhow!("classic AKE detour `bl` out of range"))?;
        thumb::write(&mut w, ake_stub_va as usize, &ake_bytes);
        thumb::write(&mut w, ake_site, &ake_bl);

        *out = w;
        Ok(vec![
            ("gatea_gate", gatea_cmp as u32),
            ("gatea_stub_va", gatea_stub_va),
            ("gatea_authed", gatea_authed),
            ("ake_site", ake_site as u32),
            ("ake_stub_va", ake_stub_va),
            ("ake_gate", ake as u32),
            ("deny", gatea_deny),
            ("scratch", scratch),
            ("vid_producer", vid_producer),
        ])
    }
}
