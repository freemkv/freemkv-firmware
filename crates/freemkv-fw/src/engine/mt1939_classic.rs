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
use thumb_asm::{self as thumb, Asm, CommandTable};

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

    /// MT1939-**classic** create (bare base): the modern [`Self::build_report`]
    /// monolith is modern-shaped (modern table window, the `FLAG_TABLE_BASE`
    /// constant, modern `emit_*` windows) and dies on classic at the flag-table
    /// SRAM assert. This is its classic analogue — the same base every finder in
    /// `mt1939-classic-identity-base.md` proves 17/17, mirroring the base tier of
    /// [`Self::build_modify_classic`] but producing a [`CreateReport`].
    ///
    /// Ships the injected `0x3C-0E` handler (Identity / SET / GET / SAVE / RESET /
    /// DumpAll) + record repoint + CMAC re-sign, and — now that the classic boot
    /// hook is blessed (`CLASSIC_BOOT_BLESSED`, emulation-verified) — the always-on
    /// boot-init hook plus the classic feature stubs, mirroring the modern
    /// [`Self::build_report`] structure (boot FIRST, then features).
    ///
    /// **SAFETY COUPLING.** The boot hook fills the flag table with `0xFF` at
    /// power-on, which is what makes the tri-state `0x00 == OFF` invariant every
    /// feature stub relies on hold on a freshly powered drive. It is therefore
    /// emitted FIRST and every feature emit is gated on its success; if
    /// `Self::emit_boot_init` fails on some classic image, this falls back to a
    /// BARE base (handler + record repoint + CMAC only) and ships NO feature stub —
    /// never a feature that would boot into its OFF state without the 0xFF-fill.
    ///
    /// The classic feature set that actually resolves (measured over the 17 classic
    /// images): **Region-free** 17/17, **Raw-read** Gate-A + Encryption 17/17.
    /// **Speed**, **UHD** and **BD** are genuine architecture misses on this pre-UHD
    /// (2012–2016) silicon: no ramp-ceiling gate (Speed), no disc-version classifier
    /// (UHD), and no separate disc-mode/class REPORT-KEY accept gate (BD — acceptance
    /// is purely AKE-gated, already handled). **HRL** 17/17 (classic cert-revocation
    /// lookup via `emit_hrl_classic`). Net classic set: Region + Raw-read/Encryption
    /// + HRL = 17/17.
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

        // Classic reboot verb: bake `boot_init_site - 0x10` (the classic caller_bl_site,
        // minus 0x10 — the analogous offset to the modern boot function prologue). If
        // the classic site refuses to resolve, treat the reboot verb as unwired (0)
        // rather than failing the whole classic base build.
        // Classic Verb::Reboot: RETIRED (baked as 0 = inert). The modern
        // `boot_init_site - 0x10` offset is anchored on BOOT_INIT_SIG's fixed
        // `bmi +3`, so on modern images subtracting 0x10 always lands at the
        // boot function's push prologue. The classic BOOT_INIT_SIG_CLASSIC
        // resolves a caller-bl inside whichever parent function calls the
        // classic leaf helper, and that VA has no fixed offset to any function
        // entry. Baking `site - 0x10` would blx into garbage and wedge the
        // drive. Reboot on classic images is left inert (returns zeroed reply,
        // no side effect); a future signature dedicated to the classic boot
        // function entry can flip this back on.
        let boot_function_entry: u32 = 0;
        let handler_bytes = self
            .build_handler(image, record.handler, flag_base, boot_function_entry)
            .context("classic base: assembling the 3C-0E handler")?;

        let mut out = image.to_vec();
        let handler_va = self.free_space(&out, handler_bytes.len() + 16)?;
        thumb::write(&mut out, handler_va as usize, &handler_bytes);

        // ---- FEATURE emits — mirror the modern `build_report` structure (boot hook
        //      FIRST, then the feature stubs), but with the CLASSIC emits. All fact
        //      accumulators default to "unwired" (0 / empty), so a per-feature miss
        //      simply leaves that feature off the advertised set — the base still
        //      ships. Populated below only on the paths that verifiably resolve.
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
        let mut hrl_sites: Vec<u32> = Vec::new();
        let mut hrl_stub_va = 0u32;

        // SAFETY COUPLING (the whole point of the classic boot blessing): the
        // always-on boot-init hook writes 0xFF into every flag byte at power-on,
        // which is what makes the tri-state `0x00 == OFF` invariant every feature
        // stub relies on hold on a freshly powered drive. Emit it FIRST; if it
        // fails on some classic image, fall back to a BARE base (handler + record
        // repoint + CMAC only) — never ship a feature stub without the 0xFF-fill,
        // or the drive would boot every feature into its OFF state. Each feature
        // emit inside the boot-success arm is otherwise best-effort.
        if let Ok((site, va)) = self
            .resolve_boot_init_pair(image)
            .and_then(|pair| self.emit_boot_init(image, &mut out, flag_base, pair))
        {
            boot_init_site = site;
            boot_stub_va = va;

            // Region-free — classic REGION_EMIT_SIG window (proven on classic, the
            // same emit `build_modify_classic` ships).
            if let Ok((emitter, va)) = self.emit_region_classic(&mut out, flag_base) {
                region_emitter = emitter;
                region_stub_va = va;
            }

            // Raw read — classic Gate-A (`04 01`) + AKE accept (`04 02`); NO deny
            // detour (the classic deny path stays byte-identical to OEM). Same emit
            // `build_modify_classic` ships. Facts come back as a key/value list.
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

            // UHD / BD / HRL — the modern AACS detours, tried best-effort. On classic
            // these are HONEST MISSES: UHD (no disc-version classifier — these are
            // pre-UHD 2012–2016 BD writers) and BD (no separate disc-mode/class REPORT-KEY
            // accept gate; BD acceptance is purely AKE-gated, which freemkv already
            // handles 17/17) were both disasm-proven genuinely absent — the classic
            // refusal is generic auth-gated inline sense with no unique anchor, so there
            // is nothing safe to detour. Each finder self-guards (unique match + landmark
            // re-verify) and resolves 0× on all 17, so nothing is wired and there is zero
            // wrong-detour risk.
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
            // HRL — the MODERN hrl_skip_detour misses on classic (the classic lookup
            // body diverges at the 10th halfword). emit_hrl_classic locates the classic
            // HRL lookup via HRL_LOOKUP_SIG_CLASSIC (unique 17/17), verifies every cert
            // site's cmp/bne revoke shape + the classic OEM 6F-deny head, and reuses the
            // shared build_hrl_skip_stub (flag[Hrl]==STATE_OFF -> force clean/accept
            // revoked; ON/OEM -> replay OEM). Self-guarding; bails (unwired) on any
            // mismatch.
            if let Ok((sites, stub_va)) = self.emit_hrl_classic(image, &mut out, flag_base) {
                hrl_sites = sites;
                hrl_stub_va = stub_va;
            }
        }

        // Downgrade-enable (DE) byte: a fixed base identity-page byte, NOT a
        // tri-state feature flag, so it is always safe and does not depend on the
        // boot 0xFF-fill (written regardless of the boot-hook outcome, exactly as
        // the modern `build_report` does). Best-effort: an image whose identity page
        // isn't located just doesn't get DE.
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
            // Speed is a documented classic MISS (no MT1959-style ramp-ceiling gate).
            speed_gate: 0,
            speed_stub_va: 0,
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
            // Auth-cell state-band widen (MT1959-family only): the classic MT1939
            // lineage does not carry the extended `ldr r4,[pc,...] = 0x01FF9E04`
            // shape (its post-classification path is different), so this lever is
            // never wired on classic. Report 0s.
            auth_cell_site: 0,
            auth_cell_stub_va: 0,
            hrl_sites,
            hrl_stub_va,
            de_off: de_off.unwrap_or(0),
            flag_base,
            free_sram_cell: flag_base,
        })
    }

    /// Commit a single modern-style best-effort detour onto the classic create
    /// path: place `bytes` in CMAC-covered free space and write a `bl` to it at
    /// `site` (replacing the OEM instruction there). Returns the stub VA on
    /// success, or `None` if free space / `bl` range can't be satisfied (a miss —
    /// the feature is left unwired, the base still ships). Mirrors the per-feature
    /// commit block modern `emit_rawread` uses, but for the classic report path.
    fn commit_classic_detour(&self, out: &mut [u8], site: usize, bytes: &[u8]) -> Option<u32> {
        let stub_va = self.free_space(out, bytes.len() + 16).ok()?;
        let bl = thumb::encode_bl(site, stub_va)?;
        thumb::write(out, stub_va as usize, bytes);
        thumb::write(out, site, &bl);
        // Emit-time decode-back guard — miss-is-graceful per this fn's
        // `Option` contract, so an install-shape failure returns None
        // (feature left unwired, base still ships) rather than panicking.
        if thumb::decode_bl(out, site) != Some(stub_va) {
            return None;
        }
        Some(stub_va)
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

        // Classic reboot verb: same rule as build_report_classic — bake
        // `boot_init_site - 0x10` from the classic caller_bl_site when it
        // resolves (blessed), else 0 (unwired). Keeps modify byte-identical to
        // create on the classic base.
        // Classic Verb::Reboot: RETIRED (baked as 0 = inert). The modern
        // `boot_init_site - 0x10` offset is anchored on BOOT_INIT_SIG's fixed
        // `bmi +3`, so on modern images subtracting 0x10 always lands at the
        // boot function's push prologue. The classic BOOT_INIT_SIG_CLASSIC
        // resolves a caller-bl inside whichever parent function calls the
        // classic leaf helper, and that VA has no fixed offset to any function
        // entry. Baking `site - 0x10` would blx into garbage and wedge the
        // drive. Reboot on classic images is left inert (returns zeroed reply,
        // no side effect); a future signature dedicated to the classic boot
        // function entry can flip this back on.
        let boot_function_entry: u32 = 0;
        let handler_bytes = self
            .build_handler(image, record.handler, flag_base, boot_function_entry)
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
        let boot_init_pair = self.resolve_boot_init_pair(image)?;
        let (_boot_init_site, _boot_stub_va) =
            self.emit_boot_init(image, &mut out, flag_base, boot_init_pair)?;

        let mut levers: Vec<LeverReport> = Vec::new();

        // Identity / vendor handler + DumpAll — structurally valid, self-verifies,
        // passes the structural audit → produced unconditionally (static-only label).
        // `boot_function_entry` is 0 on classic (Reboot arm emits inert — see
        // build_handler); recorded here so the audit can skip the Reboot-literal
        // check without special-casing classic.
        levers.push(LeverReport::applied(
            LeverId::Identity,
            vec![
                ("handler_va", handler_va),
                ("record_off", record.off as u32),
                ("flag_base", flag_base),
                ("boot_function_entry", boot_function_entry),
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
        //
        // HRL-skip is emitted alongside RawRead (and its facts folded in),
        // MIRRORING `build_report_classic` — otherwise create and modify
        // produce non-identical images on the same classic base and
        // `corpus_create_and_modify_agree_byte_for_byte` fails once
        // `CLASSIC_BOOT_BLESSED` is true. Modern `build_modify` (mt1959.rs)
        // folds HRL facts into the RawRead lever the same way; keep the two
        // engines symmetric so downstream (audit / reporter) sees one lever
        // shape regardless of family.
        levers.push(if cap.bd_aacs {
            match self.emit_rawread_classic(image, &mut out, flag_base) {
                Ok(mut facts) => {
                    if let Ok((sites, stub_va)) = self.emit_hrl_classic(image, &mut out, flag_base)
                    {
                        if stub_va != 0 {
                            facts.push(("hrl_stub_va", stub_va));
                            for (k, &s) in sites.iter().take(3).enumerate() {
                                facts.push((["hrl_site", "hrl_site2", "hrl_site3"][k], s));
                            }
                        }
                    }
                    LeverReport::applied(LeverId::RawRead, facts)
                }
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
        crate::install_guard::verify_branch(
            out,
            region_site,
            thumb::BranchKind::Bl,
            region_stub_va,
            "classic Region",
        )?;
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
        // Full-image scan (de-hardcoded): the classic VID/AKE gates are unique
        // image-wide on all 17 classic images, but a fixed 0x170000..0x180000 window
        // missed the ones whose AACS block sits below/above it (e.g. BH16NS40 at
        // ~0x139k, BE14NU40 1.01 at ~0x180640). The unique-match guard below keeps it
        // safe. Same fix as the modern AACS finders.
        let lo = 0usize;
        let hi = image.len();

        // ---- validate (read-only) ----
        // Classic VID producer Gate-A, required unique.
        let vid_gate = match masked_matches(image, VID_GATE_SIG_CLASSIC, lo, hi).as_slice() {
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
        // Classic AGID struct = CDB base (the finder fix), NOT the r7 heuristic.
        let agid_struct = self.find_vid_agid_struct_classic(image)?;
        // Same de-bus latch clear the modern path installs — see
        // `build_gatea_stub`. Resolved here so the classic bare-read arm gets it
        // too; a classic image that cannot resolve it refuses rather than
        // shipping a Gate-A that forces auth without clearing the latch.
        let classic_aacs_reset = self.find_aacs_session_reset(image)?;
        let gatea_bytes = self.build_gatea_stub(
            flag_base,
            agid_struct,
            gatea_authed,
            gatea_deny,
            classic_aacs_reset,
        )?;

        // Scratch clear-VID buffer (audit-only: no stub consumes it — the producer
        // stages the clear VID there itself; pinned unique for the audit).
        // Audit-only (no stub consumes it), and it recurses through the MODERN
        // find_vid_gate whose window can miss a classic image whose AACS block is
        // relocated (e.g. BE14NU40 1.01 at ~0x180k). Best-effort: never fail the
        // classic Raw-read/AKE emit on an audit anchor.
        let (vid_producer, scratch) = self.find_vid_producer(image).unwrap_or((0, 0));

        // Classic AKE accept gate (04 02), required unique. The reject writer folds
        // the `lsrs` (AGID compute) into the 4 replaced bytes.
        let ake = match masked_matches(image, AKE_GATE_SIG_CLASSIC, lo, hi).as_slice() {
            [one] => *one,
            hits => bail!(
                "classic AKE gate matched {} time(s) in [0x{lo:x},0x{hi:x}) (want 1)",
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

    /// Host-Revocation-List skip emission for the MT1939 **classic** cert path — the
    /// classic-codegen analogue of the modern [`Self::hrl_skip_detour`], reusing the
    /// modern [`Self::build_hrl_skip_stub`] verbatim (the site contract is identical:
    /// each detour `bl` replaces a `cmp r0,#0; bne <revoke>` so on entry `lr` is the
    /// CLEAN fall-through and `r0` is the HRL result). Only the SITE FINDER is classic:
    /// the modern one anchors on [`super::core::HRL_LOOKUP_SIG`] (matches 0× on
    /// classic) and a `ldrb r0,[r4,#2]` (`0x78A0`) revoke head, whereas classic uses
    /// [`super::mt1939::HRL_LOOKUP_SIG_CLASSIC`] and an `ldrb r0,[r5,#2]` (`0x78A8`)
    /// head — and one classic layout reaches the check through a single unconditional
    /// `b` after the `bl <hrl>` (`bl hrl; b <check>`), which this finder follows.
    ///
    /// Grounded, never hardcoded, and self-guarding — a resolve requires ALL of:
    ///   1. the classic HRL lookup routine present and UNIQUE image-wide;
    ///   2. every `bl <hrl>` followed (within a short budget, across at most one
    ///      unconditional `b`) by `cmp r0,#0; bne <T>`, ALL sites agreeing on one `T`;
    ///   3. `T` carrying the version-invariant classic OEM revoke head
    ///      `ldrb r0,[r5,#2]; cmp r0,#0; bne …` immediately followed (head+6) by the
    ///      6F copy-protection sense `movs r0,#0x6f`.
    ///
    /// Any disagreement / missing landmark bails (HRL left unwired), so a mis-anchored
    /// match refuses rather than corrupting the cert path. Commits on a working copy
    /// (atomic): the stub lands in CMAC-covered free space and every `bl` is
    /// range-checked before ANY is written. Returns `(cmp_site_offsets, stub_va)`.
    pub(crate) fn emit_hrl_classic(
        &self,
        image: &[u8],
        out: &mut Vec<u8>,
        flag_base: u32,
    ) -> Result<(Vec<u32>, u32)> {
        use super::mt1939::{masked_matches, HRL_LOOKUP_SIG_CLASSIC};

        // ---- locate the classic HRL lookup routine, required unique image-wide ----
        let hrl = match masked_matches(image, HRL_LOOKUP_SIG_CLASSIC, 0, image.len()).as_slice() {
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

        // ---- cert-path check sites: `bl <hrl>` then `cmp r0,#0; bne <revoke>`,
        //      following at most one unconditional T2 `b` (the classic `bl hrl; b
        //      <check>` layout). ALL sites must agree on one revoke target. ----
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
                        p = (p as i32 + 4 + d * 2) as usize;
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

        // ---- verify the shared revoke target's version-invariant classic OEM head:
        //      `ldrb r0,[r5,#2]; cmp r0,#0; bne …; movs r0,#0x6f` (the 6F deny). ----
        let t = revoke as usize;
        let head_ok = t + 8 <= image.len()
            && hw(t) == 0x78A8 // ldrb r0,[r5,#2]   (classic r5; modern head is r4/0x78A0)
            && hw(t + 2) == 0x2800 // cmp  r0,#0
            && (hw(t + 4) & 0xFF00) == 0xD100 // bne  <loop>
            && hw(t + 6) == 0x206F; // movs r0,#0x6f   (6F copy-protection sense)
        if !head_ok {
            bail!("classic HRL revoke target 0x{revoke:x} lacks the OEM 6F-deny head — refusing");
        }

        // ---- build the shared skip stub (identical contract to modern) ----
        let bytes = self.build_hrl_skip_stub(flag_base, revoke)?;

        // ---- commit on a working copy (atomic): range-check EVERY `bl` before any
        //      is written — a partial write would be a wrong (cert-corrupting) detour.
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
