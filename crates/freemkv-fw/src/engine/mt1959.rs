//! MediaTek MT1959 engine.
//!
//! All chip knowledge lives in [`super::core`]: the
//! scanner signature that proves the dispatch-record format, and the grounded
//! finds (CDB base, sense-setter, the `0x3C` handler) that are *derived from the
//! image*, never hardcoded. This module is just the [`Engine`] wiring; it
//! composes the dumb [`thumb_asm`] verbs against that knowledge.

use anyhow::{anyhow, bail, Context, Result};

use freemkv_flash::cmac;

use super::core::*;
use super::lever::{LeverId, LeverReport, Validation};
use super::{CreateReport, Engine, ModifyReport};
use crate::abi;
use crate::family::{self, Capability, ChipInfo, MediaClass};
use thumb_asm::{self as thumb, CommandTable};

/// The MT1959 platform engine.
pub struct Mt1959Engine;

impl Engine for Mt1959Engine {
    fn name(&self) -> &'static str {
        "MT1959"
    }

    fn create(&self, image: &[u8]) -> Result<CreateReport> {
        self.build_report(image)
    }

    fn modify(&self, image: &[u8]) -> Result<ModifyReport> {
        let chip = family::detect_chip(image)?;
        let cap = family::capability_for(&chip.model, chip.family);
        self.build_modify(image, &chip, &cap)
    }
}

/// Grounded facts produced by the Raw-read lever (VID + AKE + Gate-A + deny).
/// `Default` (all-`0` / empty) is the "feature not wired on this image" value used
/// when the best-effort raw-read emit misses — the base still ships without it.
#[derive(Default)]
struct RawReadFacts {
    ake_gate: u32,
    /// The AKE detour `bl` site (where the redirect was written) — needed by the
    /// structural audit to recompute the expected hook via `encode_bl`.
    ake_site: u32,
    ake_stub_va: u32,
    gatea_cmp: u32,
    gatea_stub_va: u32,
    deny_site: u32,
    deny_stub_va: u32,
    /// `04 03` UHD mode-gate neutralizer detour site — the classifier prologue's
    /// disc-version reload (`UHD_CLASSIFIER_SIG` match+6), replaced by a `bl` to the
    /// UHD stub. `0` when not wired (image whose classifier prologue is not the known
    /// MT1959 shape).
    uhd_site: u32,
    /// Injection address of the `04 03` UHD mode-gate neutralizer trampoline. `0`
    /// when not wired.
    uhd_stub_va: u32,
    /// The three HRL-skip cert-path detour sites (`flag[Feature::Hrl]==STATE_OFF`):
    /// each is a `cmp r0,#0; bne <6F/00>` replaced by a `bl` to the shared HRL-skip
    /// stub. Empty when the HRL cert path is not the known shape (lever MISS).
    hrl_sites: Vec<u32>,
    /// Injection address of the shared HRL-skip trampoline. `0` when not wired.
    hrl_stub_va: u32,
    /// `Feature::Bd` REPORT KEY refuse detour site — the mode-0 class check
    /// (`ldrb r0,[r2,#7]; cmp r0,#2`, [`BD_GATE_SIG`] `anchor+16`), replaced by a `bl`
    /// to the BD-refuse stub. `0` when not wired (image whose REPORT KEY gate is not
    /// the known MT1959 shape).
    bd_site: u32,
    /// Injection address of the `Feature::Bd` BD-refuse trampoline. `0` when not wired.
    bd_stub_va: u32,
    /// `Feature::Unrestricted` auth-cell state-band widen detour site — the OEM
    /// `cmp r0,#0xC; bne <deny>` at `AUTH_CELL_SIG` `anchor+10`
    /// (`0x00136826` on BU40N 1.00), replaced by a `bl` to the widen stub. `0`
    /// when not wired (image does not carry the known auth-cell shape).
    auth_cell_site: u32,
    /// Injection address of the `Feature::Unrestricted` auth-cell widen trampoline.
    /// `0` when not wired.
    auth_cell_stub_va: u32,
    vid_producer: u32,
}

impl Mt1959Engine {
    /// Full freemkv build: prove the find, inject the handler into covered free
    /// space, repoint only the `0x3C` handler pointer (flags untouched), and
    /// re-sign. Returns the new image and the grounded facts used. The [`Engine`]
    /// trait's `create` delegates here.
    ///
    /// [`Engine`]: super::Engine
    pub fn build_report(&self, image: &[u8]) -> Result<CreateReport> {
        // ---- BASE (mandatory) — the verb handler + boot hook + save/reset need these;
        // a miss means this image cannot carry a freemkv base, so refuse.
        let scanner_entry = self.find_scanner_entry(image)?;
        let cdb_base = self.find_cdb_base(image)?;
        // sense_setter is a REPORT anchor only — build_handler never uses it, and the
        // classic scanner raises sense inline (no movs r2/r1/r0 + bl triple), so its
        // modern shape legitimately misses on classic. Best-effort (0 when absent) so
        // it never blocks the base; byte-identical on every path (emit ignores it).
        let sense_setter = self.sense_setter(image).unwrap_or(0);
        let record = self.find_live_record(image, abi::READ_BUFFER_OPCODE)?;
        // ---- FEATURE facts (best-effort) — these are per-feature report anchors, NOT
        // required by the base handler. A miss = that feature is unavailable on this
        // image (0/None), advertised as such; it must never fail the base build.
        // (BASE/GATE DECOUPLING: was hard-`?`, which made a single drifted feature
        // signature refuse an otherwise-perfect base — e.g. the JBC6 lineage.)
        let (vid_producer, vid_out_buf) = self.find_vid_producer(image).unwrap_or((0, 0));
        let vid_gate_setter = self.find_vid_gate_setter(image).unwrap_or(0);
        let setdiscmode = self.find_setdiscmode(image).unwrap_or(0);
        let de_off = self.find_de_byte(image).ok(); // DowngradeEnable feature (optional)
                                                    // AUDIT-only candidate cell (unsound; never used as the flag base) — best-effort.
        let free_sram_cell = self.find_free_sram_cell(image).unwrap_or(0);
        // Flag-table base actually used by the emitted code: the validated 204-byte
        // free hole (chip constant, hardware-proven writable+free across 24 images).
        let flag_base = FLAG_TABLE_BASE;
        // Hybrid safety belt: cells are chip constants, but assert per-image they
        // sit in mapped RAM and are unreferenced before we commit. The table holds
        // `flag[Feature::X]` for feature ids `1..=NUM_FEATURES` (slot 0 is the
        // NV saved-marker), so it spans `NUM_FEATURES + 1` = 7 bytes.
        let flag_table_len = NUM_FEATURES as u32 + 1;
        self.assert_sram_cell_free(image, flag_base, flag_table_len, "flag table")?;
        // TEMPORARY flash-write probe: its 1-byte SRAM source-staging cell lives in
        // the same validated free hole, past the flag table — guard-check it per
        // image so we never stage the source byte over live SRAM.
        self.assert_sram_cell_free(
            image,
            flag_base + FLASHWRITE_SCRATCH_OFF,
            1,
            "flash-write scratch",
        )?;

        // Resolve the boot-init detour `(conv, orig_init)` pair once, up front,
        // so we can bake the boot function's entry VA (conv - 0x10) into the
        // handler as the target of Verb::Reboot AND thread the same pair into
        // `emit_boot_init` below — no second `find_boot_init` scan.
        let boot_init_pair = self.resolve_boot_init_pair(image)?;
        let resolved_boot_init_site = boot_init_pair.0 as u32;
        let boot_function_entry = resolved_boot_init_site.wrapping_sub(0x10);

        let handler_bytes = self
            .build_handler(image, record.handler, flag_base, boot_function_entry)
            .context("assembling the 3C-0E handler")?;

        let mut out = image.to_vec();

        // Place the injected code blobs into CMAC-covered free space, in order.
        // Each `free_space` call runs on the progressively-written image, so the
        // large erased run shrinks past each blob and the next lands after it.
        let handler_va = self.free_space(&out, handler_bytes.len() + 16)?;
        thumb::write(&mut out, handler_va as usize, &handler_bytes);
        // Absence guard: the AACS session-rearm wrapper VA (if resolvable)
        // MUST NOT appear as a callable literal in the handler bytes. Strategy A
        // (0.8.14) removed the rearm-on-SET call; a future refactor that
        // reintroduces the wrapper as a `blx` target would silently wedge the
        // vendor-CDB path with no medium. See `install_guard::assert_literal_absent`.
        if let Ok(rearm) = self.find_aacs_session_rearm(image) {
            crate::install_guard::assert_literal_absent(
                &out,
                handler_va as usize,
                handler_va as usize + handler_bytes.len(),
                rearm,
                "SET-Encryption rearm removal",
            )?;
        }

        // Always-on boot-init hook — installed FIRST (right after the handler, before
        // any feature stub) so the free_space allocation order is identical on the
        // create and modify paths (handler → boot → speed → region → raw-read). It
        // writes 0xFF into every flag at power-on, which is what makes the tri-state
        // `0x00 == OFF` safe. The pre-resolved pair is threaded through so we don't
        // re-scan for the site.
        let (boot_init_site, boot_stub_va) =
            self.emit_boot_init(image, &mut out, flag_base, boot_init_pair)?;
        debug_assert_eq!(
            boot_init_site, resolved_boot_init_site,
            "boot_init_site drifted between resolve and emit"
        );

        // Speed / Region / Raw-read levers are emitted through the exact same
        // `emit_*` helpers `build_modify` uses (single source of truth), so a fresh
        // `create` and a `modify` on the same base produce byte-for-byte identical
        // images — asserted by `create_and_modify_agree_on_base`. Each helper
        // re-finds its own anchors and preserves the `free_space` allocation order
        // (handler → speed → region → raw-read[ake → gatea → deny → uhd →
        // hrl → bd → auth-cell]). The AKE gate is resolved via `ake_detour`
        // (desktop → NB → V5), and uhd/hrl/bd/auth-cell are graceful
        // (unwired = 0/empty on unknown shapes),
        // exactly as `modify` treats them — so `create` no longer diverges on the
        // NB/V5 images the old inline `find_ake_gate` path failed.
        // BASE/GATE DECOUPLING: each feature emit is best-effort. A miss leaves the
        // feature unwired (0) and off the advertised set, but the base image still
        // ships. On the fully-resolving base (BU40N + the 91) every emit succeeds, so
        // the free_space order and output are byte-identical (golden KAT unaffected).
        let (speed_gate, speed_stub_va) = self
            .emit_speed(image, &mut out, flag_base)
            .unwrap_or((0, 0));
        let (region_emitter, region_stub_va) = self
            .emit_region(image, &mut out, flag_base)
            .unwrap_or((0, 0));
        let f = self
            .emit_rawread(image, &mut out, flag_base)
            .unwrap_or_default();

        // HRL wipe-once is destructive and gated behind HRL_WIPE_ARMED (default
        // off) — its record codegen is `hrl_valid_empty_record`; no image ships the
        // wipe detour until a hardware-validated confirmation flips the constant.
        let _hrl_wipe_armed = HRL_WIPE_ARMED;

        // Downgrade-enable (DE) byte: write 0xDE at the identity-page slot when the
        // slot resolved (idempotent on already-DE images). Best-effort: an image whose
        // identity page isn't located just doesn't get DE — the base still ships.
        if let Some(off) = de_off {
            out[off as usize] = 0xDE;
        }

        // repoint handler pointer only; flags stay exactly as OEM shipped.
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
        let _ = CHAIN_FLAG; // (documented; walk uses it — kept for the record format)

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
            vid_out_buf,
            vid_gate_setter,
            setdiscmode,
            speed_gate,
            speed_stub_va,
            region_emitter,
            region_stub_va,
            ake_gate: f.ake_gate,
            ake_stub_va: f.ake_stub_va,
            gatea_gate: f.gatea_cmp,
            gatea_stub_va: f.gatea_stub_va,
            deny_reset_gate: f.deny_site,
            deny_stub_va: f.deny_stub_va,
            uhd_classifier_site: f.uhd_site,
            uhd_stub_va: f.uhd_stub_va,
            bd_gate_site: f.bd_site,
            bd_stub_va: f.bd_stub_va,
            auth_cell_site: f.auth_cell_site,
            auth_cell_stub_va: f.auth_cell_stub_va,
            hrl_sites: f.hrl_sites,
            hrl_stub_va: f.hrl_stub_va,
            de_off: de_off.unwrap_or(0),
            flag_base,
            free_sram_cell,
        })
    }

    /// Never-abort MODIFY: run every applicable lever, collect per-lever
    /// outcomes, re-sign once. Aborts the whole run **only** when the base
    /// vendor-command prerequisites cannot be built (nothing modifiable) — a
    /// single lever missing its signature does not stop the others.
    ///
    /// On an image where every lever applies (e.g. the BU40N 1.00 base) this
    /// emits byte-for-byte the same image as [`Self::build_report`]: the same
    /// finds, the same `free_space` allocation order (handler → speed → region →
    /// ake → gate-a → deny), the same detours, one `cmac::resign`. That equality
    /// is asserted by `create_and_modify_agree_on_base` in the KAT tests.
    pub fn build_modify(
        &self,
        image: &[u8],
        chip: &ChipInfo,
        cap: &Capability,
    ) -> Result<ModifyReport> {
        // Idempotency: re-feeding a freemkv-modified image must not re-patch or
        // error out (the repointed 0x3C record now targets our injected handler,
        // which has no stock push-lr prologue). Instead, report every lever
        // AlreadyPresent and return the image byte-identical. Detected by the
        // RESP_MAGIC the Identity handler always injects (absent from stock OEM).
        if is_freemkv_patched(image) {
            return Ok(self.already_present_report(image, chip, cap, "MT1959"));
        }

        // ---- Base prerequisites: if these fail the vendor command cannot exist
        //      at all → whole-run abort ("nothing modifiable"). ----
        self.find_scanner_entry(image)
            .context("nothing modifiable: dispatch scanner signature not found")?;
        self.find_cdb_base(image)?;
        self.sense_setter(image)?;
        let record = self.find_live_record(image, abi::READ_BUFFER_OPCODE)?;
        let flag_base = FLAG_TABLE_BASE;
        let flag_table_len = NUM_FEATURES as u32 + 1;
        self.assert_sram_cell_free(image, flag_base, flag_table_len, "flag table")?;
        // TEMPORARY flash-write probe scratch cell (see build_report).
        self.assert_sram_cell_free(
            image,
            flag_base + FLASHWRITE_SCRATCH_OFF,
            1,
            "flash-write scratch",
        )?;
        // Boot function entry baked into the Verb::Reboot arm — same rule as
        // build_report (conv - 0x10). Resolve the pair once and thread it into
        // `emit_boot_init` below to avoid a second `find_boot_init` scan.
        let boot_init_pair = self.resolve_boot_init_pair(image)?;
        let resolved_boot_init_site = boot_init_pair.0 as u32;
        let boot_function_entry = resolved_boot_init_site.wrapping_sub(0x10);
        let handler_bytes = self
            .build_handler(image, record.handler, flag_base, boot_function_entry)
            .context("assembling the 3C-0E handler")?;

        let mut out = image.to_vec();
        let handler_va = self.free_space(&out, handler_bytes.len() + 16)?;
        thumb::write(&mut out, handler_va as usize, &handler_bytes);
        if let Ok(rearm) = self.find_aacs_session_rearm(image) {
            crate::install_guard::assert_literal_absent(
                &out,
                handler_va as usize,
                handler_va as usize + handler_bytes.len(),
                rearm,
                "SET-Encryption rearm removal",
            )?;
        }

        // Always-on boot-init hook (see build_report): same allocation slot on both
        // paths (handler → boot → …), so create and modify stay byte-identical.
        // Fail-closed if the boot-init site is absent — a base prerequisite now, since
        // tri-state OFF is unsafe without it.
        let (boot_init_site, boot_stub_va) =
            self.emit_boot_init(image, &mut out, flag_base, boot_init_pair)?;
        debug_assert_eq!(
            boot_init_site, resolved_boot_init_site,
            "boot_init_site drifted between resolve and emit"
        );

        let mut levers: Vec<LeverReport> = Vec::new();

        // Identity / base (the vendor handler + DumpAll + always-on boot-init hook).
        // Always applicable — its success is what makes every toggle addressable.
        // `boot_function_entry` is recorded so the structural audit can verify the
        // debug-knock Reboot arm baked the correct Thumb-tagged literal into the
        // emitted handler bytes (see engine::audit).
        levers.push(LeverReport::applied(
            LeverId::Identity,
            vec![
                ("handler_va", handler_va),
                ("record_off", record.off as u32),
                ("boot_init_site", boot_init_site),
                ("boot_stub_va", boot_stub_va),
                ("boot_function_entry", boot_function_entry),
            ],
        ));

        // Speed (read-ramp ceiling) — BD capability.
        levers.push(if cap.media_class >= MediaClass::Bd || cap.bd_aacs {
            match self.emit_speed(image, &mut out, flag_base) {
                Ok((gate, va)) => LeverReport::applied(
                    LeverId::Speed,
                    vec![("speed_gate", gate), ("speed_stub_va", va)],
                ),
                Err(e) => LeverReport::missed(LeverId::Speed, format!("{e:#}")),
            }
        } else {
            LeverReport::not_applicable(LeverId::Speed, "no BD read-ramp on this model")
        });

        // Region-free (RPC-1) — DVD or BD.
        levers.push(if cap.region_lockable {
            match self.emit_region(image, &mut out, flag_base) {
                Ok((emitter, va)) => LeverReport::applied(
                    LeverId::RegionFree,
                    vec![("region_emitter", emitter), ("region_stub_va", va)],
                ),
                Err(e) => LeverReport::missed(LeverId::RegionFree, format!("{e:#}")),
            }
        } else {
            LeverReport::not_applicable(LeverId::RegionFree, "no region lever on this model")
        });

        // Raw read / clear VID (VID gate + AKE accept + deny reset) — AACS/BD.
        levers.push(if cap.bd_aacs {
            match self.emit_rawread(image, &mut out, flag_base) {
                Ok(f) => {
                    let mut facts = vec![
                        ("ake_gate", f.ake_gate),
                        ("ake_site", f.ake_site),
                        ("ake_stub_va", f.ake_stub_va),
                        ("gatea_gate", f.gatea_cmp),
                        ("gatea_stub_va", f.gatea_stub_va),
                        ("deny_site", f.deny_site),
                        ("deny_stub_va", f.deny_stub_va),
                        ("vid_producer", f.vid_producer),
                    ];
                    // `04 03` UHD mode-gate neutralizer, when wired (classifier prologue
                    // is a known MT1959 shape). Recorded so the audit re-checks its `bl`.
                    if f.uhd_stub_va != 0 {
                        facts.push(("uhd_site", f.uhd_site));
                        facts.push(("uhd_stub_va", f.uhd_stub_va));
                    }
                    // HRL skip (`flag[Feature::Hrl]==STATE_OFF`), when wired. One or
                    // more cert-path detour sites (1 on the NS40/NU50 lineage, 3 on
                    // the BU40N/NS60 desktop lineage) share one stub; each `bl` is
                    // re-checked. Only the first three are named as audit facts (the
                    // observed maximum); all sites are still detoured in the image.
                    if f.hrl_stub_va != 0 {
                        facts.push(("hrl_stub_va", f.hrl_stub_va));
                        for (k, &site) in f.hrl_sites.iter().take(3).enumerate() {
                            facts.push((["hrl_site", "hrl_site2", "hrl_site3"][k], site));
                        }
                    }
                    // `Feature::Bd` BD-refuse detour (REPORT KEY mode-0 class gate),
                    // when wired (gate is a known MT1959 shape). Recorded so the audit
                    // re-checks its `bl`.
                    if f.bd_stub_va != 0 {
                        facts.push(("bd_site", f.bd_site));
                        facts.push(("bd_stub_va", f.bd_stub_va));
                    }
                    // `Feature::Unrestricted` auth-cell state-band widen detour
                    // (post-classification `state>>4 == 0xC` gate), when wired.
                    // Recorded so the audit re-checks its `bl`.
                    if f.auth_cell_stub_va != 0 {
                        facts.push(("auth_cell_site", f.auth_cell_site));
                        facts.push(("auth_cell_stub_va", f.auth_cell_stub_va));
                    }
                    LeverReport::applied(LeverId::RawRead, facts)
                }
                Err(e) => LeverReport::missed(LeverId::RawRead, format!("{e:#}")),
            }
        } else {
            LeverReport::not_applicable(LeverId::RawRead, "no AACS/BD on this model")
        });

        // Downgrade-enable (DE) — family-agnostic: any image with a well-formed
        // MTEK identity page. Idempotent (already-0xDE → AlreadyPresent).
        levers.push(self.lever_de(image, &mut out, chip));

        // Repoint the hijacked record's handler pointer; flags stay OEM.
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

        // If literally nothing took effect, this image is not modifiable.
        if !levers.iter().any(|l| l.outcome.is_effective()) {
            bail!("nothing modifiable on this image (no lever applied)");
        }

        let signed = cmac::resign(&out).map_err(|e| anyhow!("re-sign failed: {e}"))?;

        Ok(ModifyReport {
            engine: "MT1959",
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

    /// Speed lever emission (atomic: writes only on full success). Mirrors the
    /// Speed block of [`Self::build_report`]; the `bl` range is checked before any
    /// write so a miss leaves `out` untouched.
    fn emit_speed(&self, image: &[u8], out: &mut [u8], flag_base: u32) -> Result<(u32, u32)> {
        let (speed_gate, speed_idx_reg) = self.find_speed_gate(image)?;
        let cmp_at = speed_gate as usize + 4;
        let bhi_at = speed_gate as usize + 6;
        let bhi_hw = u16::from_le_bytes([image[bhi_at], image[bhi_at + 1]]);
        if (bhi_hw & 0xFF00) != 0xD800 {
            bail!("speed gate `bhi` not at 0x{bhi_at:x} (got 0x{bhi_hw:04x})");
        }
        let mut disp = (bhi_hw & 0xFF) as i32;
        if disp >= 0x80 {
            disp -= 0x100;
        }
        let ramp_exit = (bhi_at as i32 + 4 + disp * 2) as u32;
        let fallthrough = speed_gate + 8;
        let speed_bytes =
            self.build_speed_stub(flag_base, fallthrough, ramp_exit, speed_idx_reg)?;
        let speed_stub_va = self.free_space(out, speed_bytes.len() + 16)?;
        let bl = thumb::encode_bl(cmp_at, speed_stub_va)
            .ok_or_else(|| anyhow!("Speed detour `bl` out of range"))?;
        thumb::write(out, speed_stub_va as usize, &speed_bytes);
        thumb::write(out, cmp_at, &bl);
        crate::install_guard::verify_branch(
            out,
            cmp_at,
            thumb::BranchKind::Bl,
            speed_stub_va,
            "Speed",
        )?;
        Ok((speed_gate, speed_stub_va))
    }

    /// Region-free lever emission (atomic). Mirrors the Region block of
    /// [`Self::build_report`].
    fn emit_region(&self, image: &[u8], out: &mut [u8], flag_base: u32) -> Result<(u32, u32)> {
        let region_emitter = self.find_region_emitter(image)?;
        let region_site = region_emitter as usize + 6;
        let region_bytes = self.build_region_stub(flag_base)?;
        let region_stub_va = self.free_space(out, region_bytes.len() + 16)?;
        let bl = thumb::encode_bl(region_site, region_stub_va)
            .ok_or_else(|| anyhow!("Region detour `bl` out of range"))?;
        thumb::write(out, region_stub_va as usize, &region_bytes);
        thumb::write(out, region_site, &bl);
        crate::install_guard::verify_branch(
            out,
            region_site,
            thumb::BranchKind::Bl,
            region_stub_va,
            "Region",
        )?;
        Ok((region_emitter, region_stub_va))
    }

    /// Raw-read lever emission (VID gate + AKE accept + deny reset). Validates all
    /// three sub-finds read-only first, then commits the three detours on a
    /// working copy so a mid-commit invariant break leaves `out` clean. Mirrors
    /// the AKE/Gate-A/deny blocks of [`Self::build_report`], same allocation
    /// order (ake → gate-a → deny).
    fn emit_rawread(
        &self,
        image: &[u8],
        out: &mut Vec<u8>,
        flag_base: u32,
    ) -> Result<RawReadFacts> {
        // ---- validate (read-only) ----
        // AKE accept gate — BU40N/desktop (reject-writer detour) or NB-class
        // (shared-`bl` detour). Resolved by `ake_detour`; BU40N matches the
        // original signature first. `install_shape` picks the correct 4-byte
        // encoding at the detour site: `WideB` (Thumb-2 wide `B`) for the
        // BU40N tail-call site so `lr` is preserved through the shared setter,
        // `WideBl` for NB shared-`bl` sites where OEM already had a `bl` and
        // `lr = site+4` is the intended return.
        let (reset_site, ake_bytes, ake_gate, ake_install_shape) =
            self.ake_detour(image, flag_base)?;

        // Producer Gate-A.
        let gatea_anchor = self.find_vid_gate(image)?;
        let gatea_cmp = gatea_anchor + 18;
        let cmp_hw = u16::from_le_bytes([image[gatea_cmp], image[gatea_cmp + 1]]);
        if cmp_hw != 0x2806 {
            bail!("VID gate `cmp r0,#6` not at 0x{gatea_cmp:x} (got 0x{cmp_hw:04x})");
        }
        let gatea_bne = gatea_cmp + 2;
        let bne_hw = u16::from_le_bytes([image[gatea_bne], image[gatea_bne + 1]]);
        if (bne_hw & 0xFF00) != 0xD100 {
            bail!("VID gate `bne` not at 0x{gatea_bne:x} (got 0x{bne_hw:04x})");
        }
        let mut d = (bne_hw & 0xFF) as i32;
        if d >= 0x80 {
            d -= 0x100;
        }
        let gatea_deny = (gatea_bne as i32 + 4 + d * 2) as u32;
        let gatea_authed = (gatea_cmp + 4) as u32;
        let vid_agid_struct = self.find_vid_agid_struct(image)?;
        // Resolved before Gate-A because the bare-read arm now clears the
        // bus-encryption latch with it (see `build_gatea_stub`), as well as the
        // deny path below.
        let aacs_reset = self.find_aacs_session_reset(image)?;
        let gatea_bytes = self.build_gatea_stub(
            flag_base,
            vid_agid_struct,
            gatea_authed,
            gatea_deny,
            aacs_reset,
        )?;
        let deny_site = gatea_deny as usize + 0x10;
        if deny_site + 4 > image.len() {
            bail!("deny sense-setup site 0x{deny_site:x} is past the end of the image");
        }
        let d0 = u16::from_le_bytes([image[deny_site], image[deny_site + 1]]);
        let d1 = u16::from_le_bytes([image[deny_site + 2], image[deny_site + 3]]);
        if d0 != 0x2202 || d1 != 0x216f {
            bail!(
                "deny sense-setup (movs r2,#2; movs r1,#0x6f) not at 0x{deny_site:x} \
                 (got 0x{d0:04x} 0x{d1:04x})"
            );
        }
        let deny_bytes = self.build_deny_reset_stub(aacs_reset)?;

        // VID producer facts (required for the feature; reported).
        let (vid_producer, _vid_out_buf) = self.find_vid_producer(image)?;
        self.find_vid_gate_setter(image)?;

        // ---- commit on a working copy (atomic) ----
        let mut w = out.clone();
        let ake_stub_va = self.free_space(&w, ake_bytes.len() + 16)?;
        thumb::write(&mut w, ake_stub_va as usize, &ake_bytes);
        // The AKE install site is load-bearing: a wrong encoding (a `BL` where
        // the OEM tail-call needs `B.W`, or a mis-computed displacement) ships
        // an image that boots into a detour which either corrupts the outer
        // function's `lr` or jumps to the wrong stub. `install_branch` encodes,
        // writes and decodes back in one step, so the shape used to patch and
        // the shape used to verify cannot drift apart — which is exactly how
        // the 0.8.13 BL-over-tail-call bug reached a flashed drive.
        crate::install_guard::install_branch(
            &mut w,
            reset_site,
            ake_install_shape,
            ake_stub_va,
            "AKE",
        )?;

        let gatea_stub_va = self.free_space(&w, gatea_bytes.len() + 16)?;
        let gatea_bl = thumb::encode_bl(gatea_cmp, gatea_stub_va)
            .ok_or_else(|| anyhow!("Gate-A detour `bl` out of range"))?;
        thumb::write(&mut w, gatea_stub_va as usize, &gatea_bytes);
        thumb::write(&mut w, gatea_cmp, &gatea_bl);
        crate::install_guard::verify_branch(
            &w,
            gatea_cmp,
            thumb::BranchKind::Bl,
            gatea_stub_va,
            "Gate-A",
        )?;

        let deny_stub_va = self.free_space(&w, deny_bytes.len() + 16)?;
        let deny_bl = thumb::encode_bl(deny_site, deny_stub_va)
            .ok_or_else(|| anyhow!("deny-reset detour `bl` out of range"))?;
        thumb::write(&mut w, deny_stub_va as usize, &deny_bytes);
        thumb::write(&mut w, deny_site, &deny_bl);
        crate::install_guard::verify_branch(
            &w,
            deny_site,
            thumb::BranchKind::Bl,
            deny_stub_va,
            "Deny-reset",
        )?;

        // `Feature::Unrestricted` UHD (AACS 2.0) media accept/refuse: detour the REPORT KEY
        // accept gate's UHD class-3 check (via uhd_gate_detour → find_bd_gate) — the
        // UHD sibling of the BD arm on the SAME gate. When `flag[Uhd]==STATE_OFF` the
        // stub forces the OEM deny; unarmed it replays OEM (UHD reads are native).
        // Images on the descriptor-classifier gate shape (no class-3 arm) leave it
        // unwired (0). Committed so the free_space order matches build_report (…→ deny → uhd).
        let (uhd_site, uhd_stub_va) = match self.uhd_gate_detour(image, flag_base) {
            Ok((site, bytes)) => {
                let stub_va = self.free_space(&w, bytes.len() + 16)?;
                let bl = thumb::encode_bl(site, stub_va)
                    .ok_or_else(|| anyhow!("UHD media-gate detour `bl` out of range"))?;
                thumb::write(&mut w, stub_va as usize, &bytes);
                thumb::write(&mut w, site, &bl);
                crate::install_guard::verify_branch(
                    &w,
                    site,
                    thumb::BranchKind::Bl,
                    stub_va,
                    "UHD",
                )?;
                (site as u32, stub_va)
            }
            Err(_) => (0, 0),
        };

        // HRL skip (`flag[Feature::Hrl]==STATE_OFF`): one shared stub, a `bl` to it at
        // each of the three cert-path `cmp r0,#0; bne <6F/00>` sites. Graceful:
        // images whose HRL cert path is not the known shape leave it unwired.
        // Committed last so the free_space order matches build_report (…→ uhd → hrl).
        let (hrl_sites, hrl_stub_va) = match self.hrl_skip_detour(image, flag_base) {
            Ok((sites, _revoke, bytes)) => {
                let stub_va = self.free_space(&w, bytes.len() + 16)?;
                thumb::write(&mut w, stub_va as usize, &bytes);
                for &site in &sites {
                    let bl = thumb::encode_bl(site, stub_va)
                        .ok_or_else(|| anyhow!("HRL-skip detour `bl` out of range"))?;
                    thumb::write(&mut w, site, &bl);
                    crate::install_guard::verify_branch(
                        &w,
                        site,
                        thumb::BranchKind::Bl,
                        stub_va,
                        "HRL-skip",
                    )?;
                }
                (sites.iter().map(|&s| s as u32).collect(), stub_va)
            }
            Err(_) => (Vec::new(), 0),
        };

        // `Feature::Bd` BD (AACS 1.0) capability-refuse: detour the REPORT KEY gate's
        // mode-0 class check (via bd_detour → find_bd_gate). When `flag[Bd]==STATE_OFF`
        // the stub forces the OEM deny path so the drive refuses a BD disc; unarmed it
        // replays OEM (stealth). Graceful: images whose REPORT KEY gate is not the
        // known MT1959 shape leave it unwired (0). Committed last so the free_space
        // order matches build_report (…→ hrl → bd).
        let (bd_site, bd_stub_va) = match self.bd_detour(image, flag_base) {
            Ok((site, bytes)) => {
                let stub_va = self.free_space(&w, bytes.len() + 16)?;
                let bl = thumb::encode_bl(site, stub_va)
                    .ok_or_else(|| anyhow!("BD-refuse detour `bl` out of range"))?;
                thumb::write(&mut w, stub_va as usize, &bytes);
                thumb::write(&mut w, site, &bl);
                crate::install_guard::verify_branch(
                    &w,
                    site,
                    thumb::BranchKind::Bl,
                    stub_va,
                    "BD-refuse",
                )?;
                (site as u32, stub_va)
            }
            Err(_) => (0, 0),
        };

        // `Feature::Unrestricted` auth-cell state-band widen: detour the OEM
        // `cmp (state>>4),#0xC; bne <6F/02>` at `AUTH_CELL_SIG` `anchor+10`
        // (`0x00136826` on BU40N 1.00). When armed the stub returns immediately
        // so the caller enters the accept-arm regardless of nibble value; when
        // OFF the stub replays OEM (`cmp r0,#0xC`; deny on !=). Fixes drives that
        // land the state byte on the `0xEx` band on specific triple-layer UHDs.
        // Graceful: images that don't carry the `ldr r4,[pc,...] = 0x01FF9E04`
        // prefix leave it unwired (0). Committed last so the free_space order
        // matches build_report (…→ bd → auth-cell).
        let (auth_cell_site, auth_cell_stub_va) =
            match self.auth_cell_widen_detour(image, flag_base) {
                Ok((site, bytes)) => {
                    let stub_va = self.free_space(&w, bytes.len() + 16)?;
                    let bl = thumb::encode_bl(site, stub_va)
                        .ok_or_else(|| anyhow!("auth-cell widen detour `bl` out of range"))?;
                    thumb::write(&mut w, stub_va as usize, &bytes);
                    thumb::write(&mut w, site, &bl);
                    crate::install_guard::verify_branch(
                        &w,
                        site,
                        thumb::BranchKind::Bl,
                        stub_va,
                        "auth-cell widen",
                    )?;
                    (site as u32, stub_va)
                }
                Err(_) => (0, 0),
            };

        *out = w;
        Ok(RawReadFacts {
            ake_gate,
            ake_site: reset_site as u32,
            ake_stub_va,
            gatea_cmp: gatea_cmp as u32,
            gatea_stub_va,
            deny_site: deny_site as u32,
            deny_stub_va,
            uhd_site,
            uhd_stub_va,
            hrl_sites,
            hrl_stub_va,
            bd_site,
            bd_stub_va,
            auth_cell_site,
            auth_cell_stub_va,
            vid_producer,
        })
    }
}

#[cfg(test)]
#[path = "mt1959_tests.rs"]
mod tests;
