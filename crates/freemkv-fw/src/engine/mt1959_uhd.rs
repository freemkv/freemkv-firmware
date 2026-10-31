//! Atomic MT1959 UHD conversion, separate from freemkv raw-read controls.
//!
//! OEM UHD is defined here as the six G01-G06 media contracts. Authentication
//! differences G07/G08 are diagnostics only: they neither block media conversion
//! nor generate patches. Existing freemkv AKE/encryption controls are separate.
//! No incomplete media conversion is installed; physical testing is separate.
use anyhow::{ensure, Context, Result};
use mediatek_optical::image::analysis::{LegacyStackDi, SavedLink, UhdArea, UhdAreas, UhdKeyPath};
use sha2::{Digest, Sha256};
use thumb_asm::{Asm, Cond};

/// Stable gap IDs shared with the OEM comparison report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gap {
    /// UHD disc-information admission.
    DiscInformation,
    /// C7 hardware-control bit.
    ControlBit,
    /// C7 hardware-control field.
    ControlField,
    /// C7 forward calculation.
    ForwardCalculation,
    /// C7 reverse calculation and native mode selection.
    ReverseCalculation,
    /// C7 conditional parameter.
    Parameter,
    /// Diagnostic only: REPORT/SEND KEY class-3 routing.
    KeyRouting,
    /// Diagnostic only: extended authentication response/session path.
    ExtendedAuthentication,
}
impl Gap {
    /// ID used by the durable comparison table.
    pub fn id(self) -> &'static str {
        match self {
            Self::DiscInformation => "G01",
            Self::ControlBit => "G02",
            Self::ControlField => "G03",
            Self::ForwardCalculation => "G04",
            Self::ReverseCalculation => "G05",
            Self::Parameter => "G06",
            Self::KeyRouting => "G07",
            Self::ExtendedAuthentication => "G08",
        }
    }
}
/// A prepared detour. Construction changes no image.
#[derive(Debug, Clone)]
pub struct Candidate {
    /// Gap this detour implements.
    pub gap: Gap,
    /// Original image offset, selected from code relationships.
    pub site: usize,
    /// Exact displaced instructions checked again immediately before installation.
    pub original: Vec<u8>,
    /// Position-independent Thumb-1 stub.
    pub bytes: Vec<u8>,
}
/// Source-bound, all-or-nothing conversion plan.
#[derive(Debug)]
pub struct Plan {
    source: [u8; 32],
    /// Required G01-G06 media gaps. Physical validation is separate.
    gaps: Vec<Gap>,
    /// Requirements which prevent committing any conversion edit.
    pending: Vec<String>,
    /// Prepared, independently testable detours; never install them individually.
    candidates: Vec<Candidate>,
    authentication_differences: Vec<Gap>,
    authentication_diagnostic_error: Option<String>,
}
impl Plan {
    /// Required media gaps; callers cannot alter the installation requirements.
    pub fn gaps(&self) -> &[Gap] {
        &self.gaps
    }
    /// Unresolved contracts which block the entire group.
    pub fn pending(&self) -> &[String] {
        &self.pending
    }
    /// Read-only prepared detours for independent verification.
    pub fn candidates(&self) -> &[Candidate] {
        &self.candidates
    }

    /// Internal G07/G08 findings, never requirements or patch candidates.
    pub fn authentication_differences(&self) -> &[Gap] {
        &self.authentication_differences
    }
    /// An unbound authentication diagnostic does not block media conversion.
    pub fn authentication_diagnostic_error(&self) -> Option<&str> {
        self.authentication_diagnostic_error.as_deref()
    }

    /// Select by native signatures, never image/model/hash allowlists.
    pub fn inspect(image: &[u8], flags: u32) -> Result<Self> {
        ensure!(
            (0x01ff0000..0x0200fffd).contains(&flags),
            "boot flags outside RAM"
        );
        let mut plan = Self {
            source: Sha256::digest(image).into(),
            gaps: Vec::new(),
            pending: Vec::new(),
            candidates: Vec::new(),
            authentication_differences: Vec::new(),
            authentication_diagnostic_error: None,
        };
        let areas = UhdAreas::inspect(image);
        let state = areas.state_address().context("UHD media-state binding")?;
        for (role, gap) in [
            (UhdArea::DiscInformation, Gap::DiscInformation),
            (UhdArea::ControlBit, Gap::ControlBit),
            (UhdArea::ControlField, Gap::ControlField),
            (UhdArea::ForwardCalculation, Gap::ForwardCalculation),
            (UhdArea::ReverseCalculation, Gap::ReverseCalculation),
            (UhdArea::ParameterNibble, Gap::Parameter),
        ] {
            let contract = areas
                .area(role)
                .with_context(|| format!("{} native contract", gap.id()))?;
            if contract.selects_c7() != Some(false) {
                continue;
            }
            plan.gaps.push(gap);
            if role == UhdArea::DiscInformation {
                match LegacyStackDi::detect(image) {
                    Ok(di) => {
                        plan.candidates.extend(di_candidates(image, flags, &di)?);
                    }
                    Err(e) => plan.pending.push(format!("G01: native DI contract: {e}")),
                }
                continue;
            }
            if role == UhdArea::ReverseCalculation {
                plan.pending.push(
                    "G05: bind the native reverse-mode flag and both numerical continuations"
                        .into(),
                );
                continue;
            }
            let Some(s) = contract.selection() else {
                plan.pending
                    .push(format!("{}: unsupported selector contract", gap.id()));
                continue;
            };
            SavedLink::detect(image, s.site()).context("UHD selector saved-LR contract")?;
            let c7_accept = if role == UhdArea::ForwardCalculation {
                // C7 belongs to the third native calculation, not the CC case.
                // Bind the second BICS/BNE before deriving that continuation.
                ensure!(
                    image
                        .get(s.accept()..s.accept() + 8)
                        .is_some_and(|v| v[0..6] == [0x08, 0x78, 0xcc, 0x21, 0x81, 0x43]),
                    "G04 second native calculation selector"
                );
                conditional_target(image, s.accept() + 6, Cond::Ne)?
            } else {
                s.accept()
            };
            let reject = follow_taken_bne(image, s.reject())?;
            plan.candidates.push(Candidate {
                gap,
                site: s.site(),
                original: image[s.site()..s.site() + s.span()].to_vec(),
                bytes: selection_stub(state, flags, s.replay(), s.accept(), reject, c7_accept)?,
            });
        }
        // Authentication parity is retained for internal analysis only. Neither
        // a difference nor an unresolved diagnostic authorizes an auth patch
        // or prevents a complete G01-G06 media plan.
        match UhdKeyPath::inspect(image) {
            Ok(keys) => {
                if !keys.report.legacy_selectors.is_empty()
                    || !keys.send.legacy_selectors.is_empty()
                {
                    plan.authentication_differences.push(Gap::KeyRouting);
                }
                if keys.mode.is_none() || keys.certificate.is_none() {
                    plan.authentication_differences
                        .push(Gap::ExtendedAuthentication);
                }
            }
            Err(e) => plan.authentication_diagnostic_error = Some(format!("{e:#}")),
        }
        Ok(plan)
    }
    /// Verify that the output contains the complete group, or no candidate edits
    /// when any required contract remains unresolved.
    pub fn verify(&self, out: &[u8]) -> Result<()> {
        for c in &self.candidates {
            if !self.pending.is_empty() {
                ensure!(
                    out.get(c.site..c.site + c.original.len()) == Some(c.original.as_slice()),
                    "partial {} conversion installed while requirements remain unresolved",
                    c.gap.id()
                );
                continue;
            }
            let branch =
                thumb_asm::isa::decode_at(out, c.site).context("UHD installed branch decode")?;
            ensure!(
                branch.mnemonic == "bl",
                "{} installed detour is not BL",
                c.gap.id()
            );
            let target = branch.branch_target().context("UHD installed target")? as usize;
            ensure!(
                out.get(target..target + c.bytes.len()) == Some(c.bytes.as_slice()),
                "{} installed stub differs",
                c.gap.id()
            );
            for at in (c.site + 4..c.site + c.original.len()).step_by(2) {
                ensure!(
                    out.get(at..at + 2) == Some(0x46c0u16.to_le_bytes().as_slice()),
                    "{} installed padding differs",
                    c.gap.id()
                );
            }
        }
        Ok(())
    }
    /// Commit only a complete plan to a private buffer. On any error the caller's
    /// image remains byte-identical, including when allocation/install fails late.
    pub fn apply(&self, source: &[u8], out: &mut Vec<u8>) -> Result<()> {
        ensure!(
            <[u8; 32]>::from(Sha256::digest(source)) == self.source,
            "UHD source changed"
        );
        ensure!(
            self.pending.is_empty(),
            "UHD conversion unavailable: {}",
            self.pending.join("; ")
        );
        let mut work = out.clone();
        for c in &self.candidates {
            ensure!(
                work.get(c.site..c.site + c.original.len()) == Some(c.original.as_slice()),
                "{} source instructions changed",
                c.gap.id()
            );
            let target = super::mt1959::Mt1959Engine.free_space(&work, c.bytes.len())?;
            let branch = thumb_asm::encode_bl(c.site, target).context("UHD detour range")?;
            work[target as usize..target as usize + c.bytes.len()].copy_from_slice(&c.bytes);
            work[c.site..c.site + 4].copy_from_slice(&branch);
            // Replayed instructions beyond the BL no longer execute.
            for at in (c.site + 4..c.site + c.original.len()).step_by(2) {
                work[at..at + 2].copy_from_slice(&0x46c0u16.to_le_bytes());
            }
            crate::install_guard::verify_branch(
                &work,
                c.site,
                thumb_asm::BranchKind::Bl,
                target,
                c.gap.id(),
            )?;
        }
        self.verify(&work)?;
        *out = work;
        Ok(())
    }
}
fn conditional_target(image: &[u8], at: usize, cond: Cond) -> Result<usize> {
    let i = thumb_asm::isa::decode_at(image, at).context("native branch decode")?;
    ensure!(
        i.mnemonic == "b" && i.cond == Some(cond),
        "native branch condition"
    );
    let target = i.branch_target().context("native direct branch")? as usize;
    ensure!(target + 2 <= image.len(), "native branch outside image");
    Ok(target)
}
fn follow_taken_bne(image: &[u8], mut at: usize) -> Result<usize> {
    let mut seen = Vec::new();
    while thumb_asm::isa::decode_at(image, at)
        .is_some_and(|i| i.mnemonic == "b" && i.cond == Some(Cond::Ne))
    {
        ensure!(!seen.contains(&at), "native branch cycle");
        seen.push(at);
        at = conditional_target(image, at, Cond::Ne)?;
    }
    Ok(at)
}
fn tail(a: &mut Asm, target: usize) {
    a.push(0x108);
    a.ldr_lit(3, target as u32 | 1);
    a.str_sp(3, 4);
    a.pop(0x108);
}
fn selection_stub(
    state: u32,
    flags: u32,
    replay: &[u16],
    accept: usize,
    reject: usize,
    c7: usize,
) -> Result<Vec<u8>> {
    let mut a = Asm::new();
    // CMP overwrites C/V; BICS preserves them. Save C/V through native branches
    // before inspecting the feature byte, without Thumb-2 MRS/MSR.
    let bic =
        thumb_asm::isa::decode_at(&replay[0].to_le_bytes(), 0).is_some_and(|i| i.mnemonic == "bic");
    if bic {
        let v = a.label();
        let c = a.label();
        let cv = a.label();
        a.bvs(v);
        a.bhs(c);
        selection_case(&mut a, state, flags, replay, (accept, reject, c7), Some(0));
        a.bind(c);
        selection_case(
            &mut a,
            state,
            flags,
            replay,
            (accept, reject, c7),
            Some(0xffffffff),
        );
        a.bind(v);
        a.bhs(cv);
        selection_case(
            &mut a,
            state,
            flags,
            replay,
            (accept, reject, c7),
            Some(0x40000000),
        );
        a.bind(cv);
        selection_case(
            &mut a,
            state,
            flags,
            replay,
            (accept, reject, c7),
            Some(0x80000000),
        );
    } else {
        selection_case(&mut a, state, flags, replay, (accept, reject, c7), None);
    }
    finish_t1(a)
}
fn selection_case(
    a: &mut Asm,
    state: u32,
    flags: u32,
    replay: &[u16],
    dest: (usize, usize, usize),
    cv: Option<u32>,
) {
    let original = a.label();
    let no = a.label();
    a.push(8);
    a.ldr_lit(3, flags + crate::abi::Feature::Unrestricted as u32);
    a.ldrb_imm(3, 3, 0);
    a.cmp_imm(3, crate::abi::STATE_ON);
    a.bne(original);
    a.ldr_lit(3, state);
    a.ldrb_imm(3, 3, 0);
    a.cmp_imm(3, 0xc7);
    a.bne(original);
    restore_cv(a, cv);
    a.pop(8);
    a.replay(
        &replay
            .iter()
            .flat_map(|h| h.to_le_bytes())
            .collect::<Vec<_>>(),
    );
    tail(a, dest.2);
    a.bind(original);
    restore_cv(a, cv);
    a.pop(8);
    a.replay(
        &replay
            .iter()
            .flat_map(|h| h.to_le_bytes())
            .collect::<Vec<_>>(),
    );
    a.bne(no);
    tail(a, dest.0);
    a.bind(no);
    tail(a, dest.1);
}
fn restore_cv(a: &mut Asm, cv: Option<u32>) {
    if let Some(seed) = cv {
        a.ldr_lit(3, seed);
        a.adds_reg(3, 3, 3);
    }
}
fn finish_t1(mut a: Asm) -> Result<Vec<u8>> {
    let end = a.pos();
    let bytes = a.finish()?;
    // Only 16-bit Thumb instructions are permitted in these stubs. Pools start
    // after `end`; never decode data as instructions. This rejects Thumb-2 too.
    for at in (0..end).step_by(2) {
        let h = u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap());
        let ordinary = h & 0xf800 < 0xe800;
        let stack = h & 0xf000 != 0xb000 || h & 0xff00 == 0xb000 || h & 0xf600 == 0xb400;
        let conditional = h & 0xf000 != 0xd000 || h & 0xff00 < 0xde00;
        ensure!(
            ordinary && stack && conditional,
            "non ARMv5 Thumb-1 instruction at stub offset {at:#x}"
        );
    }
    Ok(bytes)
}

/// Two coordinated G01 detours retain native format handling, its flag store,
/// and every instruction following the native layer-state store.
fn di_candidates(image: &[u8], flags: u32, di: &LegacyStackDi) -> Result<Vec<Candidate>> {
    let mut result = Vec::new();
    for layers in [false, true] {
        let mut a = Asm::new();
        let v = a.label();
        let inspect = a.label();
        let original = a.label();
        let vzero = a.label();
        let replay = a.label();
        // Preserve V because the displaced shifts preserve it. Every scratch
        // register is saved; the bound caller already owns a saved return link.
        a.push(0x2f);
        a.bvs(v);
        a.movs_imm(5, 0);
        a.b(inspect);
        a.bind(v);
        a.movs_imm(5, 1);
        a.bind(inspect);
        a.mov_reg(3, 13);
        a.adds_imm(3, 20 + di.stack_block);
        a.ldr_lit(0, flags + crate::abi::Feature::Unrestricted as u32);
        a.ldrb_imm(0, 0, 0);
        a.cmp_imm(0, crate::abi::STATE_ON);
        a.bne(original);
        a.ldrb_imm(0, 3, u16::from(di.identifier_offset));
        a.cmp_imm(0, b'U');
        a.bne(original);
        a.ldrb_imm(0, 3, u16::from(di.identifier_offset) + 3);
        a.cmp_imm(0, 5);
        a.bne(original);
        a.ldrb_imm(0, 3, u16::from(di.identifier_offset) + 1);
        a.lsls_imm(0, 0, 26);
        a.lsrs_imm(0, 0, 30);
        let attr = a.label();
        a.cmp_imm(0, 0);
        a.beq(attr);
        a.cmp_imm(0, 3);
        a.bne(original);
        a.bind(attr);
        a.ldrb_imm(0, 3, u16::from(di.identifier_offset) + 2);
        a.lsrs_imm(0, 0, 4);
        let valid = a.label();
        a.cmp_imm(0, 2);
        a.beq(valid);
        a.cmp_imm(0, 3);
        a.bne(original);
        a.bind(valid);
        a.pop(0x2f);
        if layers {
            // Native normalization uses R1=F3 and R3=the original DI block.
            a.mov_reg(3, 13);
            a.adds_imm(3, di.stack_block);
            a.ldrb_imm(0, 3, u16::from(di.identifier_offset) + 2);
            a.lsrs_imm(0, 0, 4);
            a.adds_imm(0, 0xc5);
            a.movs_imm(1, 0xf3);
            if di.state_register.is_none() {
                let op = u16::from_le_bytes(
                    image[di.layer_store..di.layer_store + 2]
                        .try_into()
                        .unwrap(),
                );
                a.ldr_lit((op >> 3) & 7, di.state);
            }
            tail(&mut a, di.layer_store);
        } else {
            tail(&mut a, di.format);
        }
        a.bind(original);
        a.cmp_imm(5, 0);
        a.beq(vzero);
        a.ldr_lit(0, 0x40000000);
        a.adds_reg(0, 0, 0);
        a.b(replay);
        a.bind(vzero);
        a.movs_imm(0, 0);
        a.adds_reg(0, 0, 0);
        a.bind(replay);
        a.pop(0x2f);
        let site = if layers { di.layers } else { di.prevalidation };
        let width = 8;
        // Both regions contain only position-independent operations; the
        // source contract checks the original SP-relative DI block explicitly.
        a.replay(&image[site..site + width]);
        tail(&mut a, site + width);
        result.push(Candidate {
            gap: Gap::DiscInformation,
            site,
            original: image[site..site + width].to_vec(),
            bytes: finish_t1(a)?,
        });
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    const FLAGS: u32 = super::super::core::FLAG_TABLE_BASE;
    #[test]
    fn thumb1_guard_rejects_narrow_thumb2_and_wide_prefixes() {
        for halfword in [0xb100, 0xbf08, 0xba00, 0xb200, 0xe800, 0xf000] {
            let mut a = Asm::new();
            a.raw16(halfword);
            assert!(finish_t1(a).is_err(), "{halfword:#x}");
        }
        let mut a = Asm::new();
        a.bx(14);
        assert!(finish_t1(a).is_ok());
    }
    #[test]
    fn authentication_differences_are_diagnostics_without_patches_or_blockers() {
        let image = include_bytes!("../../tests/fixtures/WH16NS58_OEM_1.V9.bin");
        let plan = Plan::inspect(image, FLAGS).unwrap();
        assert_eq!(
            plan.authentication_differences(),
            &[Gap::KeyRouting, Gap::ExtendedAuthentication]
        );
        assert!(plan.authentication_diagnostic_error().is_none());
        assert!(plan.gaps().is_empty());
        assert!(plan.pending().is_empty());
        assert!(plan.candidates().is_empty());
        let mut out = image.to_vec();
        plan.apply(image, &mut out).unwrap();
        plan.verify(&out).unwrap();
        assert_eq!(out, image);
    }
    #[test]
    fn native_reviewed_paths_require_no_conversion_edits() {
        let image = include_bytes!("../../tests/fixtures/BU40N_OEM_1.05.bin");
        let plan = Plan::inspect(image, FLAGS).unwrap();
        assert!(plan.gaps.is_empty());
        assert!(plan.pending.is_empty());
        assert!(plan.candidates.is_empty());
        let mut out = image.to_vec();
        plan.apply(image, &mut out).unwrap();
        assert_eq!(out, image);
        let mut changed = image.to_vec();
        changed[0] ^= 1;
        assert!(plan.apply(&changed, &mut out).is_err());
        assert_eq!(out, image);
    }
    #[test]
    fn audit_rejects_partial_conversion_and_late_install_failure_is_atomic() {
        let image = include_bytes!("../../tests/fixtures/WH16NS58_OEM_1.V9.bin");
        let mut plan = Plan::inspect(image, FLAGS).unwrap();
        // Private synthetic media candidates exercise rollback after the first
        // real allocation. No authentication candidate is ever generated.
        for site in [0x80000, 0x80004] {
            plan.candidates.push(Candidate {
                gap: Gap::ControlBit,
                site,
                original: image[site..site + 4].to_vec(),
                bytes: vec![0x70, 0x47],
            });
        }
        plan.pending
            .push("G05: unresolved test media contract".into());
        plan.verify(image).unwrap();
        let mut changed = image.to_vec();
        changed[plan.candidates[0].site] ^= 1;
        assert!(plan.verify(&changed).is_err());
        let mut out = image.to_vec();
        assert!(plan.apply(image, &mut out).is_err());
        assert_eq!(out, image);
        plan.pending.clear();
        plan.candidates[1].original[0] ^= 1;
        assert!(plan.apply(image, &mut out).is_err());
        assert_eq!(out, image);
    }

    #[test]
    fn unresolved_authentication_diagnostics_do_not_block_native_media() {
        let image = include_bytes!("../../tests/fixtures/WH16NS58_OEM_1.V9.bin");
        let path = UhdKeyPath::inspect(image).unwrap();
        for site in [
            path.report.legacy_selectors[0],
            path.report.legacy_selectors[1],
            path.send.legacy_selectors[0],
        ] {
            let mut changed = image.to_vec();
            changed[site] ^= 1;
            let plan = Plan::inspect(&changed, FLAGS).unwrap();
            assert!(
                plan.authentication_diagnostic_error().is_some(),
                "{site:#x}"
            );
            assert!(plan.pending().is_empty());
            assert!(plan.candidates().is_empty());
            let mut out = changed.clone();
            plan.apply(&changed, &mut out).unwrap();
            assert_eq!(out, changed);
        }
    }
}
