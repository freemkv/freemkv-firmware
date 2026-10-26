//! Component-based UHD conversion planning and research hook emission.
//!
//! Locators live in mediatek-optical. This module owns policy and Thumb emission.
//! A collection of matched regions is not a complete conversion: no ordinary
//! Modify output installs these hooks until the remaining contracts are proven.
use anyhow::{ensure, Context, Result};
use mediatek_optical::image::analysis::{UhdArea, UhdAreas};
use sha2::{Digest, Sha256};
use thumb_asm::Asm;

/// What one independently selected component requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UhdAction {
    /// This region already has native U/C7 handling; do not add another hook.
    Native,
    /// Add identifier recognition and preserve the newly assigned layer state.
    AddRecognition,
    /// Extend a native selector without changing its parameters or calculations.
    ExtendSelection,
    /// Retain the image's hardware/media policy unchanged.
    PreserveHardware,
}
/// One source-bound plan. Construction cannot alter the input image.
#[derive(Debug, Clone)]
pub struct UhdConversionPlan {
    areas: UhdAreas,
    state: u32,
    source_hash: [u8; 32],
}
impl UhdConversionPlan {
    /// Select each implementation separately and require their common state cell.
    pub fn inspect(image: &[u8]) -> Result<Self> {
        let areas = UhdAreas::inspect(image);
        let state = areas
            .state_address()
            .context("UHD component state bindings")?;
        areas
            .area(UhdArea::DiscInformation)
            .context("UHD DI recognition contract")?;
        Ok(Self {
            areas,
            state,
            source_hash: Sha256::digest(image).into(),
        })
    }
    /// Common state byte derived from the image's independent consumers.
    pub fn state_address(&self) -> u32 {
        self.state
    }
    /// Component evidence used to select emission; hardware defaults stay read-only.
    pub fn areas(&self) -> &UhdAreas {
        &self.areas
    }
    /// Avoid patching native implementations merely because another component is old.
    pub fn action(&self, area: UhdArea) -> Result<UhdAction> {
        let contract = self.areas.area(area)?;
        Ok(match contract.selects_c7() {
            None => UhdAction::PreserveHardware,
            Some(true) => UhdAction::Native,
            Some(false) if area == UhdArea::DiscInformation => UhdAction::AddRecognition,
            Some(false) => UhdAction::ExtendSelection,
        })
    }
    /// Remaining semantic requirements. All seven locator hits alone must never
    /// silently promote an unproven classic conversion into public capability.
    pub fn remaining_contracts(&self) -> Vec<&'static str> {
        if UhdArea::ALL.iter().all(|&a| {
            matches!(
                self.action(a),
                Ok(UhdAction::Native | UhdAction::PreserveHardware)
            )
        }) {
            return vec![];
        }
        vec!["remaining indirect and structure consumers"]
    }
    /// Refuse incomplete conversion before an output buffer can be modified.
    pub fn require_complete_conversion(&self) -> Result<()> {
        let pending = self.remaining_contracts();
        ensure!(
            pending.is_empty(),
            "UHD conversion contracts pending: {}",
            pending.join("; ")
        );
        Ok(())
    }
    /// Emit the independently validated classic selection stubs for CPU research.
    /// These bytes are not installed by ordinary Modify and grant no capability.
    pub fn routing_candidates(&self, image: &[u8], flags: u32) -> Result<Vec<UhdRoutingCandidate>> {
        ensure!(
            <[u8; 32]>::from(Sha256::digest(image)) == self.source_hash,
            "source state changed"
        );
        let mut candidates = Vec::new();
        for area in UhdArea::ALL {
            if self.action(area)? != UhdAction::ExtendSelection {
                continue;
            }
            let contract = self.areas.area(area)?;
            let Some(selection) = contract.selection() else {
                continue;
            };
            let site = selection.site();
            let width = selection.span();
            let replay = selection.replay();
            let accept = selection.accept();
            let reject = selection.reject();
            let bytes = emit_c7_selection(self.state, flags, replay, accept, reject)?;
            candidates.push(UhdRoutingCandidate {
                area,
                region_start: contract.site(),
                calculation_end: contract.coefficient_continuation().map(|pc| pc + 2),
                site,
                original: image[site..site + width].to_vec(),
                accept,
                reject,
                bytes,
                caller: mediatek_optical::image::analysis::SavedLink::detect(image, site)?,
            });
        }
        Ok(candidates)
    }
    /// Emit separately proven native auxiliary selectors. Recognition alone
    /// does not close the remaining downstream-consumer audit or enable UHD.
    pub fn auxiliary_candidates(
        &self,
        image: &[u8],
        flags: u32,
    ) -> Result<Vec<UhdRoutingCandidate<mediatek_optical::image::analysis::ClassicConsumerKind>>>
    {
        ensure!(
            <[u8; 32]>::from(Sha256::digest(image)) == self.source_hash,
            "source state changed"
        );
        mediatek_optical::image::analysis::ClassicConsumer::inspect(image, self.state)?
            .into_iter()
            .map(|contract| {
                let selection = contract.selection;
                let site = selection.site();
                Ok(UhdRoutingCandidate {
                    area: contract.kind,
                    region_start: contract.region,
                    calculation_end: None,
                    site,
                    original: image[site..site + selection.span()].to_vec(),
                    accept: selection.accept(),
                    reject: selection.reject(),
                    bytes: emit_c7_selection_relocated(
                        self.state,
                        flags,
                        selection.replay(),
                        selection.accept(),
                        selection.reject(),
                        contract.relocated_load,
                    )?,
                    caller: contract.caller,
                })
            })
            .collect()
    }
    /// Emit both selectors only after matching the complete native position
    /// routine, including its polling loops, table loads and balanced return.
    pub fn position_candidates(
        &self,
        image: &[u8],
        flags: u32,
    ) -> Result<Vec<UhdRoutingCandidate<PositionRole>>> {
        ensure!(
            <[u8; 32]>::from(Sha256::digest(image)) == self.source_hash,
            "source state changed"
        );
        let contract =
            mediatek_optical::image::analysis::ClassicPosition::detect(image, self.state)?;
        [
            (
                PositionRole::PositionInput,
                &contract.input,
                contract.entry + 2,
                0,
            ),
            (
                PositionRole::PositionOutput,
                &contract.output,
                contract.output.site() - 2,
                1,
            ),
        ]
        .into_iter()
        .map(|(area, selection, region_start, index)| {
            let site = selection.site();
            Ok(UhdRoutingCandidate {
                area,
                region_start,
                calculation_end: None,
                site,
                original: image[site..site + selection.span()].to_vec(),
                accept: selection.accept(),
                reject: selection.reject(),
                bytes: emit_c7_selection(
                    self.state,
                    flags,
                    selection.replay(),
                    selection.accept(),
                    selection.reject(),
                )?,
                caller: contract.callers[index].clone(),
            })
        })
        .collect()
    }
    /// Select this image's own C8 calibration at the native startup lookup.
    /// State-independent getters already share coefficients and need no hook.
    pub fn calibration_candidate(
        &self,
        image: &[u8],
        flags: u32,
    ) -> Result<Option<UhdCalibrationCandidate>> {
        ensure!(
            <[u8; 32]>::from(Sha256::digest(image)) == self.source_hash,
            "source state changed"
        );
        let contract =
            mediatek_optical::image::analysis::ClassicCalibration::detect(image, self.state)?;
        let Some(coefficients) = contract.c7_coefficients else {
            return Ok(None);
        };
        let mut a = Asm::new();
        let oem = a.label();
        a.push(0x0a);
        a.ldr_lit(3, flag_address(flags)?);
        a.ldrb_imm(3, 3, 0);
        a.cmp_imm(3, crate::abi::STATE_ON);
        a.bne(oem);
        a.ldr_lit(3, self.state);
        a.ldrb_imm(3, 3, 0);
        a.cmp_imm(3, 0xc7);
        a.bne(oem);
        a.pop(0x0a);
        a.ldr_lit(0, contract.original_base);
        a.raw16(0x3058);
        a.ldr_lit(0, coefficients);
        a.raw16(0x5b80);
        tail(&mut a, contract.site + 6);
        a.bind(oem);
        a.pop(0x0a);
        a.ldr_lit(0, contract.original_base);
        a.raw16(0x3058);
        a.raw16(0x5b80);
        tail(&mut a, contract.site + 6);
        let original = image[contract.site..contract.site + 6].to_vec();
        Ok(Some(UhdCalibrationCandidate {
            contract,
            original,
            bytes: a.finish()?,
        }))
    }
    /// Preserve a state-independent lookup, or extend the positively bound
    /// native media-table gate. Never copy another drive's calibration values.
    pub fn parameter_candidate(&self, image: &[u8], flags: u32) -> Result<UhdParameterCandidate> {
        ensure!(
            <[u8; 32]>::from(Sha256::digest(image)) == self.source_hash,
            "source state changed"
        );
        let contract =
            mediatek_optical::image::analysis::ClassicParameter::detect(image, self.state)?;
        let hook = if let Some(selection) = &contract.selection {
            let site = selection.site();
            Some(UhdRoutingCandidate {
                area: contract.variant,
                region_start: contract.entry + 2,
                calculation_end: None,
                site,
                original: image[site..site + selection.span()].to_vec(),
                accept: selection.accept(),
                reject: selection.reject(),
                bytes: emit_c7_selection(
                    self.state,
                    flags,
                    selection.replay(),
                    selection.accept(),
                    selection.reject(),
                )?,
                caller: contract.caller.clone(),
            })
        } else {
            None
        };
        Ok(UhdParameterCandidate { contract, hook })
    }
}
/// Bound startup calibration load and its emitted replacement.
#[derive(Debug, Clone)]
pub struct UhdCalibrationCandidate {
    /// Native table/getter and saved-frame contract.
    pub contract: mediatek_optical::image::analysis::ClassicCalibration,
    /// Source instructions displaced by the detour.
    pub original: Vec<u8>,
    /// Relocatable Thumb replacement.
    pub bytes: Vec<u8>,
}
/// Paired native position-scaling roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PositionRole {
    /// Quarter-scale the native input.
    PositionInput,
    /// Double the native result before its final shift.
    PositionOutput,
}
/// Parameter lookup evidence and the optional source-bound detour.
#[derive(Debug, Clone)]
pub struct UhdParameterCandidate {
    /// Native getter, rate list, coefficient table and setter relationship.
    pub contract: mediatek_optical::image::analysis::ClassicParameter,
    /// Absent when the complete native getter is state-independent.
    pub hook:
        Option<UhdRoutingCandidate<mediatek_optical::image::analysis::ClassicParameterVariant>>,
}
/// A candidate detour with exact replay bytes and both native continuations.
/// Includes the native saved-link contract needed before installing a branch.
#[derive(Debug, Clone)]
pub struct UhdRoutingCandidate<R = UhdArea> {
    /// Independent area that requested this extension.
    pub area: R,
    /// First native instruction used to execute the selector's inputs.
    pub region_start: usize,
    /// Native arithmetic result join, when this is a calculation selector.
    pub calculation_end: Option<usize>,
    /// Original operation and branch pair.
    pub site: usize,
    /// Original source bytes, retained for stale-source/overlap checks.
    pub original: Vec<u8>,
    /// Native C8-class continuation.
    pub accept: usize,
    /// Native other-state continuation.
    pub reject: usize,
    /// Position-independent Thumb bytes for controlled CPU testing.
    pub bytes: Vec<u8>,
    /// Native stack/LR lifetime proof for installing a Thumb BL at this site.
    pub caller: mediatek_optical::image::analysis::SavedLink,
}
fn tail(a: &mut Asm, target: usize) {
    a.push(0x0108); // r3,lr; preserve r3 while replacing only the stacked return
    a.ldr_lit(3, target as u32 | 1);
    a.raw16(0x9301); // str r3,[sp,4]
    a.pop(0x0108); // r3,pc; LR itself is unchanged
}
fn flag_address(flags: u32) -> Result<u32> {
    ensure!(
        (0x01ff0000..0x02010000).contains(&flags),
        "invalid boot flags address"
    );
    let address = flags
        .checked_add(crate::abi::Feature::Unrestricted as u32)
        .context("boot flags overflow")?;
    ensure!(
        (0x01ff0000..0x02010000).contains(&address),
        "boot flag slot outside RAM"
    );
    Ok(address)
}
fn selection_case(
    a: &mut Asm,
    state: u32,
    flag: u32,
    replay: &[u16],
    continuations: (usize, usize),
    cv: Option<u32>,
    relocated_load: Option<(u8, u32)>,
) {
    let (accept, reject) = continuations;
    let oem = a.label();
    let no = a.label();
    a.push(8);
    a.ldr_lit(3, flag);
    a.ldrb_imm(3, 3, 0);
    a.cmp_imm(3, crate::abi::STATE_ON);
    a.bne(oem);
    a.ldr_lit(3, state);
    a.ldrb_imm(3, 3, 0);
    a.cmp_imm(3, 0xc7);
    a.bne(oem);
    restore_cv(a, cv);
    a.pop(8);
    for &op in replay {
        a.raw16(op);
    }
    if let Some((register, value)) = relocated_load {
        a.ldr_lit(u16::from(register), value);
    }
    tail(a, accept);
    a.bind(oem);
    restore_cv(a, cv);
    a.pop(8);
    for &op in replay {
        a.raw16(op);
    }
    if let Some((register, value)) = relocated_load {
        a.ldr_lit(u16::from(register), value);
    }
    a.bne(no);
    tail(a, accept);
    a.bind(no);
    tail(a, reject);
}
fn restore_cv(a: &mut Asm, seed: Option<u32>) {
    if let Some(seed) = seed {
        // ADDS r3,r3,r3 establishes the saved C/V combination; native BICS
        // then establishes N/Z. No Thumb-2 MRS or ARM-mode helper is needed.
        a.ldr_lit(3, seed);
        a.raw16(0x18db);
    }
}
fn emit_c7_selection(
    state: u32,
    flags: u32,
    replay: &[u16],
    accept: usize,
    reject: usize,
) -> Result<Vec<u8>> {
    emit_c7_selection_relocated(state, flags, replay, accept, reject, None)
}
fn emit_c7_selection_relocated(
    state: u32,
    flags: u32,
    replay: &[u16],
    accept: usize,
    reject: usize,
    relocated_load: Option<(u8, u32)>,
) -> Result<Vec<u8>> {
    let mut a = Asm::new();
    let flag = flag_address(flags)?;
    if replay.first().is_some_and(|h| h & 0xffc0 == 0x4380) {
        // BICS preserves incoming C/V. Capture both through branches before any
        // new flag-setting instruction, so OEM behavior also preserves flags.
        let v1 = a.label();
        let c1v0 = a.label();
        let c1v1 = a.label();
        a.bvs(v1);
        a.bhs(c1v0);
        selection_case(
            &mut a,
            state,
            flag,
            replay,
            (accept, reject),
            Some(0),
            relocated_load,
        );
        a.bind(c1v0);
        selection_case(
            &mut a,
            state,
            flag,
            replay,
            (accept, reject),
            Some(0xffff_ffff),
            relocated_load,
        );
        a.bind(v1);
        a.bhs(c1v1);
        selection_case(
            &mut a,
            state,
            flag,
            replay,
            (accept, reject),
            Some(0x4000_0000),
            relocated_load,
        );
        a.bind(c1v1);
        selection_case(
            &mut a,
            state,
            flag,
            replay,
            (accept, reject),
            Some(0x8000_0000),
            relocated_load,
        );
    } else {
        selection_case(
            &mut a,
            state,
            flag,
            replay,
            (accept, reject),
            None,
            relocated_load,
        );
    }
    a.finish().map_err(Into::into)
}
/// Pure DI extension helper: r0=identifier, r1=format, r2=layer field; r0 returns
/// C7/C8 or zero (defer to OEM). r1-r3 and LR survive. Only STATE_ON adds behavior.
pub fn emit_di_recognition(flags: u32) -> Result<Vec<u8>> {
    let mut a = Asm::new();
    let no = a.label();
    let two = a.label();
    let done = a.label();
    a.push(0x0e);
    a.ldr_lit(3, flag_address(flags)?);
    a.ldrb_imm(3, 3, 0);
    a.cmp_imm(3, crate::abi::STATE_ON);
    a.bne(no);
    a.cmp_imm(0, b'U');
    a.bne(no);
    a.cmp_imm(1, 5);
    a.bne(no);
    a.cmp_imm(2, 2);
    a.beq(two);
    a.cmp_imm(2, 3);
    a.bne(no);
    a.movs_imm(0, 0xc8);
    a.b(done);
    a.bind(two);
    a.movs_imm(0, 0xc7);
    a.b(done);
    a.bind(no);
    a.movs_imm(0, 0);
    a.bind(done);
    a.pop(0x0e);
    a.bx(14);
    a.finish().map_err(Into::into)
}
/// New layer normalization helper: r0=state, r1=layer field, returns state in r0.
/// Preserves C7 only for layer 2 with STATE_ON. All other inputs use native math.
pub fn emit_di_layers(flags: u32) -> Result<Vec<u8>> {
    let mut a = Asm::new();
    let oem = a.label();
    let done = a.label();
    a.push(0x0e);
    a.ldr_lit(3, flag_address(flags)?);
    a.ldrb_imm(3, 3, 0);
    a.cmp_imm(3, crate::abi::STATE_ON);
    a.bne(oem);
    a.cmp_imm(0, 0xc7);
    a.bne(oem);
    a.cmp_imm(1, 2);
    a.beq(done);
    a.bind(oem);
    a.cmp_imm(1, 1);
    a.blo(done);
    a.cmp_imm(1, 4);
    a.bhi(done);
    a.movs_imm(2, 0xf3);
    a.raw16(0x4010);
    a.subs_imm(1, 1);
    a.lsls_imm(1, 1, 2);
    a.orrs(0, 1);
    a.bind(done);
    a.pop(0x0e);
    a.bx(14);
    a.finish().map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    const CLASSIC: &[u8] = include_bytes!("../../tests/fixtures/BE14NU40_MT1939_JB7_1.01.bin");
    #[test]
    fn di_entry_candidate_binds_native_continuations_without_mutating_source() {
        let before = CLASSIC.to_vec();
        let candidate = di_prevalidation_candidate(CLASSIC, 0x0200f000).unwrap();
        assert_eq!(candidate.original.len(), 8);
        assert_eq!(
            candidate.contract.replay_continuation,
            candidate.contract.prevalidation + 8
        );
        assert!(!candidate.bytes.is_empty());
        assert!(di_prevalidation_candidate(CLASSIC, u32::MAX).is_err());
        assert_eq!(CLASSIC, before);
    }
    #[test]
    fn component_plan_preserves_hardware_and_refuses_incomplete_conversion() {
        let plan = UhdConversionPlan::inspect(CLASSIC).unwrap();
        assert_eq!(
            plan.action(UhdArea::HardwareDefaults).unwrap(),
            UhdAction::PreserveHardware
        );
        assert_eq!(
            plan.action(UhdArea::DiscInformation).unwrap(),
            UhdAction::AddRecognition
        );
        assert!(!plan.remaining_contracts().is_empty());
        assert!(plan.require_complete_conversion().is_err());
        let candidates = plan.routing_candidates(CLASSIC, 0x0200f000).unwrap();
        assert_eq!(candidates.len(), 5);
        for candidate in candidates {
            assert_ne!(candidate.area, UhdArea::HardwareDefaults);
            assert_eq!(
                &CLASSIC[candidate.site..candidate.site + candidate.original.len()],
                candidate.original
            );
        }
        let auxiliary = plan.auxiliary_candidates(CLASSIC, 0x0200f000).unwrap();
        assert_eq!(auxiliary.len(), 9);
        for candidate in auxiliary {
            assert_eq!(
                &CLASSIC[candidate.site..candidate.site + candidate.original.len()],
                candidate.original
            );
            assert!(candidate.caller.entry < candidate.site);
            assert!(candidate.calculation_end.is_none());
        }
        let mut changed = CLASSIC.to_vec();
        changed[0x1000] ^= 1;
        assert!(plan.routing_candidates(&changed, 0x0200f000).is_err());
    }
    #[test]
    fn component_plans_match_all_corpus_roles_without_promoting_classic() {
        let Ok(path) = std::env::var("FREEMKV_UHD_PLAN_CORPUS") else {
            return;
        };
        let hoard = std::path::PathBuf::from(std::env::var("FREEMKV_UHD_PLAN_HOARD").unwrap());
        let inventory: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        for row in inventory["images"].as_array().unwrap() {
            let hint = std::path::Path::new(row["path"].as_str().unwrap());
            let tail: std::path::PathBuf = hint.iter().skip(1).collect();
            let source = std::iter::once(hoard.join(hint))
                .chain(["oem", "dump", "mk", "omni"].map(|b| hoard.join(b).join(&tail)))
                .find(|p| p.is_file())
                .expect("held corpus image");
            let data = std::fs::read(source).unwrap();
            assert_eq!(
                format!("{:x}", Sha256::digest(&data)),
                row["sha256"].as_str().unwrap()
            );
            let plan = UhdConversionPlan::inspect(&data).unwrap();
            for (name, area) in [
                ("di_identifier_recognition", UhdArea::DiscInformation),
                ("hardware_control_bit", UhdArea::ControlBit),
                ("hardware_control_field", UhdArea::ControlField),
                ("forward_calculation", UhdArea::ForwardCalculation),
                ("reverse_calculation", UhdArea::ReverseCalculation),
                ("hardware_parameter_nibble", UhdArea::ParameterNibble),
                (
                    "speed_defaults_hardware_sensitive",
                    UhdArea::HardwareDefaults,
                ),
            ] {
                let actual = plan.areas().area(area).unwrap();
                let expected = &row["areas"][name]["matches"][0];
                assert_eq!(
                    actual.site(),
                    expected["address"].as_u64().unwrap() as usize
                );
                assert_eq!(
                    actual.variant(),
                    expected["reference_style"].as_str().unwrap()
                );
            }
            if row["identity"]["chip"] == "MT1939" {
                assert!(plan.require_complete_conversion().is_err());
                assert_eq!(plan.routing_candidates(&data, 0x0200f000).unwrap().len(), 5);
                assert_eq!(
                    plan.auxiliary_candidates(&data, 0x0200f000).unwrap().len(),
                    7
                );
            }
        }
    }
    #[test]
    fn emission_rejects_invalid_flag_locations() {
        for value in [0, 0x0200ffff, 0x04200000, u32::MAX] {
            assert!(emit_di_recognition(value).is_err());
            assert!(emit_di_layers(value).is_err());
        }
    }
}

/// Candidate DI entry detour; kept separate from ordinary Modify installation.
#[derive(Debug, Clone)]
pub struct UhdDiCandidate {
    /// Source-derived parser/frame/continuation evidence.
    pub contract: mediatek_optical::image::analysis::ClassicDi,
    /// Exact eight bytes displaced by the entry detour.
    pub original: Vec<u8>,
    /// Position-independent Thumb code.
    pub bytes: Vec<u8>,
    /// Native frame/lifetime evidence for the entry detour.
    pub caller: mediatek_optical::image::analysis::SavedLink,
}
/// Recognize U/5 with two or three layers, then reuse the native format and
/// layer handlers. OEM/Off/unknown flags replay native prevalidation exactly.
pub fn di_prevalidation_candidate(image: &[u8], flags: u32) -> Result<UhdDiCandidate> {
    let contract = mediatek_optical::image::analysis::ClassicDi::detect(image)?;
    let caller =
        mediatek_optical::image::analysis::SavedLink::detect(image, contract.prevalidation)?;
    ensure!(
        caller.entry == contract.entry && caller.stack_bytes == 40,
        "DI caller frame disagrees"
    );
    let original = image[contract.prevalidation..contract.replay_continuation].to_vec();
    let mut a = Asm::new();
    let v1 = a.label();
    let inspect = a.label();
    let oem = a.label();
    let v0 = a.label();
    let replay = a.label();
    let attribute_ok = a.label();
    let two = a.label();
    let assign = a.label();
    a.raw16(0x466b); // r3 = native caller SP, before any local push.
    a.push(0x12f); // r0-r3,r5,lr; save every scratch and the incoming V flag.
    a.bvs(v1);
    a.movs_imm(5, 0);
    a.b(inspect);
    a.bind(v1);
    a.movs_imm(5, 1);
    a.bind(inspect);
    a.ldr_lit(0, flag_address(flags)?);
    a.ldrb_imm(0, 0, 0);
    a.cmp_imm(0, crate::abi::STATE_ON);
    a.bne(oem);
    a.ldr_lit(0, contract.state);
    a.cmp_reg(4, 0);
    a.bne(oem);
    for (offset, expected) in [(12, b'B'), (13, b'D'), (16, b'U'), (19, 5)] {
        a.ldrb_imm(0, 3, offset);
        a.cmp_imm(0, expected);
        a.bne(oem);
    }
    a.ldrb_imm(0, 3, 17);
    a.lsls_imm(0, 0, 26);
    a.lsrs_imm(0, 0, 30);
    a.cmp_imm(0, 0);
    a.beq(attribute_ok);
    a.cmp_imm(0, 3);
    a.bne(oem);
    a.bind(attribute_ok);
    a.ldrb_imm(0, 3, 18);
    a.lsrs_imm(0, 0, 4);
    a.cmp_imm(0, 2);
    a.beq(two);
    a.cmp_imm(0, 3);
    a.bne(oem);
    a.movs_imm(0, 0xc8);
    a.b(assign);
    a.bind(two);
    a.movs_imm(0, 0xc7);
    a.bind(assign);
    a.strb_imm(0, 4, 0);
    a.pop(0x2f);
    a.raw16(0xb001); // Drop saved local LR; native parent restores its own LR.
    a.ldrb_imm(2, 4, 0);
    a.movs_imm(contract.one_register as u16, 1);
    tail(&mut a, contract.format);
    a.bind(oem);
    a.cmp_imm(5, 0);
    a.beq(v0);
    a.ldr_lit(0, 0x4000_0000);
    a.raw16(0x1800); // ADDS r0,r0,r0: restore V=1.
    a.b(replay);
    a.bind(v0);
    a.cmp_reg(5, 5); // Restore V=0.
    a.bind(replay);
    a.pop(0x2f);
    a.raw16(0xb001);
    for word in original.as_chunks::<2>().0 {
        a.raw16(u16::from_le_bytes(*word));
    }
    tail(&mut a, contract.replay_continuation);
    Ok(UhdDiCandidate {
        contract,
        original,
        bytes: a.finish()?,
        caller,
    })
}
