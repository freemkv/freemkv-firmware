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
        vec![
            "DI format validation and copied-byte producer",
            "reverse calculation selecting-flag producer",
            "remaining indirect and layer/structure consumers",
            "hook caller/link-register lifetimes",
        ]
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
                site,
                original: image[site..site + width].to_vec(),
                accept,
                reject,
                bytes,
            });
        }
        Ok(candidates)
    }
}
/// A candidate detour with exact replay bytes and both native continuations.
/// Link-register/caller validation is still required before installing a branch.
#[derive(Debug, Clone)]
pub struct UhdRoutingCandidate {
    /// Independent area that requested this extension.
    pub area: UhdArea,
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
    accept: usize,
    reject: usize,
    cv: Option<u32>,
) {
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
    tail(a, accept);
    a.bind(oem);
    restore_cv(a, cv);
    a.pop(8);
    for &op in replay {
        a.raw16(op);
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
        selection_case(&mut a, state, flag, replay, accept, reject, Some(0));
        a.bind(c1v0);
        selection_case(
            &mut a,
            state,
            flag,
            replay,
            accept,
            reject,
            Some(0xffff_ffff),
        );
        a.bind(v1);
        a.bhs(c1v1);
        selection_case(
            &mut a,
            state,
            flag,
            replay,
            accept,
            reject,
            Some(0x4000_0000),
        );
        a.bind(c1v1);
        selection_case(
            &mut a,
            state,
            flag,
            replay,
            accept,
            reject,
            Some(0x8000_0000),
        );
    } else {
        selection_case(&mut a, state, flag, replay, accept, reject, None);
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
        assert_eq!(candidates.len(), 4);
        for candidate in candidates {
            assert!(!matches!(
                candidate.area,
                UhdArea::HardwareDefaults | UhdArea::ReverseCalculation
            ));
            assert_eq!(
                &CLASSIC[candidate.site..candidate.site + candidate.original.len()],
                candidate.original
            );
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
            let data = std::fs::read(hoard.join(row["path"].as_str().unwrap())).unwrap();
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
                assert_eq!(plan.routing_candidates(&data, 0x0200f000).unwrap().len(), 4);
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
