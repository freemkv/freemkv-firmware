//! Component-based UHD conversion planning and normal Modify hook emission.
//!
//! Locators live in mediatek-optical. This module owns policy and Thumb emission.
//! Installation requires every named software contract and commits atomically.
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
    pending: Vec<&'static str>,
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
        let mut pending = Vec::new();
        if areas
            .area(UhdArea::DiscInformation)?
            .variant()
            .starts_with("classic")
        {
            use mediatek_optical::image::analysis::*;
            let checks = [
                (
                    "disc-information recognition",
                    ClassicDi::detect(image).map(|_| ()),
                ),
                (
                    "auxiliary native selectors",
                    ClassicConsumer::inspect(image, state).map(|_| ()),
                ),
                (
                    "position scaling",
                    ClassicPosition::detect(image, state).map(|_| ()),
                ),
                (
                    "position setup",
                    ClassicPositionSetup::detect(image, state).map(|_| ()),
                ),
                (
                    "read-position decode and ranges",
                    ClassicReadPosition::detect(image, state).map(|_| ()),
                ),
                (
                    "parameter lookup",
                    ClassicParameter::detect(image, state).map(|_| ()),
                ),
                (
                    "startup calibration",
                    ClassicCalibration::detect(image, state).map(|_| ()),
                ),
                (
                    "controller completion and native recovery",
                    ClassicReadCompletion::inspect(image, state).map(|_| ()),
                ),
                (
                    "native speed defaults and request clamp",
                    NativeSpeedPolicy::detect(image).map(|_| ()),
                ),
            ];
            pending.extend(
                checks
                    .into_iter()
                    .filter_map(|(name, result)| result.err().map(|_| name)),
            );
            for area in UhdArea::ALL {
                if areas.area(area).is_err() {
                    pending.push("core native routing");
                    break;
                }
            }
        }
        if !areas
            .area(UhdArea::DiscInformation)?
            .variant()
            .starts_with("classic")
            && UhdArea::ALL.iter().any(|&area| {
                !matches!(
                    areas.area(area).map(|c| c.selects_c7()),
                    Ok(None | Some(true))
                )
            })
        {
            pending.push("unvalidated non-classic conversion");
        }
        Ok(Self {
            pending,
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
    /// Remaining software contracts required by the complete hook group.
    /// An empty list does not establish optical/controller behavior on hardware.
    pub fn remaining_contracts(&self) -> Vec<&'static str> {
        self.pending.clone()
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
    /// Emit independently validated classic selection stubs.
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
    /// Bind and emit native controller/completion roles after the original hook group.
    pub fn completion_candidates(
        &self,
        image: &[u8],
        flags: u32,
    ) -> Result<Vec<UhdRoutingCandidate<CompletionRole>>> {
        ensure!(
            <[u8; 32]>::from(Sha256::digest(image)) == self.source_hash,
            "source state changed"
        );
        let contract =
            mediatek_optical::image::analysis::ClassicReadCompletion::inspect(image, self.state)?;
        let mut result = Vec::new();
        for (index, area) in [
            CompletionRole::ControllerTiming,
            CompletionRole::ControllerMode,
            CompletionRole::ReadCompletionBoundary,
        ]
        .into_iter()
        .enumerate()
        {
            let selection = &contract.selections[index];
            let site = selection.site();
            result.push(UhdRoutingCandidate {
                area,
                region_start: if index < 2 {
                    contract.controller_region
                } else {
                    contract.boundary_region
                },
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
            });
        }
        Ok(result)
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
    /// Extend both positively bound native position-setup selectors for C7/On.
    pub fn position_setup_candidates(
        &self,
        image: &[u8],
        flags: u32,
    ) -> Result<Vec<UhdRoutingCandidate<PositionRole>>> {
        ensure!(
            <[u8; 32]>::from(Sha256::digest(image)) == self.source_hash,
            "source state changed"
        );
        let contract =
            mediatek_optical::image::analysis::ClassicPositionSetup::detect(image, self.state)?;
        [
            (
                PositionRole::PositionSetupInput,
                &contract.input,
                contract.entry + 6,
                0,
            ),
            (
                PositionRole::PositionSetupCommand,
                &contract.command,
                contract.entry + 118,
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
                original: image[site..site + 4].to_vec(),
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
    /// Extend read-position decoding and native range checks for C7/On.
    pub fn read_position_candidates(
        &self,
        image: &[u8],
        flags: u32,
    ) -> Result<(
        UhdReadPositionCandidate,
        Vec<UhdRoutingCandidate<PositionRole>>,
    )> {
        ensure!(
            <[u8; 32]>::from(Sha256::digest(image)) == self.source_hash,
            "source state changed"
        );
        let contract =
            mediatek_optical::image::analysis::ClassicReadPosition::detect(image, self.state)?;
        let mut a = Asm::new();
        let oem = a.label();
        let zero = a.label();
        let reject = a.label();
        a.push(8);
        a.ldr_lit(3, flag_address(flags)?);
        a.ldrb_imm(3, 3, 0);
        a.cmp_imm(3, crate::abi::STATE_ON);
        a.bne(oem);
        a.ldr_lit(3, self.state);
        a.ldrb_imm(3, 3, 0);
        a.cmp_imm(3, 0xc7);
        a.bne(oem);
        a.pop(8);
        a.ldrb_imm(1, 4, 2);
        a.lsrs_imm(1, 1, 6);
        a.cmp_imm(1, 1);
        a.bne(zero);
        tail(&mut a, contract.layer_one);
        a.bind(zero);
        tail(&mut a, contract.layer_zero);
        a.bind(oem);
        a.pop(8);
        a.cmp_imm(1, 0);
        a.bne(reject);
        tail(&mut a, contract.decode.accept());
        a.bind(reject);
        tail(&mut a, contract.decode.reject());
        let original = image[contract.decode.site()..contract.decode.site() + 4].to_vec();
        let bytes = a.finish()?;
        let ranges = contract
            .ranges
            .iter()
            .enumerate()
            .map(|(index, selection)| {
                let site = selection.site();
                Ok(UhdRoutingCandidate {
                    area: if index == 0 {
                        PositionRole::ReadUpperRange
                    } else {
                        PositionRole::ReadLowerRange
                    },
                    region_start: contract.entry + if index == 0 { 0x124 } else { 0x134 },
                    calculation_end: None,
                    site,
                    original: image[site..site + 4].to_vec(),
                    accept: selection.accept(),
                    reject: selection.reject(),
                    bytes: emit_c7_selection(
                        self.state,
                        flags,
                        selection.replay(),
                        selection.accept(),
                        selection.reject(),
                    )?,
                    caller: contract.callers[index + 1].clone(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok((
            UhdReadPositionCandidate {
                contract,
                original,
                bytes,
            },
            ranges,
        ))
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
        a.adds_imm(0, 0x58);
        a.ldr_lit(0, coefficients);
        a.ldrh_reg(0, 0, 6);
        tail(&mut a, contract.site + 6);
        a.bind(oem);
        a.pop(0x0a);
        a.ldr_lit(0, contract.original_base);
        a.adds_imm(0, 0x58);
        a.ldrh_reg(0, 0, 6);
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
/// Bound read-position decoder and its emitted replacement.
#[derive(Debug, Clone)]
pub struct UhdReadPositionCandidate {
    /// Complete native decode/range routine and state cells.
    pub contract: mediatek_optical::image::analysis::ClassicReadPosition,
    /// Source CMP/branch displaced by the replacement.
    pub original: Vec<u8>,
    /// Relocatable C7 decoder.
    pub bytes: Vec<u8>,
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
    /// Quarter-scale the native setup position and table term.
    PositionSetupInput,
    /// Select the native high-density command parameter.
    PositionSetupCommand,
    /// Upper read-position threshold selection.
    ReadUpperRange,
    /// Lower read-position threshold selection.
    ReadLowerRange,
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
    a.str_sp(3, 4); // str r3,[sp,4]
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
    let replay_bytes = replay
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect::<Vec<_>>();
    a.replay(&replay_bytes);
    if let Some((register, value)) = relocated_load {
        a.ldr_lit(u16::from(register), value);
    }
    tail(a, accept);
    a.bind(oem);
    restore_cv(a, cv);
    a.pop(8);
    let replay_bytes = replay
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect::<Vec<_>>();
    a.replay(&replay_bytes);
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
        a.adds_reg(3, 3, 3);
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
    let replay_bytes: Vec<_> = replay.iter().flat_map(|word| word.to_le_bytes()).collect();
    if thumb_asm::isa::decode_at(&replay_bytes, 0)
        .is_some_and(|instruction| instruction.mnemonic == "bic" && instruction.sets_flags)
    {
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
    a.ands(0, 2);
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
    fn component_plan_binds_complete_software_group_and_preserves_hardware() {
        let plan = UhdConversionPlan::inspect(CLASSIC).unwrap();
        assert_eq!(
            plan.action(UhdArea::HardwareDefaults).unwrap(),
            UhdAction::PreserveHardware
        );
        assert_eq!(
            plan.action(UhdArea::DiscInformation).unwrap(),
            UhdAction::AddRecognition
        );
        assert!(plan.remaining_contracts().is_empty());
        plan.require_complete_conversion().unwrap();
        let mut changed = CLASSIC.to_vec();
        let completion =
            mediatek_optical::image::analysis::ClassicReadCompletion::inspect(CLASSIC, plan.state)
                .unwrap();
        changed[completion.controller_region + 0x20] ^= 1;
        let broken = UhdConversionPlan::inspect(&changed).unwrap();
        assert!(broken
            .remaining_contracts()
            .contains(&"controller completion and native recovery"));
        assert!(broken.require_complete_conversion().is_err());
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
        assert_eq!(auxiliary.len(), 11);
        for candidate in auxiliary {
            assert_eq!(
                &CLASSIC[candidate.site..candidate.site + candidate.original.len()],
                candidate.original
            );
            assert!(candidate.caller.entry() < candidate.site);
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
                plan.require_complete_conversion().unwrap();
                assert_eq!(plan.routing_candidates(&data, 0x0200f000).unwrap().len(), 5);
                assert_eq!(
                    plan.auxiliary_candidates(&data, 0x0200f000).unwrap().len(),
                    11
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
        caller.entry() == contract.entry && caller.stack_bytes() == 40,
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
    a.mov_reg(3, 13); // r3 = native caller SP, before any local push.
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
    a.add_sp(4); // Drop saved local LR; native parent restores its own LR.
    a.ldrb_imm(2, 4, 0);
    a.movs_imm(contract.one_register as u16, 1);
    tail(&mut a, contract.format);
    a.bind(oem);
    a.cmp_imm(5, 0);
    a.beq(v0);
    a.ldr_lit(0, 0x4000_0000);
    a.adds_reg(0, 0, 0); // ADDS r0,r0,r0: restore V=1.
    a.b(replay);
    a.bind(v0);
    a.cmp_reg(5, 5); // Restore V=0.
    a.bind(replay);
    a.pop(0x2f);
    a.add_sp(4);
    a.replay(&original);
    tail(&mut a, contract.replay_continuation);
    Ok(UhdDiCandidate {
        contract,
        original,
        bytes: a.finish()?,
        caller,
    })
}

/// Independently bound read-completion roles; no hardware constants are replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionRole {
    /// Native paired timing fields.
    ControllerTiming,
    /// Native controller mode field.
    ControllerMode,
    /// Native boundary reflection on read completion.
    ReadCompletionBoundary,
}

/// Install the complete source-bound conversion as part of normal Modify.
/// No partial group or capability facts escape a failed allocation or contract.
pub(super) fn install_conversion(
    image: &[u8],
    out: &mut Vec<u8>,
    flags: u32,
    plan: &UhdConversionPlan,
) -> Result<Vec<(&'static str, u32)>> {
    use super::mt1959::Mt1959Engine;
    use mediatek_optical::image::analysis::{AuthCell, AuthCellVariant};
    plan.require_complete_conversion()?;
    let di = di_prevalidation_candidate(image, flags)?;
    let mut parts = vec![(
        "DiscInformation".to_string(),
        di.contract.prevalidation,
        di.original,
        di.bytes,
    )];
    for part in plan.routing_candidates(image, flags)? {
        parts.push((
            format!("{:?}", part.area),
            part.site,
            part.original,
            part.bytes,
        ));
    }
    for part in plan.auxiliary_candidates(image, flags)? {
        parts.push((
            format!("{:?}", part.area),
            part.site,
            part.original,
            part.bytes,
        ));
    }
    for part in plan.completion_candidates(image, flags)? {
        parts.push((
            format!("{:?}", part.area),
            part.site,
            part.original,
            part.bytes,
        ));
    }
    for part in plan.position_candidates(image, flags)? {
        parts.push((
            format!("{:?}", part.area),
            part.site,
            part.original,
            part.bytes,
        ));
    }
    for part in plan.position_setup_candidates(image, flags)? {
        parts.push((
            format!("{:?}", part.area),
            part.site,
            part.original,
            part.bytes,
        ));
    }
    let (read_position, ranges) = plan.read_position_candidates(image, flags)?;
    parts.push((
        "ReadPositionDecode".to_string(),
        read_position.contract.decode.site(),
        read_position.original,
        read_position.bytes,
    ));
    for part in ranges {
        parts.push((
            format!("{:?}", part.area),
            part.site,
            part.original,
            part.bytes,
        ));
    }
    let calibration = plan.calibration_candidate(image, flags)?;
    let calibration_patch = calibration.is_some();
    if let Some(part) = calibration {
        parts.push((
            "StartupCalibration".to_string(),
            part.contract.site,
            part.original,
            part.bytes,
        ));
    }
    let parameter = plan.parameter_candidate(image, flags)?;
    let parameter_patch = parameter.hook.is_some();
    if let Some(part) = parameter.hook {
        parts.push((
            "ParameterTable".to_string(),
            part.site,
            part.original,
            part.bytes,
        ));
    }
    ensure!(
        parts.len() == 27 + usize::from(parameter_patch) + usize::from(calibration_patch),
        "conversion is missing required components"
    );

    let auth = AuthCell::detect(image)?;
    ensure!(
        auth.variant() == AuthCellVariant::R0StateR1Alternate,
        "classic authentication contract mismatch"
    );
    let (site, bytes) = Mt1959Engine.auth_cell_refusal_detour(image, flags)?;
    parts.push((
        "Authentication".into(),
        site,
        image[site..site + 4].to_vec(),
        bytes,
    ));
    let mut working = out.clone();
    let mut auth_stub = 0;
    for (role, site, original, bytes) in parts {
        ensure!(
            working.get(site..site + original.len()) == Some(original.as_slice()),
            "another hook owns {role}"
        );
        ensure!(
            original.len() >= 4 && original.len() % 2 == 0,
            "invalid conversion span"
        );
        let stub = Mt1959Engine.free_space(&working, bytes.len())?;
        let branch = thumb_asm::encode_bl(site, stub).context("conversion branch out of range")?;
        thumb_asm::write(&mut working, stub as usize, &bytes);
        thumb_asm::write(&mut working, site, &branch);
        let mut padding = Asm::new();
        for _ in (site + 4..site + original.len()).step_by(2) {
            padding.mov_reg(8, 8);
        }
        thumb_asm::write(&mut working, site + 4, &padding.finish()?);
        crate::install_guard::verify_branch(
            &working,
            site,
            thumb_asm::BranchKind::Bl,
            stub,
            "UHD conversion",
        )?;
        ensure!(
            working.get(stub as usize..stub as usize + bytes.len()) == Some(bytes.as_slice()),
            "conversion stub changed"
        );
        if site == auth.site() {
            auth_stub = stub;
        }
    }
    ensure!(auth_stub != 0, "missing authentication control");
    *out = working;
    Ok(vec![
        ("auth_cell_site", auth.site() as u32),
        ("auth_cell_stub_va", auth_stub),
        ("auth_cell_refusal", 1),
        ("auth_cell_native_refusal", auth.refusal() as u32),
    ])
}
