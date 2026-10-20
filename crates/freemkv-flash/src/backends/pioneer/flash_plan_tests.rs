use super::*;

#[test]
fn cached_authorization_facts_preserve_pair_and_normal_only_routes() {
    use pioneer_optical::receiver::Receiver;
    for installed_gated in [false, true] {
        let installed = super::super::prepared_tests::pair(installed_gated, 1);
        let receiver = Receiver::from_installed(&installed).unwrap();
        let cached_installed = installed_from_loaded(&receiver, installed.normal_transfer());
        let old_installed = super::super::installed_component_facts(
            Some(installed.kernel_transfer()),
            Some(installed.normal_transfer()),
        );
        assert_eq!(cached_installed, old_installed);
        for target_gated in [false, true] {
            for marker in [0, 1, 0xff] {
                let target = super::super::prepared_tests::pair(target_gated, marker);
                let cached = target_from_loaded(
                    Some(target.kernel()),
                    target.normal(),
                    Some(target.kernel_transfer()),
                    target.normal_transfer(),
                )
                .unwrap();
                let old = target_from_components(
                    Some(target.kernel_transfer()),
                    Some(target.normal_transfer()),
                )
                .unwrap();
                assert_eq!(cached, old);
                assert_eq!(
                    check_loaded_receiver(&target),
                    check_receiver(
                        Some(installed.kernel_transfer()),
                        Some(target.kernel_transfer()),
                        target.normal_transfer()
                    )
                );
                assert_eq!(
                    decide_flash_plan(cached_installed.as_ref().unwrap(), &cached),
                    decide_flash_plan(old_installed.as_ref().unwrap(), &old)
                );

                let normal = pioneer_optical::envelope::Envelope::load_with_kernel(
                    target.normal_transfer(),
                    receiver.installed_kernel().unwrap(),
                )
                .unwrap();
                let cached_normal =
                    target_from_loaded(None, &normal, None, target.normal_transfer()).unwrap();
                let mut old_normal =
                    target_from_components(None, Some(target.normal_transfer())).unwrap();
                old_normal.family = normal_family_with_kernel(
                    target.normal_transfer(),
                    installed.kernel_transfer(),
                );
                assert_eq!(cached_normal, old_normal);
                assert_eq!(
                    decide_flash_plan(cached_installed.as_ref().unwrap(), &cached_normal),
                    decide_flash_plan(old_installed.as_ref().unwrap(), &old_normal)
                );
            }
        }
    }
}

fn date(s: &str) -> Option<FwDate> {
    FwDate::parse(s)
}

/// The injected family every fixture shares unless a test overrides it.
fn fam() -> Option<FamilyKey> {
    Some(FamilyKey::new("f1"))
}

/// The injected tag every fixture shares unless a test overrides it. The
/// gate-2 Normal-only tag check compares `Installed.kernel_tag` to
/// `Target.required_kernel_tag`; tests use this value on both sides so a
/// Normal-only target lands as `Plain`.
fn tag() -> Option<String> {
    Some("ID58".to_string())
}

fn installed(cid: u16, new_gen: bool, d: &str) -> Installed {
    Installed {
        controller_id: cid,
        receiver_new_gen: Some(new_gen),
        normal_date: date(d),
        family: fam(),
        kernel_tag: tag(),
    }
}

fn pair_target(cid: u16, kd: &str, nd: &str, marker: u8) -> Target {
    Target {
        controller_id: cid,
        normal: Some(ComponentInfo { date: date(nd) }),
        kernel: Some(KernelInfo {
            date: date(kd),
            marker,
        }),
        family: fam(),
        required_kernel_tag: tag(),
    }
}

/// Normal-only target with a matching tag by default; override to test
/// mismatch.
fn normal_only_target(cid: u16, nd: &str) -> Target {
    Target {
        controller_id: cid,
        normal: Some(ComponentInfo { date: date(nd) }),
        kernel: None,
        family: fam(),
        required_kernel_tag: tag(),
    }
}

fn header_only(file_type: &str, tag: Option<&str>) -> Vec<u8> {
    let mut img = vec![0u8; 0x200];
    let kv = tag.map_or(String::new(), |t| format!("Kernel Version : {t}\r\n"));
    let header = format!(
        "********  Copyright(c) 2000 Pioneer Corporation  ********\r\n\
             ID : PIONEER BD-RW   BDR-UD04\r\n\
             Revision Level : 1.11\r\n\
             Hardware Version : SAT 8A10\r\n\
             Destination : GENERAL\r\n\
             Generated Date : 22/01/01\r\n\
             {kv}File Type : {file_type}\r\n"
    );
    img[..header.len()].copy_from_slice(header.as_bytes());
    img
}

fn header_model(file_type: &str, tag: &str, model: &str) -> Vec<u8> {
    let mut img = vec![0u8; 0x200];
    let header = format!(
        "********  Copyright(c) 2000 Pioneer Corporation  ********\r\n\
             ID : PIONEER BD-RW   {model}\r\n\
             Revision Level : 1.11\r\n\
             Hardware Version : SAT 8A10\r\n\
             Destination : GENERAL\r\n\
             Generated Date : 22/01/01\r\n\
             Kernel Version : {tag}\r\n\
             File Type : {file_type}\r\n"
    );
    img[..header.len()].copy_from_slice(header.as_bytes());
    img
}

/// The boot-time (model, variant) pairing gate: a written Kernel+Normal that
/// agree on variant (ID tag) but disagree on model must still be refused — the
/// resident-firmware validator aborts at boot on a model mismatch.
#[test]
fn validate_bundle_refuses_model_mismatch() {
    let k = header_model("Kernel", "ID58", "BDR-207");
    let same = header_model("Normal", "ID58", "BDR-207");
    assert!(validate_bundle(Some(&k), Some(&same)).is_ok());
    let other_model = header_model("Normal", "ID58", "BDR-209");
    let err = validate_bundle(Some(&k), Some(&other_model)).unwrap_err();
    assert!(err.contains("model"), "{err}");
}

#[test]
fn validate_bundle_pair_requires_both_kernel_tags() {
    let k = header_only("Kernel", Some("ID58"));
    let n = header_only("Normal", Some("ID58"));
    assert!(validate_bundle(Some(&k), Some(&n)).is_ok());
    let bad = header_only("Normal", Some("ID81"));
    assert!(validate_bundle(Some(&k), Some(&bad)).is_err());
    // An empty tag on either side cannot prove the pair is consistent.
    let empty_n = header_only("Normal", None);
    let empty_k = header_only("Kernel", None);
    assert!(validate_bundle(Some(&k), Some(&empty_n)).is_err());
    assert!(validate_bundle(Some(&empty_k), Some(&n)).is_err());
    // A Normal-only bundle is not subject to the pair check.
    assert!(validate_bundle(None, Some(&empty_n)).is_ok());
}

#[test]
fn date_parse_and_order() {
    assert!(date("20/06/15").unwrap() < date("22/12/12").unwrap());
    assert_eq!(FwDate::parse("00/00/00"), None); // null date -> unusable
    assert_eq!(FwDate::parse("20/13/01"), None); // bad month
    assert_eq!(FwDate::parse("2022/01/02"), FwDate::parse("22/01/02"));
}

#[test]
fn marker_generation_and_site1() {
    assert_eq!(Generation::from_marker(0x01), Generation::Newer);
    assert_eq!(Generation::from_marker(0xFF), Generation::Older);
    assert_eq!(Generation::from_marker(0x00), Generation::Older);
    assert_eq!(Generation::from_marker(0x0C), Generation::Other(0x0C));
    assert!(Generation::from_marker(0xFF).site1_rejected());
    assert!(Generation::from_marker(0x00).site1_rejected());
    assert!(!Generation::from_marker(0x01).site1_rejected());
    assert!(!Generation::from_marker(0x0C).site1_rejected()); // Site 1 rejects only FF/00
}

#[test]
fn normal_only_passes_when_installed_kernel_tag_matches_targets_required_tag() {
    let inst = installed(0x8A10, true, "22/01/01");
    // Date direction is irrelevant to the new policy; tag match is the gate.
    assert_eq!(
        decide_flash_plan(&inst, &normal_only_target(0x8A10, "23/01/01")),
        FlashPlan::Plain
    );
    assert_eq!(
        decide_flash_plan(&inst, &normal_only_target(0x8A10, "22/01/01")),
        FlashPlan::Plain
    );
    // Same-era older with Normal-only is now ALSO allowed if tags match
    // (OEM Normal-only patches ride on the installed Kernel regardless of
    // date direction).
    assert_eq!(
        decide_flash_plan(&inst, &normal_only_target(0x8A10, "20/01/01")),
        FlashPlan::Plain
    );
}

#[test]
fn normal_only_refused_when_tags_differ() {
    let inst = installed(0x8A10, true, "22/01/01");
    let mut tgt = normal_only_target(0x8A10, "23/01/01");
    tgt.required_kernel_tag = Some("ID81".to_string());
    let plan = decide_flash_plan(&inst, &tgt);
    match plan {
        FlashPlan::Refused(reason) => {
            assert!(reason.contains("ID81"));
            assert!(reason.contains("ID58"));
        }
        other => panic!("expected refusal, got {other:?}"),
    }
}

#[test]
fn normal_only_refused_when_installed_tag_unknown() {
    let mut inst = installed(0x8A10, true, "22/01/01");
    inst.kernel_tag = None;
    let tgt = normal_only_target(0x8A10, "23/01/01");
    assert!(matches!(
        decide_flash_plan(&inst, &tgt),
        FlashPlan::Refused(_)
    ));
}

#[test]
fn same_model_older_across_barrier_is_kernel_downgrade() {
    let inst = installed(0x8A10, true, "23/01/01");
    let tgt = pair_target(0x8A10, "20/06/15", "20/06/15", 0xFF);
    assert_eq!(decide_flash_plan(&inst, &tgt), FlashPlan::KernelDowngrade);
}

#[test]
fn same_model_older_same_generation_is_plain() {
    // Older, but incoming Kernel marker is 01 -> Site 1 accepts, no unlock.
    let inst = installed(0x8A10, true, "23/06/01");
    let tgt = pair_target(0x8A10, "23/01/01", "23/01/01", 0x01);
    assert_eq!(decide_flash_plan(&inst, &tgt), FlashPlan::Plain);
}

#[test]
fn same_model_older_on_old_receiver_is_plain() {
    // Receiver lacks Site 1, so even an FF kernel needs no unlock.
    let inst = installed(0x8A10, false, "23/01/01");
    let tgt = pair_target(0x8A10, "20/06/15", "20/06/15", 0xFF);
    assert_eq!(decide_flash_plan(&inst, &tgt), FlashPlan::Plain);
}

#[test]
fn normal_only_with_mismatched_tag_still_refused_even_for_newer_date() {
    // Previously the "same-or-newer date → Plain" rule allowed ANY
    // Normal-only upgrade. The new policy refuses it on tag mismatch
    // regardless of date direction — matching the OEM updater.
    let inst = installed(0x8A10, true, "20/01/01");
    let mut tgt = normal_only_target(0x8A10, "23/01/01");
    tgt.required_kernel_tag = Some("ID99".to_string());
    assert!(matches!(
        decide_flash_plan(&inst, &tgt),
        FlashPlan::Refused(_)
    ));
}

#[test]
fn crossflash_on_list_with_pair_is_kernel_crossflash() {
    let inst = installed(0x8F00, true, "22/01/01");
    let tgt = pair_target(0x8F01, "22/01/01", "22/01/01", 0x01);
    assert_eq!(decide_flash_plan(&inst, &tgt), FlashPlan::KernelCrossflash);
}

#[test]
fn crossflash_family_mismatch_is_refused() {
    let inst = installed(0x8F00, true, "22/01/01");
    let mut tgt = pair_target(0x9401, "22/01/01", "22/01/01", 0x01);
    tgt.family = Some(FamilyKey::new("f2"));
    assert!(matches!(
        decide_flash_plan(&inst, &tgt),
        FlashPlan::Refused(r) if r.contains("family mismatch")
    ));
}

#[test]
fn crossflash_without_kernel_is_refused() {
    // Different-SAT target requires a pair; Normal-only crossflash is never
    // safe (would land the new Normal on the drive's existing wrong-model
    // Kernel).
    let inst = installed(0x8F00, true, "22/01/01");
    let tgt = normal_only_target(0x8F01, "22/01/01");
    assert!(matches!(
        decide_flash_plan(&inst, &tgt),
        FlashPlan::Refused(reason) if reason.contains("crossflash")
    ));
}

#[test]
fn same_family_crossflash_is_not_gated_by_any_table() {
    // Any same-family pair is crossflash-compatible in BOTH directions; the
    // the family-match gate is deterministic from `fw::get_family`;
    // no hard-coded compatibility table gates anything.
    let fwd = decide_flash_plan(
        &installed(0x8F00, true, "22/01/01"),
        &pair_target(0x8F01, "22/01/01", "22/01/01", 0x01),
    );
    let rev = decide_flash_plan(
        &installed(0x8F01, true, "22/01/01"),
        &pair_target(0x8F00, "22/01/01", "22/01/01", 0x01),
    );
    assert_eq!(fwd, FlashPlan::KernelCrossflash);
    assert_eq!(rev, FlashPlan::KernelCrossflash);
}

#[test]
fn family_gate_requires_both_some_and_equal() {
    let a = FamilyKey::new("aa");
    let b = FamilyKey::new("bb");
    assert!(family_gate(Some(&a), Some(&a)).is_ok());
    assert!(family_gate(Some(&a), Some(&b))
        .unwrap_err()
        .contains("mismatch"));
    assert!(family_gate(None, Some(&a))
        .unwrap_err()
        .contains("installed"));
    assert!(family_gate(Some(&a), None).unwrap_err().contains("target"));
    assert!(family_gate(None, None).is_err());
}

#[test]
fn same_model_is_refused_on_family_mismatch_or_unknown() {
    let inst = installed(0x8A10, true, "22/01/01");
    let mut mismatch = pair_target(0x8A10, "23/01/01", "23/01/01", 0x01);
    mismatch.family = Some(FamilyKey::new("other"));
    let mut unknown_target = mismatch.clone();
    unknown_target.family = None;
    let mut unknown_installed = inst.clone();
    unknown_installed.family = None;
    let ok_target = pair_target(0x8A10, "23/01/01", "23/01/01", 0x01);
    for (i, t) in [
        (&inst, &mismatch),
        (&inst, &unknown_target),
        (&unknown_installed, &ok_target),
    ] {
        assert!(matches!(decide_flash_plan(i, t), FlashPlan::Refused(_)));
    }
    assert_eq!(decide_flash_plan(&inst, &ok_target), FlashPlan::Plain);
}

#[test]
fn crossflash_across_generation_barrier_is_reported_as_downgrade() {
    let inst = installed(0x8F00, true, "22/01/01");
    let tgt = pair_target(0x8F01, "20/01/01", "20/01/01", 0xFF);
    assert_eq!(decide_flash_plan(&inst, &tgt), FlashPlan::KernelDowngrade);
}

#[test]
fn kernel_mode_is_never_required() {
    for plan in [
        FlashPlan::Plain,
        FlashPlan::KernelDowngrade,
        FlashPlan::KernelCrossflash,
        FlashPlan::Refused("x".into()),
    ] {
        assert!(!kernel_mode_required(&plan));
    }
}

#[test]
fn fwdate_two_digit_year_boundary_is_strict_less_than_100() {
    // A 3-digit year (100) must NOT be treated as a 2-digit year (+2000):
    // original `< 100` keeps 100 (ancient), so it sorts BEFORE a real 2-digit
    // year like 99 -> 2099. The `<=` mutant would make 100 -> 2100 (after 2099).
    assert!(FwDate::parse("100/01/01") < FwDate::parse("99/01/01"));
    // And a genuine 2-digit year still gets the +2000 treatment (2022 > 2021).
    assert!(FwDate::parse("22/01/01") > FwDate::parse("21/12/31"));
}

/// Build a structurally-valid FrontKey Kernel envelope whose DECODED body
/// byte at 0xFE equals `marker`, via the pioneer-optical public builder. Mirrors
/// the codec's own `front_kernel` test fixture.
fn encoded_kernel_with_marker(marker: u8) -> Vec<u8> {
    use pioneer_optical::envelope::builder::{encode_kernel_envelope, KernelBuild};
    fn be32_fix(buf: &mut [u8], at: usize) {
        buf[at..at + 4].copy_from_slice(&[0; 4]);
        let mut sum = 0u32;
        let mut i = 0;
        while i + 4 <= buf.len() {
            sum = sum.wrapping_add(u32::from_be_bytes([
                buf[i],
                buf[i + 1],
                buf[i + 2],
                buf[i + 3],
            ]));
            i += 4;
        }
        buf[at..at + 4].copy_from_slice(&0u32.wrapping_sub(sum).to_be_bytes());
    }
    fn write_branch(buf: &mut [u8], at: usize, offs: [u32; 2]) {
        buf[at] = 0x7a;
        buf[at + 1] = 0x20;
        buf[at + 2..at + 6].copy_from_slice(&offs[0].to_be_bytes());
        buf[at + 6] = 0x47;
        buf[at + 7] = 12;
        buf[at + 8] = 0x7a;
        buf[at + 9] = 0x20;
        buf[at + 10..at + 14].copy_from_slice(&offs[1].to_be_bytes());
        buf[at + 14] = 0x47;
        buf[at + 15] = 4;
        buf[at + 16..at + 20].copy_from_slice(&[1, 0xf0, 0x65, 5]);
    }
    let mut k = vec![0u8; 0x10000];
    k[0x1000..0x1008].copy_from_slice(b"SAT 8A10");
    k[0x1008..0x1010].copy_from_slice(b"GENERAL ");
    k[0x1010..0x1014].copy_from_slice(b"0000");
    k[0x40] = 0xae;
    k[0x41] = 0xfe;
    k[0x46] = 0xae;
    k[0x47] = 0xf0;
    write_branch(&mut k, 0x100, [0x100, 0x200]);
    k[0xFE] = marker; // the generation marker we read back
    be32_fix(&mut k, 0xff00);
    encode_kernel_envelope(&k, "PIONEER BDR-TEST", &KernelBuild::from_seed(0x123456))
        .expect("encode synthetic kernel")
}

#[test]
fn decoded_kernel_marker_reads_body_offset_0xfe() {
    // Round-trips a real encoded Kernel and reads its decoded 0xFE marker,
    // killing the "always Ok(0)/Ok(1)" stubs of decoded_kernel_marker.
    assert_eq!(
        decoded_kernel_marker(&encoded_kernel_with_marker(0xFF)).unwrap(),
        0xFF
    );
    assert_eq!(
        decoded_kernel_marker(&encoded_kernel_with_marker(0x01)).unwrap(),
        0x01
    );
    assert_eq!(
        decoded_kernel_marker(&encoded_kernel_with_marker(0xAB)).unwrap(),
        0xAB
    );
}

/// Package encoding does not change same-family hardware compatibility.
#[test]
fn same_family_cross_sat_pairs_work_in_both_directions() {
    for (source, destination) in [(0x8F00, 0x8F01), (0x8F01, 0x8F00)] {
        let installed = installed(source, true, "23/08/01");
        let target = pair_target(destination, "23/08/01", "23/08/01", 0x01);
        assert_eq!(
            decide_flash_plan(&installed, &target),
            FlashPlan::KernelCrossflash
        );
    }
}

/// A cross-hardware crossflash whose Kernel uses the self-chunking KernelFront
/// framing carries no era-pinned schedule, so it is NOT refused by this guard.
#[test]
fn cross_hardware_non_generated_framing_still_crossflashes() {
    let installed = installed(0x8F00, true, "23/08/01");
    let target = pair_target(0x8F01, "23/08/01", "23/08/01", 0x01); // generated=false
    assert_eq!(
        decide_flash_plan(&installed, &target),
        FlashPlan::KernelCrossflash
    );
}

// ---- receiver class routing + the pure receiver gate ------------------------

/// A same-SAT Kernel+Normal pair to a *different* edition (e.g. BDR-207M ID43 ->
/// BDR-PR1ML ID88) swaps the resident Kernel, so it routes as a crossflash, not
/// Plain — the receiver gate must then clear it before any write.
#[test]
fn same_sat_different_destination_routes_crossflash_not_plain() {
    let mut inst = installed(0x8000, false, "12/09/05");
    inst.kernel_tag = Some("ID43".to_string());
    let mut tgt = pair_target(0x8000, "12/09/05", "12/09/05", 0x01);
    tgt.required_kernel_tag = Some("ID88".to_string());
    assert_eq!(decide_flash_plan(&inst, &tgt), FlashPlan::KernelCrossflash);
}

/// A same-SAT, same-edition Kernel+Normal pair stays an ordinary Plain update.
#[test]
fn same_sat_same_destination_stays_plain() {
    let mut inst = installed(0x8000, false, "12/09/05");
    inst.kernel_tag = Some("ID43".to_string());
    let mut tgt = pair_target(0x8000, "12/09/05", "12/09/05", 0x01);
    tgt.required_kernel_tag = Some("ID43".to_string());
    assert_eq!(decide_flash_plan(&inst, &tgt), FlashPlan::Plain);
}

/// An unknown installed destination routes same-SAT Kernel+Normal as a
/// crossflash (the safer route), so the receiver gate is forced to run.
#[test]
fn same_sat_unknown_destination_routes_crossflash() {
    let mut inst = installed(0x8000, false, "12/09/05");
    inst.kernel_tag = None;
    let tgt = pair_target(0x8000, "12/09/05", "12/09/05", 0x01);
    assert_eq!(decide_flash_plan(&inst, &tgt), FlashPlan::KernelCrossflash);
}

/// The pure receiver gate admits only a zero-checksum, body-matching decode.
#[test]
fn receiver_gate_admits_only_zero_checksum_matching_body() {
    assert!(receiver_gate(&ReceiverEvidence {
        installed_checksum_zero: Some(true),
        bodies_match: true,
    })
    .is_ok());
}

/// A nonzero installed-Kernel checksum (the 207M<->PR1ML case: 0x7004c /
/// 0x1acbab75) is refused as incompatible.
#[test]
fn receiver_gate_refuses_nonzero_installed_checksum() {
    let err = receiver_gate(&ReceiverEvidence {
        installed_checksum_zero: Some(false),
        bodies_match: false,
    })
    .unwrap_err();
    assert_eq!(err, RECEIVER_INCOMPATIBLE);
}

/// A zero checksum but a differing body (a rotation-only divergence) is refused.
#[test]
fn receiver_gate_refuses_zero_checksum_but_mismatched_body() {
    let err = receiver_gate(&ReceiverEvidence {
        installed_checksum_zero: Some(true),
        bodies_match: false,
    })
    .unwrap_err();
    assert_eq!(err, RECEIVER_INCOMPATIBLE);
}

/// An unknown installed Kernel fails closed.
#[test]
fn receiver_gate_fails_closed_on_unknown_installed_kernel() {
    let err = receiver_gate(&ReceiverEvidence {
        installed_checksum_zero: None,
        bodies_match: false,
    })
    .unwrap_err();
    assert_eq!(err, RECEIVER_UNKNOWN);
}

/// A Normal-only flash has no target Kernel to compare, so `check_receiver`
/// admits it: the installed Kernel is the receiver and the library's Normal-only
/// preparation already authenticates against it.
#[test]
fn check_receiver_admits_normal_only() {
    assert!(check_receiver(None, None, b"ignored").is_ok());
}
