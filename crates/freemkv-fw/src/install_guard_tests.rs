//! Unit tests for [`super`] — the emit-time detour-install guards.
//!
//! These exist because a mutation run found every guard here could be replaced
//! with `Ok(())` and the whole suite still passed. A guard nothing tests is not
//! a guard; it is a comment that compiles. Each test below fails if its guard
//! stops rejecting what it is supposed to reject.

use super::*;
use thumb_asm::BranchKind;

/// The site the guards operate on is a 4-byte window, so every fixture is a
/// small image with room for one branch plus slack either side.
///
/// 0.11.1's `can_install` pre-flight refuses a site whose bytes don't decode as
/// instructions — which `0xFF`-fill does not — so the fixture plants two
/// harmless 16-bit `movs r0,#0` (`0x2000`) instructions at the install site.
/// That is real Thumb code the pre-flight accepts, and it is what the OEM
/// image bytes would look like at any legal patch site.
fn img(len: usize) -> Vec<u8> {
    let mut v = vec![0xFF; len];
    let site = 0x10;
    if site + 4 <= len {
        v[site..site + 4].copy_from_slice(&[0x00, 0x20, 0x00, 0x20]); // 2x movs r0,#0
    }
    v
}

#[test]
fn install_branch_writes_a_branch_that_decodes_back_to_the_target() {
    let mut i = img(0x200);
    install_branch(&mut i, 0x10, BranchKind::Bl, 0x120, "T").expect("in range");
    // Not just "no error" — the bytes must really decode to the target, which
    // is the whole claim the guard makes.
    assert_eq!(
        thumb_asm::decode_bl(&i, 0x10),
        Some(0x120),
        "installed BL must decode back to its target"
    );
    // And it must be a BL specifically: B.W is 4 bytes at the same site and a
    // caller that wanted a call would silently get a jump.
    assert_ne!(
        thumb_asm::decode_b_wide(&i, 0x10),
        Some(0x120),
        "a BL install must not also read as a B.W"
    );
}

#[test]
fn install_branch_honours_the_branch_kind() {
    let mut i = img(0x200);
    install_branch(&mut i, 0x10, BranchKind::BWide, 0x120, "T").expect("in range");
    assert_eq!(
        thumb_asm::decode_b_wide(&i, 0x10),
        Some(0x120),
        "installed B.W must decode back as B.W"
    );
    // This is the 0.8.13 bug in one assertion: a B.W site read as a BL is the
    // exact confusion that corrupted `lr` and de-bussed the drive at boot.
    assert_ne!(
        thumb_asm::decode_bl(&i, 0x10),
        Some(0x120),
        "a B.W install must not also read as a BL"
    );
}

#[test]
fn install_branch_rejects_an_out_of_range_target() {
    let mut i = img(0x100);
    // Thumb-2 wide branches reach +/-16 MB; 0x7FFF_0000 from site 0x10 does not.
    let e = install_branch(&mut i, 0x10, BranchKind::Bl, 0x7FFF_0000, "Speed")
        .expect_err("an unencodable displacement must be refused, not silently skipped");
    assert!(
        format!("{e:#}").contains("Speed"),
        "the failure must name the lever so the operator knows which detour broke: {e:#}"
    );
}

#[test]
fn verify_branch_rejects_a_site_that_does_not_hold_the_expected_branch() {
    let mut i = img(0x200);
    install_branch(&mut i, 0x10, BranchKind::Bl, 0x120, "T").expect("in range");
    // Right kind, wrong target.
    verify_branch(&i, 0x10, BranchKind::Bl, 0x140, "Region")
        .expect_err("a branch reaching the wrong stub must be caught");
    // Right target, wrong kind — the 0.8.13 shape confusion again, now from
    // the verify side.
    verify_branch(&i, 0x10, BranchKind::BWide, 0x120, "Region")
        .expect_err("a BL must not verify as a B.W");
    // Unpatched bytes must not pass for anything.
    verify_branch(&i, 0x80, BranchKind::Bl, 0x120, "Region")
        .expect_err("an untouched site must not verify as an installed branch");
    // And the true statement must still hold, or the test proves nothing.
    verify_branch(&i, 0x10, BranchKind::Bl, 0x120, "Region").expect("the real install verifies");
}

#[test]
fn assert_literal_absent_finds_the_forbidden_va_and_thumb_tags_it() {
    let mut i = img(0x40);
    // The guard searches for `forbidden | 1`, because call targets are stored
    // Thumb-tagged. Plant the TAGGED form: this is what a reintroduced
    // `blx <rearm>` literal would actually look like in the handler.
    i[0x10..0x14].copy_from_slice(&0x0004_4875u32.to_le_bytes());
    let e = assert_literal_absent(&i, 0, i.len(), 0x0004_4874, "rearm")
        .expect_err("the tagged literal must be found");
    assert!(format!("{e:#}").contains("rearm"), "must name the lever");

    // A clean image passes — otherwise the guard would reject everything and
    // the test above would pass for the wrong reason.
    let clean = img(0x40);
    assert_literal_absent(&clean, 0, clean.len(), 0x0004_4874, "rearm")
        .expect("an image without the literal must pass");
}

#[test]
fn assert_literal_absent_ors_the_tag_rather_than_xor_or_and() {
    // Kills the `|` -> `^` and `|` -> `&` mutants. With an ALREADY-tagged
    // input, `|1` is a no-op and still matches, `^1` clears the bit and looks
    // for the wrong word, `&1` collapses to 1.
    let mut i = img(0x40);
    i[0x10..0x14].copy_from_slice(&0x0004_4875u32.to_le_bytes());
    assert_literal_absent(&i, 0, i.len(), 0x0004_4875, "rearm")
        .expect_err("an already-tagged forbidden VA must still be found (| is idempotent here)");
}

#[test]
fn assert_literal_absent_respects_the_search_window() {
    let mut i = img(0x40);
    i[0x30..0x34].copy_from_slice(&0x0004_4875u32.to_le_bytes());
    // Literal sits outside [0, 0x20) — must NOT fire. Makes the upper bound
    // load-bearing, killing the `<` -> `>` mutant.
    assert_literal_absent(&i, 0, 0x20, 0x0004_4874, "rearm")
        .expect("a literal outside the window must not trip the guard");
    // Inside the window — must fire.
    assert_literal_absent(&i, 0x20, i.len(), 0x0004_4874, "rearm")
        .expect_err("a literal inside the window must trip the guard");
    // An empty window scans nothing.
    //
    // Note: `start < end` vs `start <= end` is an EQUIVALENT mutation here and
    // no test can kill it — the two differ only at `start == end`, where the
    // slice `img[start..start]` is empty and `.windows(4).any(..)` is false
    // either way. The comparison earns its keep by preventing a panic when
    // `start > end` (which `end.min(img.len())` can produce), not by the
    // `==` case. Recorded so a future mutation run does not re-chase it.
    assert_literal_absent(&i, 0x30, 0x30, 0x0004_4874, "rearm")
        .expect("an empty window cannot contain anything");
}

#[test]
fn assert_literal_absent_clamps_end_to_the_image() {
    let mut i = img(0x40);
    i[0x10..0x14].copy_from_slice(&0x0004_4875u32.to_le_bytes());
    // `end` past the image must clamp, not panic — the handler length passed by
    // the caller is stub_va + len and can overrun a short image.
    assert_literal_absent(&i, 0, 0x1000, 0x0004_4874, "rearm")
        .expect_err("clamped scan still finds the literal");
    assert_literal_absent(&i, 0x1000, 0x2000, 0x0004_4874, "rearm")
        .expect("a window entirely past the image scans nothing");
}

/// 0.11.1: the `can_install` pre-flight must refuse a site where a 4-byte
/// install would consume half of a 32-bit Thumb-2 instruction and leave the
/// other half executable as whatever it happens to encode. That is the
/// field-reported brick the release notes call out, and it is the exact class
/// of hazard `install_branch`'s displacement check cannot see.
///
/// Fixture plants a 32-bit Thumb-2 instruction (`BL` encoding = `0xF000 0xF800`,
/// four bytes) starting at `site + 2`. The install at `site` would then span
/// bytes `[site, site+4)`, cutting the wide instruction at byte 2 out of 4 —
/// exactly `InstallHazard::SplitsInstruction`. Refusing here is what makes the
/// guard worth having.
#[test]
fn install_branch_refuses_a_site_that_splits_a_wide_instruction() {
    let mut i = vec![0xFF; 0x100];
    // site+0..site+2: a 16-bit `movs r0,#0`, so the first halfword decodes
    // cleanly on its own. site+2..site+6: a 32-bit BL, whose second halfword
    // sits at site+4 — outside the 4-byte install window.
    i[0x10..0x12].copy_from_slice(&[0x00, 0x20]);
    i[0x12..0x16].copy_from_slice(&[0x00, 0xF0, 0x00, 0xF8]);
    let e = install_branch(&mut i, 0x10, BranchKind::Bl, 0x40, "SplitLever")
        .expect_err("a 4-byte install that halves a wide instruction must be refused");
    let s = format!("{e:#}");
    assert!(s.contains("SplitLever"), "refusal must name the lever: {s}");
    assert!(
        s.contains("refuses a 4-byte install") || s.contains("Splits"),
        "refusal must point at the pre-flight, not the encoder: {s}"
    );
    // And the bytes must not have been written to — the guard runs BEFORE the
    // library install, or it is not a guard.
    assert_eq!(
        &i[0x10..0x14],
        &[0x00, 0x20, 0x00, 0xF0],
        "no bytes written"
    );
}
