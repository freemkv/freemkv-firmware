//! Golden CDB KAT + catalog invariants for [`super`].
//!
//! The golden KAT pins the declarative MT1959 recipe to the byte-for-byte output
//! of the live `drive::mtk` CDB builders — so the declarative catalog can never
//! drift from the proven, hardware-executed path.

use super::*;
use crate::drive::mtk;

fn step(label: &str) -> &'static FlashStep {
    FlashInstructionSet::mt1959()
        .steps
        .iter()
        .find(|s| s.label == label)
        .unwrap_or_else(|| panic!("MT1959 recipe missing step {label:?}"))
}

#[test]
fn golden_cdb_kat_fixed_steps_match_mtk_builders() {
    assert_eq!(step("PROBE").render(0, 0), mtk::cdb_read_probe());
    assert_eq!(step("READY").render(0, 0), mtk::cdb_test_unit_ready());
    assert_eq!(step("PREPARE").render(0, 0), mtk::cdb_wb_prepare());
    assert_eq!(step("COMMIT").render(0, 0), mtk::cdb_wb_commit());
    assert_eq!(step("STATUS").render(0, 0), mtk::cdb_request_sense());
}

#[test]
fn golden_cdb_kat_stream_matches_mtk_for_every_chunk_offset() {
    let stream = step("STREAM");
    assert!(stream.per_chunk, "STREAM must be the per-chunk step");
    let len = mtk::CHUNK as u32; // 0x4000
                                 // First, last, and interior chunk offsets across the 2 MiB image.
    for off in (0..mtk::IMAGE_SIZE as u32).step_by(mtk::CHUNK) {
        assert_eq!(
            stream.render(off, len),
            mtk::cdb_wb_data(off, len as u16).to_vec(),
            "STREAM CDB differs from mtk::cdb_wb_data at offset {off:#x}"
        );
    }
}

#[test]
fn golden_cdb_kat_readback_matches_mtk_read_buffer() {
    let rb = step("READBACK");
    for &(off, len) in &[(0u32, 0x100u32), (0x1E_C000, 0x100), (0x1F_0000, 0x1_0000)] {
        assert_eq!(
            rb.render(off, len),
            mtk::cdb_read_buffer(mtk::MODE_6, mtk::FLASH_BUFFER_ID, off, len).to_vec(),
            "READBACK CDB differs from mtk::cdb_read_buffer at {off:#x}/{len:#x}"
        );
    }
}

#[test]
fn mt1959_recipe_shape_is_executable_and_verbatim() {
    let s = FlashInstructionSet::mt1959();
    assert_eq!(s.family, Family::Mtk);
    assert_eq!(s.transport, Transport::Spti);
    assert_eq!(s.write_opcode, 0x3B);
    assert!(!s.host_side_key, "MT1959 needs no host-side key");
    assert_eq!(s.status, FlashStatus::Executable);
    assert!(s.status.is_executable());
    // Exactly one per-chunk step (the streaming loop).
    assert_eq!(s.steps.iter().filter(|st| st.per_chunk).count(), 1);
}

#[test]
fn for_family_only_mtk_has_an_executable_set() {
    assert!(FlashInstructionSet::for_family(Family::Mtk).is_some());
    assert!(FlashInstructionSet::for_family(Family::Pioneer).is_none());
    assert!(FlashInstructionSet::for_family(Family::Renesas).is_none());
    assert!(FlashInstructionSet::for_family(Family::Unknown).is_none());
}

#[test]
fn catalog_covers_18_brands_plus_the_executable_family() {
    // 18 cdb.json brands + MediaTek MT1959 = 19 entries.
    assert_eq!(CATALOG.len(), 19);
    for r in CATALOG {
        assert!(
            !r.host_side_key,
            "{}: no brand needs a host-side key",
            r.brand
        );
    }
    // Exactly one Executable (MT1959), and it is the only one.
    let exec: Vec<_> = CATALOG
        .iter()
        .filter(|r| r.status == FlashStatus::Executable)
        .collect();
    assert_eq!(exec.len(), 1);
    assert_eq!(exec[0].brand, "MediaTek MT1959");
}

#[test]
fn transport_gated_entries_are_exactly_the_aspi_brands() {
    for r in CATALOG {
        // Tier and transport must agree: ASPI/kernel => TransportGated; SPTI => not.
        match r.transport {
            Transport::Aspi | Transport::MtkKernelDioc => {
                assert_eq!(
                    r.status,
                    FlashStatus::TransportGated,
                    "{} uses an un-issuable transport but is not transport-gated",
                    r.brand
                );
            }
            Transport::Spti => {
                assert_ne!(
                    r.status,
                    FlashStatus::TransportGated,
                    "{} is SPTI and must not be transport-gated",
                    r.brand
                );
            }
        }
    }
    let gated: Vec<_> = CATALOG
        .iter()
        .filter(|r| r.status == FlashStatus::TransportGated)
        .map(|r| r.brand)
        .collect();
    assert_eq!(gated, ["NEC", "Optiarc", "Ricoh", "Teac", "Yamaha"]);
}

#[test]
fn catalog_only_are_spti_and_not_hardware_proven() {
    let catalog_only = CATALOG
        .iter()
        .filter(|r| r.status == FlashStatus::CatalogOnly)
        .count();
    // 19 total - 1 executable - 5 transport-gated = 13 catalog-only.
    assert_eq!(catalog_only, 13);
    for r in CATALOG
        .iter()
        .filter(|r| r.status == FlashStatus::CatalogOnly)
    {
        assert_eq!(
            r.transport,
            Transport::Spti,
            "{} catalog-only must be SPTI",
            r.brand
        );
        assert!(
            !r.status.is_executable(),
            "{} catalog-only must not be executable",
            r.brand
        );
    }
}

#[test]
fn brand_recipe_lookup_is_case_insensitive() {
    assert_eq!(brand_recipe("liteon").unwrap().brand, "LiteOn");
    assert_eq!(
        brand_recipe("YAMAHA").unwrap().status,
        FlashStatus::TransportGated
    );
    assert!(brand_recipe("nonesuch").is_none());
}
