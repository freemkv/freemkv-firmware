use super::*;

#[test]
fn known_bd_model_resolves_from_table() {
    let cap = capability_for("BD-RE BU40N", ChipFamily::Mt1959);
    assert_eq!(cap.media_class, MediaClass::UhdBd);
    assert!(cap.bd_aacs && cap.region_lockable);
}

#[test]
fn unknown_model_falls_back_to_bd_uhd_default() {
    let cap = capability_for("SOME-FUTURE-DRIVE", ChipFamily::Mt1939);
    assert_eq!(cap.media_class, MediaClass::UhdBd);
    assert!(cap.bd_aacs && cap.region_lockable);
}

#[test]
fn longest_token_wins() {
    // Two table tokens match this string and map to DIFFERENT media classes:
    // "BU40N" (UhdBd, len 5) and the longer "WH16NS40" (Bd, len 8). The
    // max_by_key tie-break must pick the longer one, so the class flips to Bd
    // — proving selection is by token length, not by class ordering.
    let short = capability_for("BU40N", ChipFamily::Mt1959);
    assert_eq!(short.media_class, MediaClass::UhdBd);
    let cap = capability_for("BU40N WH16NS40", ChipFamily::Mt1959);
    assert_eq!(cap.media_class, MediaClass::Bd);
}

#[test]
fn media_class_is_ordered() {
    assert!(MediaClass::Cd < MediaClass::Dvd);
    assert!(MediaClass::Dvd < MediaClass::Bd);
    assert!(MediaClass::Bd < MediaClass::UhdBd);
}
