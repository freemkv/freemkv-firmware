use super::*;

fn report(levers: Vec<LeverReport>) -> ModifyReport {
    ModifyReport {
        engine: "MT1959",
        family: "MT1959".into(),
        vendor: "HL-DT-ST".into(),
        model: "BD-RE BU40N".into(),
        rev: "1.00".into(),
        media: "BD/UHD".into(),
        levers,
        image: vec![],
        validation: Validation::StaticOnly,
    }
}

#[test]
fn outcome_words_and_effectiveness() {
    assert_eq!(LeverOutcome::Applied.word(), "applied");
    assert_eq!(LeverOutcome::AlreadyPresent.word(), "already set");
    assert_eq!(
        LeverOutcome::NotApplicable { reason: "x".into() }.word(),
        "n/a"
    );
    assert_eq!(
        LeverOutcome::SignatureNotFound { detail: "x".into() }.word(),
        "skipped"
    );
    assert!(LeverOutcome::Applied.is_effective());
    assert!(LeverOutcome::AlreadyPresent.is_effective());
    assert!(!LeverOutcome::NotApplicable { reason: "x".into() }.is_effective());
    assert!(!LeverOutcome::SignatureNotFound { detail: "x".into() }.is_effective());
}

#[test]
fn summary_partitions_applied_already_and_skipped() {
    let r = report(vec![
        LeverReport::applied(LeverId::RegionFree, vec![]),
        LeverReport::missed(LeverId::RawRead, "NB VID gate not found"),
        LeverReport::applied(LeverId::Speed, vec![]),
        LeverReport::already(LeverId::DowngradeEnable, vec![]),
    ]);
    let s = r.summary();
    assert!(s.contains("Region Free + Speed applied"), "{s}");
    assert!(s.contains("Downgrade (DE) already set"), "{s}");
    assert!(s.contains("Raw read skipped"), "{s}");
    assert!(r.any_effective());
}

#[test]
fn json_is_well_formed_and_encodes_outcomes() {
    let r = report(vec![
        LeverReport::applied(LeverId::RegionFree, vec![("region_emitter", 0x119890)]),
        LeverReport::missed(LeverId::RawRead, "NB VID gate not found"),
        LeverReport::not_applicable(LeverId::Speed, "no BD"),
    ]);
    let j = r.to_json();
    assert!(j.starts_with('{') && j.ends_with('}'));
    assert!(j.contains("\"id\":\"RegionFree\""));
    assert!(j.contains("\"outcome\":\"Applied\""));
    assert!(j.contains("\"region_emitter\":1153168"));
    assert!(j.contains("{\"SignatureNotFound\":{\"detail\":\"NB VID gate not found\"}}"));
    assert!(j.contains("{\"NotApplicable\":{\"reason\":\"no BD\"}}"));
    // balanced braces
    let opens = j.matches('{').count();
    let closes = j.matches('}').count();
    assert_eq!(opens, closes, "unbalanced JSON braces: {j}");
}

#[test]
fn json_escapes_control_and_quotes() {
    let r = report(vec![LeverReport::missed(LeverId::RawRead, "a\"b\\c\n")]);
    let j = r.to_json();
    assert!(j.contains("a\\\"b\\\\c\\n"), "{j}");
}
