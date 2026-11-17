use super::*;

#[test]
fn every_display_language_roundtrips_through_an_atomic_saved_preference() {
    let root = std::env::temp_dir().join(format!(
        "firmware-language-{}",
        crate::diagnostics::new_operation_id()
    ));
    let path = root.join("nested/language");
    let preferences = Preferences::User(Some(path.clone()));
    for language in Language::ALL {
        assert!(!language.native_name().is_empty());
        assert_eq!(Language::from_code(language.code()), Some(language));
        preferences.save(language).unwrap();
        assert_eq!(preferences.load(), language);
        let saved = fs::read_to_string(&path).unwrap();
        assert_eq!(saved, format!("{}\n", language.code()));
    }
    Preferences::Memory.save(Language::De).unwrap();
    assert_eq!(Preferences::Memory.load(), Language::En);
    assert!(Preferences::User(None).save(Language::De).is_err());
    let parent = path.parent().unwrap();
    assert_eq!(
        fs::read_dir(parent).unwrap().count(),
        1,
        "temporary files escaped atomic replacement"
    );
    let directory = Preferences::User(Some(root.join("nested")));
    assert!(directory.save(Language::De).is_err());
    assert!(path.exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn locale_regions_select_the_shipped_spanish_and_chinese_catalogs() {
    for code in ["zh-TW", "zh-HK", "zh-MO", "zh-Hant"] {
        assert_eq!(Language::from_code(code), Some(Language::ZhHant));
    }
    for code in ["zh", "zh-CN", "zh-SG", "zh-Hans", "zh-XX"] {
        assert_eq!(Language::from_code(code), Some(Language::ZhHans));
    }
    for region in [
        "419", "AR", "BO", "BR", "BZ", "CL", "CO", "CR", "CU", "DO", "EC", "GT", "HN", "MX", "NI",
        "PA", "PE", "PR", "PY", "SV", "US", "UY", "VE",
    ] {
        assert_eq!(
            Language::from_code(&format!("es-{region}")),
            Some(Language::Es419)
        );
    }
}

#[test]
fn translated_messages_and_recursive_english_diagnostics_keep_data_intact() {
    let encoded = message("ui.mtk_read_limits", &[]);
    let expected = get(Language::En, "ui.mtk_read_limits");
    assert_eq!(
        english_json(serde_json::json!({"message": encoded, "items": [encoded, 42, null, true]})),
        serde_json::json!({"message": expected, "items": [expected, 42, null, true]})
    );
    for language in Language::ALL {
        assert_eq!(
            render(language, "/path/that/is/not/a/translation.bin"),
            "/path/that/is/not/a/translation.bin"
        );
        assert!(!render(language, &encoded).starts_with('\u{1e}'));
    }
    assert_eq!(
        template_arguments("Read {count} bytes from {path}", "Read 16 bytes from /a/b"),
        Some(vec![
            ("count".into(), "16".into()),
            ("path".into(), "/a/b".into())
        ])
    );
    assert_eq!(
        template_arguments("File {path}: done", "File /a: done/b: done"),
        Some(vec![("path".into(), "/a: done/b".into())])
    );
    for (template, value) in [
        ("Bad {unfinished", "Bad value"),
        ("{a}{b}", "ambiguous"),
        ("Expected {x}", "Wrong value"),
        ("Value {x}: done", "Value 1: missing"),
    ] {
        assert_eq!(template_arguments(template, value), None);
    }
}
