//! Catalog and language-switch contracts shared by every shell.

use super::*;
use std::collections::BTreeSet;

#[test]
fn entry_failure_translations_say_no_firmware_payload_was_sent() {
    let no_payload = [
        (Language::Ca, "no s’ha enviat cap dada"),
        (Language::Cs, "nebyla odeslána žádná data"),
        (Language::Da, "ingen firmwaredata"),
        (Language::De, "keine Firmware-Daten"),
        (Language::El, "δεν στάλθηκαν δεδομένα"),
        (Language::En, "no firmware payload was sent"),
        (Language::Es, "no se enviaron datos"),
        (Language::Es419, "no se enviaron datos"),
        (Language::Fi, "ei lähetetty"),
        (Language::Fr, "aucune donnée"),
        (Language::Hu, "nem küldtünk firmware-adatokat"),
        (Language::Id, "tidak ada data firmware"),
        (Language::It, "non sono stati inviati dati"),
        (Language::Ja, "データは送信されていません"),
        (Language::Ko, "데이터는 전송되지 않았습니다"),
        (Language::Nl, "geen firmwaregegevens"),
        (Language::No, "ingen fastvaredata"),
        (Language::Pl, "nie wysłano żadnych danych"),
        (Language::Pt, "não foram enviados dados"),
        (Language::PtBr, "nenhum dado do firmware"),
        (Language::Ro, "nu s-au trimis date de firmware"),
        (Language::Ru, "данные прошивки не отправлялись"),
        (Language::Sk, "neboli odoslané žiadne údaje"),
        (Language::Sv, "inga firmwaredata"),
        (Language::Tr, "hiçbir aygıt yazılımı verisi gönderilmedi"),
        (Language::Uk, "дані мікропрограми не надсилалися"),
        (Language::Vi, "chưa gửi dữ liệu chương trình cơ sở nào"),
        (Language::ZhHans, "未发送任何固件数据"),
        (Language::ZhHant, "未傳送任何韌體資料"),
    ];
    assert_eq!(no_payload.len(), Language::ALL.len());
    for (language, phrase) in no_payload {
        let message = get(language, "errors.update_not_started");
        assert!(message.contains(phrase), "{}: {message}", language.code());
        if language != Language::En {
            assert_ne!(message, get(Language::En, "errors.update_not_started"));
        }
    }
}

#[test]
fn every_embedded_catalog_has_the_same_nonempty_message_ids() {
    let english = Language::En.catalog()["messages"].as_object().unwrap();
    let expected: BTreeSet<_> = english.keys().collect();
    assert!(expected
        .iter()
        .all(|key| key.contains('.') && !key.contains(' ')));
    for language in Language::ALL {
        let catalog = language.catalog();
        let messages = catalog["messages"].as_object().unwrap();
        assert_eq!(
            messages.keys().collect::<BTreeSet<_>>(),
            expected,
            "{}",
            language.code()
        );
        assert_eq!(
            catalog["language_name"].as_str(),
            Some(language.native_name())
        );
        for id in &expected {
            assert!(
                !get(language, id).trim().is_empty(),
                "{}: {id}",
                language.code()
            );
        }
    }
}

#[test]
fn all_language_codes_round_trip() {
    assert_eq!(Language::ALL.len(), 29);
    let codes: BTreeSet<_> = Language::ALL
        .iter()
        .map(|language| language.code())
        .collect();
    assert_eq!(codes.len(), 29);
    for language in Language::ALL {
        assert_eq!(Language::from_code(language.code()), Some(language));
    }
}

#[test]
fn regional_and_process_locale_spellings_select_supported_languages() {
    for (code, expected) in [
        ("fr_FR.UTF-8", Language::Fr),
        ("PT_br", Language::PtBr),
        ("es-MX", Language::Es419),
        ("es-US", Language::Es419),
        ("es-ES", Language::Es),
        ("zh_TW", Language::ZhHant),
        ("zh-Hans-CN", Language::ZhHans),
        ("nb_NO.UTF-8", Language::No),
    ] {
        assert_eq!(Language::from_code(code), Some(expected), "{code}");
    }
    assert_eq!(Language::from_code("unsupported"), None);
}

#[test]
fn selected_language_is_restored_by_the_next_app_instance() {
    let dir = std::env::temp_dir().join(format!(
        "flash-language-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let path = dir.join("settings/language");
    let store = Preferences::User(Some(path.clone()));
    let mut first = crate::ui::App::with_preferences(Vec::new(), store.clone());
    first.dispatch(crate::ui::Input::SetLanguage(Language::Fr));
    assert_eq!(fs::read_to_string(&path).unwrap(), "fr\n");
    let mut next = crate::ui::App::with_preferences(Vec::new(), store.clone());
    assert_eq!(next.language, Language::Fr);
    assert_eq!(next.view().drives.label, "Lecteur optique");
    next.dispatch(crate::ui::Input::SetLanguage(Language::ZhHant));
    assert_eq!(store.load(), Language::ZhHant);
    assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn changing_language_re_resolves_existing_main_screen_copy() {
    let mut app = crate::ui::App::with_drives(Vec::new());
    for language in Language::ALL
        .into_iter()
        .chain([Language::En, Language::Fr])
    {
        app.dispatch(crate::ui::Input::SetLanguage(language));
        let view = app.view();
        assert_eq!(view.drives.label, get(language, "drive.label"));
        assert_eq!(view.drives.placeholder, get(language, "drive.none"));
        assert_eq!(view.drives.refresh.text, get(language, "action.refresh"));
        assert_eq!(view.status.unwrap().text, get(language, "status.ready"));
        let results = view.results.unwrap();
        assert_eq!(results.view_log.text, get(language, "action.view_log"));
        assert_eq!(
            results.submit_report.text,
            get(language, "action.submit_report")
        );
        for tab in view.tabs {
            assert_eq!(tab.title, get(language, tab.task.message_id()));
        }
    }
}

#[test]
fn unavailable_preferences_keep_the_selected_language_usable_for_the_session() {
    let mut app = crate::ui::App::with_preferences(Vec::new(), Preferences::User(None));
    let selected = if app.language == Language::Fr {
        Language::De
    } else {
        Language::Fr
    };
    app.dispatch(crate::ui::Input::SetLanguage(selected));
    assert_eq!(app.language, selected);
    assert_eq!(app.view().drives.label, get(selected, "drive.label"));
    assert!(app
        .log
        .iter()
        .any(|line| line.contains("could not be saved")));
}

#[test]
fn failed_preference_replacement_preserves_existing_contents_and_cleans_temporary_file() {
    let dir = std::env::temp_dir().join(format!(
        "flash-language-failure-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let destination = dir.join("language");
    fs::create_dir_all(&destination).unwrap();
    let existing = destination.join("existing");
    fs::write(&existing, "preserve me").unwrap();
    assert!(Preferences::User(Some(destination))
        .save(Language::Fr)
        .is_err());
    assert_eq!(fs::read_to_string(existing).unwrap(), "preserve me");
    assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
#[should_panic(expected = "missing fr translation")]
fn a_missing_translation_cannot_silently_show_english() {
    text(Language::Fr, "missing.message");
}

fn placeholders(value: &str) -> BTreeSet<&str> {
    value
        .split('{')
        .skip(1)
        .filter_map(|part| part.split_once('}').map(|(key, _)| key))
        .collect()
}

#[test]
fn every_translation_preserves_named_arguments() {
    let english = Language::En.catalog()["messages"].as_object().unwrap();
    for language in Language::ALL {
        for (id, source) in english {
            assert_eq!(
                placeholders(get(language, id)),
                placeholders(source.as_str().unwrap()),
                "{}: {id}",
                language.code()
            );
        }
    }
}

#[test]
fn translated_ui_and_english_diagnostics_resolve_the_same_message_independently() {
    let operation = message(
        "status.operation_failed",
        &[("operation", "task.flash".into())],
    );
    let path = r"C:\Users\reader\{operation}\firmware.bin";
    let saved = message("notice.log_saved", &[("path", path.into())]);
    for language in Language::ALL {
        assert_eq!(english(&operation), "Flash failed");
        let visible = render(language, &operation);
        assert!(
            visible.contains(get(language, "task.flash")),
            "{}: {visible}",
            language.code()
        );
        assert!(render(language, &saved).contains(path));
        assert!(!visible.contains('\u{1e}') && !visible.contains("status.operation"));
        assert_eq!(
            english_json(serde_json::json!({"summary": operation, "nested": [saved]}))["summary"],
            "Flash failed"
        );
    }
}

#[test]
fn legacy_report_templates_translate_complete_sentences_and_preserve_data() {
    let source = "Source B: this component is not included.";
    let translated = render(Language::Fr, source);
    assert_ne!(translated, source);
    assert!(translated.contains('B'));
    for data in [
        r"C:\firmware\Source B: this component is not included..bin",
        "WH16NS58 1.V9",
        "97b287072e20c952",
    ] {
        assert_eq!(render(Language::Fr, data), data);
    }
    assert_eq!(english(source), source);
}

#[test]
fn product_names_and_protocol_names_remain_identifiers_in_every_language() {
    let english = Language::En.catalog()["messages"].as_object().unwrap();
    for language in Language::ALL {
        for (id, source) in english {
            for name in ["freemkv", "MediaTek", "Pioneer", "OEM", "SCSI"] {
                if source.as_str().unwrap().contains(name) {
                    assert!(
                        get(language, id)
                            .to_lowercase()
                            .contains(&name.to_lowercase()),
                        "{}: {id} must preserve {name}",
                        language.code()
                    );
                }
            }
        }
    }
}

#[test]
fn plan_labels_and_backup_summaries_translate_without_changing_the_saved_path() {
    let path = r"C:\firmware (original)\{bytes}\backup.bin";
    let summary = format!("backup: saved {path} (2097152 bytes)");
    let french = render(Language::Fr, &summary);
    assert_ne!(french, summary);
    assert!(french.contains(path), "{french}");
    assert!(french.contains("2097152"));
    assert_eq!(english(&summary), summary);
    assert_eq!(
        render(Language::Fr, "drive: WH16NS58"),
        format!("{}: WH16NS58", render(Language::Fr, "Drive"))
    );
}

#[test]
fn memory_diagnostic_export_resolves_failure_guidance_in_english() {
    let mut app = crate::ui::App::with_drives(Vec::new());
    app.language = Language::Fr;
    app.failure = Some(message("errors.current_required", &[]));
    let diagnostic = app.diagnostic_text().unwrap();
    assert!(diagnostic.contains(get(Language::En, "errors.current_required")));
    assert!(!diagnostic.contains('\u{1e}'));
    assert!(!diagnostic.contains("\"arguments\""));
}

#[test]
fn unsupported_profile_copy_follows_the_selected_language() {
    let mut app = crate::ui::App::with_drives(Vec::new());
    app.set_profile(Ok(crate::ui::Profile {
        chips: vec!["modify.not_supported".into()],
        ..Default::default()
    }));
    for language in Language::ALL {
        app.dispatch(crate::ui::Input::SetLanguage(language));
        assert_eq!(
            app.view().drives.chips,
            [get(language, "modify.not_supported")]
        );
    }
}

#[test]
fn firmware_switches_use_enabled_states_and_keep_english_diagnostics() {
    // These are switch states, not translations of the prepositions "on"/"off".
    for (code, enabled, disabled) in [
        ("ca", "Activat", "Desactivat"),
        ("cs", "Zapnuto", "Vypnuto"),
        ("da", "Til", "Fra"),
        ("de", "Ein", "Aus"),
        ("el", "Ενεργό", "Ανενεργό"),
        ("en", "On", "Off"),
        ("es", "Activado", "Desactivado"),
        ("es-419", "Activado", "Desactivado"),
        ("fi", "Käytössä", "Pois käytöstä"),
        ("fr", "Activé", "Désactivé"),
        ("hu", "Bekapcsolva", "Kikapcsolva"),
        ("id", "Aktif", "Nonaktif"),
        ("it", "Attivo", "Disattivo"),
        ("ja", "オン", "オフ"),
        ("ko", "켜짐", "꺼짐"),
        ("nl", "Aan", "Uit"),
        ("no", "På", "Av"),
        ("pl", "Włączone", "Wyłączone"),
        ("pt", "Ativado", "Desativado"),
        ("pt-br", "Ativado", "Desativado"),
        ("ro", "Activat", "Dezactivat"),
        ("ru", "Включено", "Выключено"),
        ("sk", "Zapnuté", "Vypnuté"),
        ("sv", "På", "Av"),
        ("tr", "Açık", "Kapalı"),
        ("uk", "Увімкнено", "Вимкнено"),
        ("vi", "Bật", "Tắt"),
        ("zh-hans", "开启", "关闭"),
        ("zh-hant", "開啟", "關閉"),
    ] {
        let language = Language::from_code(code).unwrap();
        assert_eq!(render(language, "On"), enabled, "{code}");
        assert_eq!(render(language, "Off"), disabled, "{code}");
        for (source, state) in [
            ("On — enforce", enabled),
            ("On — require", enabled),
            ("Off — skip", disabled),
            ("Off — bypass", disabled),
        ] {
            assert!(
                render(language, source).starts_with(&format!("{state} — ")),
                "{code}: {source}"
            );
            assert_eq!(english(source), source);
        }
    }
}
