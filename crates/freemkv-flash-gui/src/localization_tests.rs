//! Catalog and language-switch contracts shared by every shell.

use super::*;
use std::collections::BTreeSet;

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
