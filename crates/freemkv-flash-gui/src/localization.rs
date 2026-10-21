//! Flash GUI localization. Catalogs and policy are owned by this application.

use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Language {
    Ca,
    Cs,
    Da,
    De,
    El,
    En,
    Es,
    Es419,
    Fi,
    Fr,
    Hu,
    Id,
    It,
    Ja,
    Ko,
    Nl,
    No,
    Pl,
    PtBr,
    Pt,
    Ro,
    Ru,
    Sk,
    Sv,
    Tr,
    Uk,
    Vi,
    ZhHans,
    ZhHant,
}

impl Language {
    pub const ALL: [Self; 29] = [
        Self::Ca,
        Self::Cs,
        Self::Da,
        Self::De,
        Self::El,
        Self::En,
        Self::Es,
        Self::Es419,
        Self::Fi,
        Self::Fr,
        Self::Hu,
        Self::Id,
        Self::It,
        Self::Ja,
        Self::Ko,
        Self::Nl,
        Self::No,
        Self::Pl,
        Self::PtBr,
        Self::Pt,
        Self::Ro,
        Self::Ru,
        Self::Sk,
        Self::Sv,
        Self::Tr,
        Self::Uk,
        Self::Vi,
        Self::ZhHans,
        Self::ZhHant,
    ];

    pub const fn code(self) -> &'static str {
        match self {
            Self::Ca => "ca",
            Self::Cs => "cs",
            Self::Da => "da",
            Self::De => "de",
            Self::El => "el",
            Self::En => "en",
            Self::Es => "es",
            Self::Es419 => "es-419",
            Self::Fi => "fi",
            Self::Fr => "fr",
            Self::Hu => "hu",
            Self::Id => "id",
            Self::It => "it",
            Self::Ja => "ja",
            Self::Ko => "ko",
            Self::Nl => "nl",
            Self::No => "no",
            Self::Pl => "pl",
            Self::PtBr => "pt-br",
            Self::Pt => "pt",
            Self::Ro => "ro",
            Self::Ru => "ru",
            Self::Sk => "sk",
            Self::Sv => "sv",
            Self::Tr => "tr",
            Self::Uk => "uk",
            Self::Vi => "vi",
            Self::ZhHans => "zh-hans",
            Self::ZhHant => "zh-hant",
        }
    }

    pub const fn native_name(self) -> &'static str {
        match self {
            Self::Ca => "Català",
            Self::Cs => "Čeština",
            Self::Da => "Dansk",
            Self::De => "Deutsch",
            Self::El => "Ελληνικά",
            Self::En => "English",
            Self::Es => "Español",
            Self::Es419 => "Español (Latinoamérica)",
            Self::Fi => "Suomi",
            Self::Fr => "Français",
            Self::Hu => "Magyar",
            Self::Id => "Bahasa Indonesia",
            Self::It => "Italiano",
            Self::Ja => "日本語",
            Self::Ko => "한국어",
            Self::Nl => "Nederlands",
            Self::No => "Norsk",
            Self::Pl => "Polski",
            Self::PtBr => "Português (Brasil)",
            Self::Pt => "Português",
            Self::Ro => "Română",
            Self::Ru => "Русский",
            Self::Sk => "Slovenčina",
            Self::Sv => "Svenska",
            Self::Tr => "Türkçe",
            Self::Uk => "Українська",
            Self::Vi => "Tiếng Việt",
            Self::ZhHans => "简体中文",
            Self::ZhHant => "繁體中文",
        }
    }

    pub fn from_code(code: &str) -> Option<Self> {
        let base = code
            .trim()
            .split(['.', '@'])
            .next()
            .unwrap_or_default()
            .replace('_', "-")
            .to_ascii_lowercase();
        let mut parts = base.split('-');
        let language = parts.next().unwrap_or_default();
        let region = parts.next().unwrap_or_default();
        let normalized = match language {
            "zh" => match region {
                "tw" | "hk" | "mo" | "hant" => "zh-hant",
                "hans" | "cn" | "sg" => "zh-hans",
                _ => return Some(Self::ZhHans),
            },
            "pt" if region == "br" => "pt-br",
            "es" if matches!(
                region,
                "419"
                    | "ar"
                    | "bo"
                    | "br"
                    | "bz"
                    | "cl"
                    | "co"
                    | "cr"
                    | "cu"
                    | "do"
                    | "ec"
                    | "gt"
                    | "hn"
                    | "mx"
                    | "ni"
                    | "pa"
                    | "pe"
                    | "pr"
                    | "py"
                    | "sv"
                    | "us"
                    | "uy"
                    | "ve"
            ) =>
            {
                "es-419"
            }
            "nb" | "nn" => "no",
            other => other,
        };
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.code() == normalized)
    }

    fn source(self) -> &'static str {
        match self {
            Self::Ca => include_str!("../locales/ca.json"),
            Self::Cs => include_str!("../locales/cs.json"),
            Self::Da => include_str!("../locales/da.json"),
            Self::De => include_str!("../locales/de.json"),
            Self::El => include_str!("../locales/el.json"),
            Self::En => include_str!("../locales/en.json"),
            Self::Es => include_str!("../locales/es.json"),
            Self::Es419 => include_str!("../locales/es-419.json"),
            Self::Fi => include_str!("../locales/fi.json"),
            Self::Fr => include_str!("../locales/fr.json"),
            Self::Hu => include_str!("../locales/hu.json"),
            Self::Id => include_str!("../locales/id.json"),
            Self::It => include_str!("../locales/it.json"),
            Self::Ja => include_str!("../locales/ja.json"),
            Self::Ko => include_str!("../locales/ko.json"),
            Self::Nl => include_str!("../locales/nl.json"),
            Self::No => include_str!("../locales/no.json"),
            Self::Pl => include_str!("../locales/pl.json"),
            Self::PtBr => include_str!("../locales/pt-br.json"),
            Self::Pt => include_str!("../locales/pt.json"),
            Self::Ro => include_str!("../locales/ro.json"),
            Self::Ru => include_str!("../locales/ru.json"),
            Self::Sk => include_str!("../locales/sk.json"),
            Self::Sv => include_str!("../locales/sv.json"),
            Self::Tr => include_str!("../locales/tr.json"),
            Self::Uk => include_str!("../locales/uk.json"),
            Self::Vi => include_str!("../locales/vi.json"),
            Self::ZhHans => include_str!("../locales/zh-hans.json"),
            Self::ZhHant => include_str!("../locales/zh-hant.json"),
        }
    }

    fn catalog(self) -> &'static Value {
        static CATALOGS: OnceLock<Vec<Value>> = OnceLock::new();
        let catalogs = CATALOGS.get_or_init(|| {
            Self::ALL
                .iter()
                .map(|language| {
                    serde_json::from_str(language.source()).unwrap_or_else(|error| {
                        panic!("invalid embedded {} catalog: {error}", language.code())
                    })
                })
                .collect()
        });
        &catalogs[Self::ALL
            .iter()
            .position(|language| *language == self)
            .expect("every language has an embedded catalog")]
    }
}

/// A user preference file, with an isolated mode for tests and the hardware-free GUI gate.
#[derive(Clone)]
pub enum Preferences {
    User(Option<PathBuf>),
    #[cfg(any(test, debug_assertions))]
    Memory,
}

impl Preferences {
    pub fn user() -> Self {
        Self::User(preference_path())
    }

    pub fn load(&self) -> Language {
        #[cfg(any(test, debug_assertions))]
        if matches!(self, Self::Memory) {
            return Language::En;
        }
        if let Self::User(Some(path)) = self {
            if let Ok(code) = fs::read_to_string(path) {
                if let Some(language) = Language::from_code(&code) {
                    return language;
                }
            }
        }
        for key in ["LC_ALL", "LC_MESSAGES", "LANG"] {
            if let Some(value) = std::env::var_os(key).and_then(|s| s.into_string().ok()) {
                if let Some(language) = Language::from_code(&value) {
                    return language;
                }
            }
        }
        Language::En
    }

    /// Replace a complete preference file atomically, keeping the previous choice on failure.
    pub fn save(&self, language: Language) -> std::io::Result<()> {
        #[cfg(any(test, debug_assertions))]
        if matches!(self, Self::Memory) {
            return Ok(());
        }
        let Self::User(Some(path)) = self else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "user configuration directory unavailable",
            ));
        };
        let parent = path
            .parent()
            .ok_or_else(|| std::io::Error::other("preference path has no parent"))?;
        fs::create_dir_all(parent)?;
        static SERIAL: AtomicU64 = AtomicU64::new(0);
        let temporary = parent.join(format!(
            ".language-{}-{}.tmp",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        let result = (|| {
            fs::write(&temporary, format!("{}\n", language.code()))?;
            fs::rename(&temporary, path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

/// Load the saved language, or use the process locale on first launch.
pub fn load_preference() -> Language {
    Preferences::user().load()
}

fn preference_path() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("LOCALAPPDATA")
            .or_else(|| std::env::var_os("APPDATA"))
            .map(PathBuf::from)
            .map(|base| base.join("freemkv").join("flash-gui").join("language"))
    }
    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|base| base.join("Library/Application Support/freemkv/flash-gui/language"))
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
            .map(|base| base.join("freemkv/flash-gui/language"))
    }
}

/// Resolve an app-owned message. Missing translations are programming errors.
pub fn text(language: Language, key: &str) -> String {
    get(language, key).to_owned()
}

pub fn get(language: Language, key: &str) -> &'static str {
    language.catalog()["messages"]
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| panic!("missing {} translation: {key}", language.code()))
}

pub fn is_message(value: &str) -> bool {
    Language::En.catalog()["messages"].get(value).is_some()
}

#[cfg(test)]
#[path = "localization_tests.rs"]
mod tests;
