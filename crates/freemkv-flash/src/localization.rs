//! Firmware utility UI catalogs and saved language preference. Diagnostics remain English.

use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

/// Supported UI languages; catalogs are embedded in the application.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Language {
    /// Ca UI catalog.
    Ca,
    /// Cs UI catalog.
    Cs,
    /// Da UI catalog.
    Da,
    /// De UI catalog.
    De,
    /// El UI catalog.
    El,
    /// En UI catalog.
    En,
    /// Es UI catalog.
    Es,
    /// Es419 UI catalog.
    Es419,
    /// Fi UI catalog.
    Fi,
    /// Fr UI catalog.
    Fr,
    /// Hu UI catalog.
    Hu,
    /// Id UI catalog.
    Id,
    /// It UI catalog.
    It,
    /// Ja UI catalog.
    Ja,
    /// Ko UI catalog.
    Ko,
    /// Nl UI catalog.
    Nl,
    /// No UI catalog.
    No,
    /// Pl UI catalog.
    Pl,
    /// PtBr UI catalog.
    PtBr,
    /// Pt UI catalog.
    Pt,
    /// Ro UI catalog.
    Ro,
    /// Ru UI catalog.
    Ru,
    /// Sk UI catalog.
    Sk,
    /// Sv UI catalog.
    Sv,
    /// Tr UI catalog.
    Tr,
    /// Uk UI catalog.
    Uk,
    /// Vi UI catalog.
    Vi,
    /// ZhHans UI catalog.
    ZhHans,
    /// ZhHant UI catalog.
    ZhHant,
}

impl Language {
    /// Every supported language, in display order.
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

    /// BCP-47 code used for the saved preference.
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

    /// Language name shown in its own script.
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

    /// Resolve a locale spelling to a supported language.
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

    /// Read the embedded catalog for translation audits.
    pub fn catalog(self) -> &'static Value {
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
    /// Persist the preference at this path; None reports unavailable storage.
    User(Option<PathBuf>),
    /// Memory UI catalog.
    /// An isolated English preference for tests and hardware-free previews.
    Memory,
}

impl Preferences {
    /// Use the saved per-user language preference.
    pub fn user() -> Self {
        Self::User(preference_path())
    }

    /// Read the saved preference, falling back to the process locale.
    pub fn load(&self) -> Language {
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

/// Resolve a required catalog entry; missing entries are programming errors.
pub fn get(language: Language, key: &str) -> &'static str {
    language.catalog()["messages"]
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| panic!("missing {} translation: {key}", language.code()))
}

/// Whether a string is an existing catalog message id.
pub fn is_message(value: &str) -> bool {
    Language::En.catalog()["messages"].get(value).is_some()
}

/// Preserve a message's identity and unlocalized arguments until it reaches a UI.
/// English diagnostics resolve the same value with [`english`].
pub fn message(key: &str, arguments: &[(&str, String)]) -> String {
    format!(
        "\u{1e}{}",
        serde_json::json!({"id": key, "arguments": arguments})
    )
}

/// Render a catalog message, leaving file paths, model names and other data intact.
pub fn render(language: Language, value: &str) -> String {
    if let Some(encoded) = value.strip_prefix('\u{1e}') {
        if let Ok(message) = serde_json::from_str::<Value>(encoded) {
            if let Some(id) = message["id"].as_str() {
                let mut result = text(language, id);
                if let Some(arguments) = message["arguments"].as_array() {
                    // Replace each source placeholder once, without treating inserted data
                    // as another template (paths can legitimately contain braces).
                    let replacements: Vec<_> = arguments
                        .iter()
                        .filter_map(|argument| {
                            Some((
                                argument[0].as_str()?,
                                render(language, argument[1].as_str()?),
                            ))
                        })
                        .collect();
                    let mut output = String::new();
                    while let Some(start) = result.find('{') {
                        output.push_str(&result[..start]);
                        let Some(end) = result[start..].find('}').map(|end| start + end) else {
                            output.push_str(&result[start..]);
                            result.clear();
                            break;
                        };
                        let key = &result[start + 1..end];
                        match replacements.iter().find(|(name, _)| *name == key) {
                            Some((_, value)) => output.push_str(value),
                            None => output.push_str(&result[start..=end]),
                        }
                        result = result[end + 1..].to_owned();
                    }
                    output.push_str(&result);
                    return output;
                }
                return result;
            }
        }
    }
    if is_message(value) {
        return text(language, value);
    }
    // Domain reports and CLI adapters retain English. Resolve their cataloged
    // presentation copy at the UI boundary while leaving unrecognized data intact.
    if let Some((id, _)) = Language::En.catalog()["messages"]
        .as_object()
        .unwrap()
        .iter()
        .find(|(_, english)| english.as_str() == Some(value))
    {
        return text(language, id);
    }
    // Older report providers return complete English sentences rather than ids.
    // Match the complete template, never replace words inside file paths/data.
    if language != Language::En {
        for (id, source) in Language::En.catalog()["messages"].as_object().unwrap() {
            let source = source.as_str().unwrap();
            if !id.starts_with("legacy.")
                && !(source.contains('{')
                    && source
                        .split('{')
                        .next()
                        .is_some_and(|prefix| prefix.len() >= 5 && prefix.contains(": ")))
            {
                continue;
            }
            if let Some(arguments) = template_arguments(source, value) {
                return render(
                    language,
                    &message(
                        id,
                        &arguments
                            .iter()
                            .map(|(key, value)| (key.as_str(), value.clone()))
                            .collect::<Vec<_>>(),
                    ),
                );
            }
        }
    }
    if language != Language::En {
        let messages = Language::En.catalog()["messages"].as_object().unwrap();
        let label_id = |label: &str| {
            messages.iter().find_map(|(id, source)| {
                source
                    .as_str()
                    .filter(|source| source.eq_ignore_ascii_case(label))
                    .map(|_| id.as_str())
            })
        };
        if let Some(label) = value
            .strip_prefix("== ")
            .and_then(|value| value.strip_suffix(" =="))
        {
            if let Some(id) = label_id(label) {
                return text(language, id);
            }
        }
        if let Some((label, data)) = value.split_once(": ") {
            if let Some(id) = label_id(label) {
                return format!("{}: {}", text(language, id), render(language, data));
            }
        }
    }
    value.to_owned()
}

fn template_arguments(template: &str, value: &str) -> Option<Vec<(String, String)>> {
    let mut template = template;
    let mut remaining = value;
    let mut arguments = Vec::new();
    while let Some(start) = template.find('{') {
        remaining = remaining.strip_prefix(&template[..start])?;
        let end = template[start..].find('}')? + start;
        let key = &template[start + 1..end];
        template = &template[end + 1..];
        let literal = template.split('{').next()?;
        if literal.is_empty() && template.contains('{') {
            return None;
        }
        let take = if literal.is_empty() {
            remaining.len()
        } else if key == "path" {
            remaining.rfind(literal)?
        } else {
            remaining.find(literal)?
        };
        arguments.push((key.to_owned(), remaining[..take].to_owned()));
        remaining = &remaining[take..];
    }
    (remaining == template).then_some(arguments)
}

/// Diagnostics are deliberately independent of the user's selected UI language.
pub fn english(value: &str) -> String {
    render(Language::En, value)
}

/// Keep saved support events independent of the selected display language.
pub fn english_json(value: Value) -> Value {
    match value {
        Value::String(value) => Value::String(english(&value)),
        Value::Array(values) => Value::Array(values.into_iter().map(english_json).collect()),
        Value::Object(values) => Value::Object(
            values
                .into_iter()
                .map(|(key, value)| (key, english_json(value)))
                .collect(),
        ),
        other => other,
    }
}
