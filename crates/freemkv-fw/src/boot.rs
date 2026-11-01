//! Boot choices shared by the CLI, desktop form, and firmware emitters.

use crate::engine::{CreateReport, ModifyReport};
use anyhow::{bail, ensure, Result};

/// Public settings; deprecated wire slots remain an implementation detail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootFeature {
    Unrestricted,
    Hrl,
    Encryption,
    Speed,
    Region,
}

impl BootFeature {
    /// Stable display order for both front ends.
    pub const ALL: [Self; 5] = [
        Self::Unrestricted,
        Self::Hrl,
        Self::Encryption,
        Self::Speed,
        Self::Region,
    ];
    /// CLI spelling.
    pub fn key(self) -> &'static str {
        match self {
            Self::Unrestricted => "unrestricted",
            Self::Hrl => "hrl",
            Self::Encryption => "encryption",
            Self::Speed => "speed",
            Self::Region => "region",
        }
    }
    /// Desktop/report label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Unrestricted => "Unrestricted access",
            Self::Hrl => "HRL checking",
            Self::Encryption => "Encryption",
            Self::Speed => "Read speed",
            Self::Region => "Region",
        }
    }
    fn index(self) -> usize {
        self as usize
    }
    /// Only settings implemented by the emitted stubs are offered. Forced-region
    /// encodings are experimental, so they are deliberately not public choices.
    pub fn choices(self) -> &'static [(&'static str, &'static str, u8)] {
        match self {
            Self::Unrestricted => &[
                ("oem", "OEM behavior", 255),
                ("on", "On", 1),
                ("off", "Off", 0),
            ],
            Self::Hrl => &[
                ("oem", "OEM behavior", 255),
                ("on", "On — enforce", 1),
                ("off", "Off — skip", 0),
            ],
            Self::Encryption => &[
                ("oem", "OEM behavior", 255),
                ("on", "On — require", 1),
                ("off", "Off — bypass", 0),
            ],
            // These are the encodings consumed by build_speed_stub/build_region_stub.
            // Keep runtime commands and boot choices on the same wire values.
            Self::Speed => &[
                ("oem", "OEM behavior", 255),
                ("uncapped", "Uncapped", crate::abi::SPEED_MAX),
            ],
            Self::Region => &[
                ("oem", "OEM behavior", 255),
                ("free", "Region-free", crate::abi::REGION_FREE),
            ],
        }
    }
}

/// Complete firmware startup settings, plus explicit selections for validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootSettings {
    values: [u8; 5],
    explicit: u8,
}
impl Default for BootSettings {
    fn default() -> Self {
        Self::standard()
    }
}
impl BootSettings {
    /// Current shipping choices, also used by Reset to defaults.
    pub const fn standard() -> Self {
        Self {
            values: [1, 255, 255, 255, 255],
            explicit: 0,
        }
    }
    /// Parse repeated --default assignments, rejecting duplicates even via aliases.
    pub fn parse(assignments: &[String]) -> Result<Self> {
        let mut settings = Self::standard();
        for assignment in assignments {
            let (name, value) = assignment
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("expected FEATURE=VALUE, got {assignment:?}"))?;
            let name = if name == "enc" { "encryption" } else { name };
            let feature = BootFeature::ALL.into_iter().find(|f| f.key() == name)
                .ok_or_else(|| anyhow::anyhow!("unknown boot feature {name:?}; use unrestricted, hrl, encryption, speed or region"))?;
            ensure!(
                settings.explicit & (1 << feature.index()) == 0,
                "duplicate boot setting: {}",
                feature.key()
            );
            settings.set(feature, value)?;
        }
        Ok(settings)
    }
    /// Select one validated value; the form may change a selection repeatedly.
    pub fn set(&mut self, feature: BootFeature, value: &str) -> Result<()> {
        let value = if value == "passthrough" { "oem" } else { value };
        let choice = feature
            .choices()
            .iter()
            .find(|c| c.0 == value)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "invalid {} value {value:?}; use {}",
                    feature.key(),
                    feature
                        .choices()
                        .iter()
                        .map(|c| c.0)
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })?;
        self.values[feature.index()] = choice.2;
        self.explicit |= 1 << feature.index();
        Ok(())
    }
    /// Canonical CLI value.
    pub fn value(&self, feature: BootFeature) -> &'static str {
        self.choice(feature).0
    }
    /// Plain-language value including on/off polarity.
    pub fn label(&self, feature: BootFeature) -> &'static str {
        self.choice(feature).1
    }
    fn choice(&self, feature: BootFeature) -> &'static (&'static str, &'static str, u8) {
        feature
            .choices()
            .iter()
            .find(|c| c.2 == self.values[feature.index()])
            .expect("validated boot value")
    }
    /// Wire table. The legacy BD consumer must follow the public unrestricted choice.
    pub const fn flags(&self) -> [u8; 7] {
        [
            255,
            self.values[3],
            self.values[4],
            self.values[0],
            self.values[0],
            self.values[1],
            self.values[2],
        ]
    }
    /// Reject explicit choices which cannot be honored by this image.
    pub fn validate(&self, support: &BootSupport) -> Result<()> {
        for feature in BootFeature::ALL {
            if self.explicit & (1 << feature.index()) != 0
                && !support.supports_value(feature, self.values[feature.index()])
            {
                bail!(
                    "{}={} boot setting is not supported by this firmware",
                    feature.key(),
                    self.value(feature)
                );
            }
        }
        Ok(())
    }
    /// Add the full boot report to an existing JSON object.
    pub fn report_json(&self, support: &BootSupport, report: &str) -> String {
        let fields = BootFeature::ALL
            .into_iter()
            .map(|f| {
                format!(
                    "\"{}\":{{\"value\":\"{}\",\"supported\":{},\"choices\":[{}]}}",
                    f.key(),
                    self.value(f),
                    support.supports(f),
                    f.choices()
                        .iter()
                        .filter(|(_, _, v)| support.supports_value(f, *v))
                        .map(|(key, _, _)| format!("\"{key}\""))
                        .collect::<Vec<_>>()
                        .join(",")
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{},\"boot_settings\":{{{fields}}},\"boot_settings_applied\":{}}}",
            report
                .trim_end()
                .strip_suffix('}')
                .expect("JSON object report"),
            support.boot
        )
    }
}

/// Availability comes from emitted hooks, not the drive's marketing model.
#[derive(Clone, Debug, Default)]
pub struct BootSupport {
    pub(crate) boot: bool,
    mask: u8,
}
impl BootSupport {
    /// Whether this image can initialize settings at startup.
    pub fn has_boot(&self) -> bool {
        self.boot
    }
    /// Whether a particular setting is implemented.
    pub fn supports(&self, feature: BootFeature) -> bool {
        self.boot && self.mask & (1 << feature.index()) != 0
    }
    /// Whether this exact value is implemented, including partial On/OEM controls.
    pub fn supports_value(&self, feature: BootFeature, value: u8) -> bool {
        self.supports(feature)
            && feature.choices().iter().any(|choice| choice.2 == value)
            && !(feature == BootFeature::Unrestricted
                && value == 0
                && self.mask & LIMITED_UNRESTRICTED != 0)
    }
    /// Derive support from a strict build's actual emitted stubs.
    pub fn from_create(r: &CreateReport) -> Self {
        Self::from_facts(r.boot_stub_va != 0, |key| match key {
            "uhd_stub_va" => r.uhd_stub_va,
            "auth_cell_stub_va" => r.auth_cell_stub_va,
            "auth_cell_refusal" => u32::from(r.auth_cell_refusal),
            "uhd_conversion_count" => r.uhd_conversion_count,
            "bd_stub_va" => r.bd_stub_va,
            "hrl_stub_va" => r.hrl_stub_va,
            "ake_stub_va" => r.ake_stub_va,
            "speed_stub_va" => r.speed_stub_va,
            "region_stub_va" => r.region_stub_va,
            _ => 0,
        })
    }
    /// Derive support from a best-effort build's actual emitted stubs.
    pub fn from_modify(r: &ModifyReport) -> Self {
        let fact = |key: &str| {
            r.levers
                .iter()
                .flat_map(|l| &l.facts)
                .find(|(k, _)| *k == key)
                .map(|(_, v)| *v)
                .unwrap_or(0)
        };
        Self::from_facts(fact("boot_stub_va") != 0, fact)
    }
    fn from_facts(boot: bool, fact: impl Fn(&str) -> u32) -> Self {
        let refusal =
            (fact("uhd_stub_va") != 0 && fact("bd_stub_va") != 0) || fact("auth_cell_refusal") != 0;
        let widening = fact("auth_cell_stub_va") != 0 || fact("uhd_conversion_count") != 0;
        let supported = [
            refusal || widening,
            fact("hrl_stub_va") != 0,
            fact("ake_stub_va") != 0,
            fact("speed_stub_va") != 0,
            fact("region_stub_va") != 0,
        ];
        Self {
            boot,
            mask: supported
                .iter()
                .enumerate()
                .fold(0, |mask, (i, yes)| mask | (u8::from(*yes) << i))
                | if widening && !refusal {
                    LIMITED_UNRESTRICTED
                } else {
                    0
                },
        }
    }
}

#[cfg(test)]
#[path = "boot_tests.rs"]
mod tests;

const RECORD_MAGIC: &[u8; 16] = b"freemkv.boot.v1\0";
const RECORD_MAGIC_V2: &[u8; 16] = b"freemkv.boot.v2\0";
const RECORD_MAGIC_V3: &[u8; 16] = b"freemkv.boot.v3\0";
const LIMITED_UNRESTRICTED: u8 = 1 << 5;
const RECORD_LEN: usize = 36;

/// Versioned defaults: v1/v2 retain three instruction runs. v3 shares the
/// handler defaults body between explicit reset and the never-saved fallback.
struct Record {
    offset: usize,
    settings: BootSettings,
    support: BootSupport,
    sites: [usize; 3],
    shared_reset: bool,
}

fn stores(flags: &[u8; 7], base_register: u16) -> Vec<u8> {
    flags
        .iter()
        .enumerate()
        .flat_map(|(offset, value)| {
            let mov = 0x2100 | u16::from(*value);
            let store = 0x7001 | (offset as u16) << 6 | base_register << 3;
            [mov.to_le_bytes(), store.to_le_bytes()].concat()
        })
        .collect()
}

fn read_record(image: &[u8]) -> Result<Option<Record>> {
    let locations: Vec<_> = image
        .windows(RECORD_MAGIC.len())
        .enumerate()
        .filter(|(_, w)| *w == RECORD_MAGIC || *w == RECORD_MAGIC_V2 || *w == RECORD_MAGIC_V3)
        .map(|(i, _)| i)
        .collect();
    if locations.is_empty() {
        return Ok(None);
    }
    ensure!(locations.len() == 1, "ambiguous boot settings records");
    let offset = locations[0];
    let bytes = image
        .get(offset..offset + RECORD_LEN)
        .ok_or_else(|| anyhow::anyhow!("truncated boot settings record"))?;
    let flags: [u8; 7] = bytes[16..23].try_into()?;
    let settings = BootSettings {
        values: [flags[3], flags[5], flags[6], flags[1], flags[2]],
        explicit: 0,
    };
    ensure!(flags == settings.flags(), "invalid boot settings table");
    for f in BootFeature::ALL {
        ensure!(
            f.choices()
                .iter()
                .any(|c| c.2 == settings.values[f.index()]),
            "unsupported stored {} value",
            f.key()
        );
    }
    let shared_reset = &bytes[..16] == RECORD_MAGIC_V3;
    let allowed_mask = if &bytes[..16] == RECORD_MAGIC_V2 || shared_reset {
        63
    } else {
        31
    };
    ensure!(
        bytes[23] & !allowed_mask == 0,
        "invalid boot capability record"
    );
    if bytes[23] & LIMITED_UNRESTRICTED != 0 {
        ensure!(
            bytes[23] & 1 != 0 && flags[3] != 0,
            "invalid partial Unrestricted capability"
        );
    }
    let mut sites = [0; 3];
    for (i, site) in sites.iter_mut().enumerate() {
        *site = u32::from_le_bytes(bytes[24 + i * 4..28 + i * 4].try_into()?) as usize;
        if shared_reset && i == 2 {
            ensure!(
                *site == 0,
                "shared reset record must have an empty third site"
            );
            continue;
        }
        let expected = stores(&flags, if i == 2 { 6 } else { 0 });
        ensure!(
            *site % 2 == 0
                && image.get(*site..site.saturating_add(expected.len()))
                    == Some(expected.as_slice()),
            "boot settings instruction record does not match firmware"
        );
        ensure!(
            *site + expected.len() <= offset || *site >= offset + RECORD_LEN,
            "boot settings record overlaps instructions"
        );
    }
    let site_count = if shared_reset { 2 } else { 3 };
    for i in 0..site_count {
        for j in i + 1..site_count {
            ensure!(
                sites[i].abs_diff(sites[j]) >= 28,
                "overlapping boot settings instructions"
            );
        }
    }
    Ok(Some(Record {
        offset,
        settings,
        support: BootSupport {
            boot: true,
            mask: bytes[23],
        },
        sites,
        shared_reset,
    }))
}

/// Read settings only from a recognized, integrity-checked image format.
pub fn inspect(image: &[u8]) -> Result<Option<(BootSettings, BootSupport)>> {
    let Some(record) = read_record(image)? else {
        return Ok(None);
    };
    verify(image)?;
    Ok(Some((record.settings, record.support)))
}

fn verify(image: &[u8]) -> Result<()> {
    use crate::scheme::IntegrityScheme;
    let verdicts = crate::scheme::MtkCmac.verify(image)?;
    ensure!(
        !verdicts.is_empty() && verdicts.iter().all(|v| v.ok),
        "firmware integrity verification failed"
    );
    Ok(())
}

/// Update a known image in place without reinjecting any hooks.
pub(crate) fn update(
    image: &[u8],
    defaults: &BootSettings,
) -> Result<Option<(Vec<u8>, BootSupport)>> {
    let Some(record) = read_record(image)? else {
        return Ok(None);
    };
    verify(image)?;
    defaults.validate(&record.support)?;
    let mut output = image.to_vec();
    for (i, site) in record.sites.iter().enumerate() {
        if record.shared_reset && i == 2 {
            continue;
        }
        let bytes = stores(&defaults.flags(), if i == 2 { 6 } else { 0 });
        output[*site..*site + bytes.len()].copy_from_slice(&bytes);
    }
    output[record.offset + 16..record.offset + 23].copy_from_slice(&defaults.flags());
    let output = freemkv_flash::cmac::resign(&output)?;
    verify(&output)?;
    Ok(Some((output, record.support)))
}

/// Attach a record only after proving the emitted boot/reset instructions.
pub(crate) fn attach(
    image: &mut Vec<u8>,
    handler: usize,
    handler_len: usize,
    boot: usize,
    defaults: &BootSettings,
    support: &BootSupport,
) -> Result<()> {
    if !support.boot {
        return Ok(());
    }
    let flags = defaults.flags();
    let find = |start: usize, end: usize, register: u16| -> Result<usize> {
        let needle = stores(&flags, register);
        let span = image
            .get(start..end)
            .ok_or_else(|| anyhow::anyhow!("invalid boot settings code span"))?;
        let hits: Vec<_> = span
            .windows(needle.len())
            .enumerate()
            .filter(|(_, w)| *w == needle)
            .map(|(i, _)| start + i)
            .collect();
        ensure!(
            hits.len() == 1,
            "expected one boot settings instruction run, found {}",
            hits.len()
        );
        Ok(hits[0])
    };
    let boot_site = find(boot, boot + 64, 0)?;
    let defaults_site = find(handler, handler.saturating_add(handler_len), 0)?;
    let handler_end = handler
        .checked_add(handler_len)
        .filter(|end| *end <= image.len())
        .ok_or_else(|| anyhow::anyhow!("invalid handler span"))?;
    let flash_needle = stores(&flags, 6);
    let fallback_hits: Vec<_> = image[handler..handler_end]
        .windows(flash_needle.len())
        .enumerate()
        .filter(|(_, bytes)| *bytes == flash_needle)
        .map(|(offset, _)| handler + offset)
        .collect();
    ensure!(
        fallback_hits.len() <= 1,
        "ambiguous reset-to-flash defaults"
    );
    let shared_reset = fallback_hits.is_empty();
    if shared_reset {
        // Prove the compact handler actually branches into the shared defaults
        // body; absence of a second store run alone is not evidence of reuse.
        let shared_entry = defaults_site
            .checked_sub(2)
            .ok_or_else(|| anyhow::anyhow!("invalid shared defaults site"))?;
        let calls = (handler..handler_end.saturating_sub(1))
            .step_by(2)
            .filter(|site| {
                thumb_asm::isa::decode_at(image, *site).is_some_and(|instruction| {
                    instruction.branch_target() == Some(shared_entry as u32)
                        && instruction.is_branch()
                })
            })
            .count();
        ensure!(
            calls == 1,
            "shared reset fallback branch was not uniquely proven"
        );
    }
    let sites = [
        boot_site,
        defaults_site,
        fallback_hits.first().copied().unwrap_or(0),
    ];
    // This serialization has an exact length; it has no assembler literal pool
    // or expanding branch encodings requiring the code emitters' extra headroom.
    let offset = crate::engine::mt1959::Mt1959Engine.free_space(image, RECORD_LEN)? as usize;
    let mut record = if shared_reset {
        RECORD_MAGIC_V3.to_vec()
    } else if support.mask & LIMITED_UNRESTRICTED != 0 {
        RECORD_MAGIC_V2.to_vec()
    } else {
        RECORD_MAGIC.to_vec()
    };
    record.extend_from_slice(&flags);
    record.push(support.mask);
    for site in sites {
        record.extend_from_slice(&(site as u32).to_le_bytes());
    }
    image[offset..offset + record.len()].copy_from_slice(&record);
    *image = freemkv_flash::cmac::resign(image)?;
    inspect(image)?.ok_or_else(|| anyhow::anyhow!("missing boot settings after signing"))?;
    Ok(())
}
