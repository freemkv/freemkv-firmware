//! Informational recognition of legacy and unsupported firmware formats.
//! These signatures never claim a protocol backend or authorize a write.
use crate::style;
use anyhow::Result;
/// Historical vendor recipes, retained for offline reports and API compatibility.
pub mod flashset;
/// Legacy image signatures and labels.
pub mod imageid;

pub(crate) fn family(bytes: &[u8]) -> Option<&'static str> {
    let id = imageid::identify(bytes);
    (id.family != imageid::ImageFamily::Unknown).then(|| id.family.label())
}

pub(crate) fn describe(bytes: &[u8], require_recognized: bool) -> Result<()> {
    let id = imageid::identify(bytes);
    anyhow::ensure!(
        !require_recognized || id.family != imageid::ImageFamily::Unknown,
        anyhow::anyhow!("selected file has no recognized firmware format")
            .context(crate::user_error::IssueCode::FirmwareInvalid)
    );
    describe_identity(&id)
}

pub(super) fn describe_identity(id: &imageid::ImageIdentity) -> Result<()> {
    use imageid::ImageFamily;
    if id.family == ImageFamily::Unknown {
        println!(
            "{}",
            style::kv(
                "image",
                &style::amber(
                    "unrecognized — no known drive-family signature (truncated, packed, or an \
                     unsupported family)"
                )
            )
        );
        return Ok(());
    }
    println!("{}", style::kv("family", id.family.label()));
    let model = id.model.as_deref().unwrap_or("unknown (not in image)");
    let rev = id.rev.as_deref().unwrap_or("unknown");
    println!(
        "{}",
        style::kv("descriptor", &format!("model='{model}' rev='{rev}'"))
    );
    if let Some(note) = &id.note {
        println!("{}", style::dim_line(&format!("          {note}")));
    }
    println!("{}", style::kv("flash", &id.family.flash_summary()));
    println!(
        "{}",
        style::kv(
            "integrity",
            &style::amber("not applicable (this family has no MT19xx-style signed CMAC table)")
        )
    );
    Ok(())
}
