//! The MT19xx AES-CMAC integrity table, re-exported from
//! [`mediatek_optical::image::cmac`] for `freemkv-fw` and the flash engine.

pub use mediatek_optical::image::cmac::*;

/// Reject overwritten table slots before an update or re-sign. The underlying
/// MAC verifier checks only flag `1`, so instruction bytes in an unused slot
/// can otherwise be ignored by the host but interpreted as active by a receiver.
/// Zero is accepted for explicitly disabled entries; erased slots are all ones.
pub fn validate_flags(image: &[u8]) -> anyhow::Result<()> {
    let entries = parse_table(image).map_err(|error| {
        anyhow::Error::new(error).context(crate::user_error::IssueCode::FirmwareInvalid)
    })?;
    for entry in entries {
        if !matches!(entry.enabled, 0 | 1 | u32::MAX) {
            return Err(anyhow::anyhow!(
                "integrity table entry {} has an unsupported flag word 0x{:08x}; table metadata may have been overwritten",
                entry.index, entry.enabled
            ).context(crate::user_error::IssueCode::FirmwareCorrupt));
        }
    }
    Ok(())
}
