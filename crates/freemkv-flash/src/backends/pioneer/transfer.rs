//! Data-out framing shared by the traced Pioneer protocols.
//! Selection and envelope validation belong to the caller; this module does
//! not infer a protocol from an image's size, revision, or filename.

use super::{
    cdb_wb_flash_entry, cdb_wb_flash_finish, OemTransfer, TransferStage, CONTROL_LEN, FLASH_CHUNK,
};
use anyhow::{bail, Result};
use pioneer_optical::Role;
use std::borrow::Cow;

/// A Kernel and its explicitly selected transport framing.
pub enum KernelTransfer<'a> {
    /// Send the entire envelope to FE, starting at offset zero.
    LinearFe(&'a [u8]),
    /// Canonical front-key bytes prepared by the envelope codec.
    PreparedFe(Vec<u8>),
}

/// Prepare the receiver representation through the library's envelope codec.
pub fn select_kernel(bytes: &[u8]) -> Result<KernelTransfer<'_>> {
    let decoded = pioneer_optical::envelope::Envelope::load(bytes)?;
    let prepared = decoded.kernel_transfer_image().ok_or_else(|| {
        anyhow::anyhow!(
            "Kernel transfer representation unavailable for {}",
            decoded.info().layout
        )
    })?;
    Ok(KernelTransfer::PreparedFe(prepared))
}

/// Build the data-out portion of a session that requires entry. No device I/O,
/// retry, polling, model lookup, or claim of drive acceptance occurs here.
pub fn data_out<'a>(
    control: &[u8; CONTROL_LEN],
    normal: &'a [u8],
    kernel: Option<KernelTransfer<'a>>,
) -> Result<Vec<OemTransfer<'a>>> {
    check_span(normal)?;
    if let Some(ref component) = kernel {
        match component {
            KernelTransfer::LinearFe(bytes) => check_span(bytes)?,
            KernelTransfer::PreparedFe(bytes) => check_span(bytes)?,
        }
    }
    let mut out = vec![OemTransfer {
        stage: TransferStage::Entry,
        offset: 0,
        cdb: cdb_wb_flash_entry(),
        data: Cow::Owned(control.to_vec()),
    }];
    match kernel {
        None => {}
        Some(KernelTransfer::LinearFe(bytes)) => {
            chunks(&mut out, TransferStage::KernelFe, bytes);
        }
        Some(KernelTransfer::PreparedFe(bytes)) => {
            for (index, data) in bytes.chunks(FLASH_CHUNK).enumerate() {
                let offset = (index * FLASH_CHUNK) as u32;
                out.push(OemTransfer {
                    stage: TransferStage::KernelFe,
                    offset,
                    cdb: pioneer_optical::cdb::transfer(Role::Kernel, offset, data.len() as u32),
                    data: Cow::Owned(data.to_vec()),
                });
            }
        }
    }
    chunks(&mut out, TransferStage::Normal, normal);
    out.push(OemTransfer {
        stage: TransferStage::Finish,
        offset: 0,
        cdb: cdb_wb_flash_finish(),
        data: Cow::Owned(control.to_vec()),
    });
    Ok(out)
}

fn check_span(bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() > 0x100_0000 {
        bail!("empty image or image exceeds the 24-bit WRITE BUFFER address space");
    }
    Ok(())
}

/// Chunk `bytes` into `FLASH_CHUNK` transfers for `stage` (Kernel -> FE, Normal -> F0).
fn chunks<'a>(out: &mut Vec<OemTransfer<'a>>, stage: TransferStage, bytes: &'a [u8]) {
    let role = match stage {
        TransferStage::KernelFe => Role::Kernel,
        _ => Role::Normal,
    };
    for (index, data) in bytes.chunks(FLASH_CHUNK).enumerate() {
        out.push(OemTransfer {
            stage,
            offset: (index * FLASH_CHUNK) as u32,
            cdb: pioneer_optical::cdb::transfer(
                role,
                (index * FLASH_CHUNK) as u32,
                data.len() as u32,
            ),
            data: Cow::Borrowed(data),
        });
    }
}

#[cfg(test)]
#[path = "transfer_tests.rs"]
mod tests;
