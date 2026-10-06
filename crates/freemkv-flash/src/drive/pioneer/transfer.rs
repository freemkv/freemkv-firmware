//! Data-out framing shared by the traced Pioneer protocols.
//! Selection and envelope validation belong to the caller; this module does
//! not infer a protocol from an image's size, revision, or filename.

use super::{
    bdr212_generated_kernel_block, cdb_wb_flash_entry, cdb_wb_flash_finish, OemTransfer,
    TransferStage, CONTROL_LEN, FLASH_CHUNK,
};
use anyhow::{bail, Result};
use pioneer_optical::Role;
use std::borrow::Cow;

/// A Kernel and its explicitly selected transport framing.
pub enum KernelTransfer<'a> {
    /// Send the entire envelope to FE, starting at offset zero.
    LinearFe(&'a [u8]),
    /// Send the 0x1200-byte prefix to F0, then the generated block and the
    /// observed three slices to FE. The seed is supplied by the session.
    PrefixF0GeneratedFe {
        /// Original Kernel envelope, unchanged by generated-block construction.
        bytes: &'a [u8],
        /// Explicit seed for the updater's CRT random-byte generator.
        seed: u32,
    },
}

/// Select framing from decoded Kernel layout, never model, revision or length alone.
pub fn select_kernel(bytes: &[u8], seed: u32) -> Result<KernelTransfer<'_>> {
    let decoded = pioneer_optical::envelope::decode_envelope(bytes)
        .ok_or_else(|| anyhow::anyhow!("cannot determine Kernel transfer layout"))?;
    match decoded.info().layout {
        pioneer_optical::envelope::Layout::KernelFront => Ok(KernelTransfer::LinearFe(bytes)),
        pioneer_optical::envelope::Layout::KernelDerived => {
            Ok(KernelTransfer::PrefixF0GeneratedFe { bytes, seed })
        }
        other => bail!("unsupported Kernel transfer layout: {other:?}"),
    }
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
            KernelTransfer::PrefixF0GeneratedFe { bytes, .. } => {
                // These source slices and destination offsets are established
                // only for this framing. Do not silently truncate another size.
                if bytes.len() != 0x11200 {
                    bail!("prefix/generated Kernel framing requires 0x11200 bytes");
                }
            }
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
        Some(KernelTransfer::PrefixF0GeneratedFe { bytes, seed }) => {
            out.push(OemTransfer {
                stage: TransferStage::KernelPrefix,
                offset: 0,
                cdb: pioneer_optical::cdb::transfer(Role::Normal, 0, 0x1200),
                data: Cow::Borrowed(&bytes[..0x1200]),
            });
            out.push(OemTransfer {
                stage: TransferStage::KernelFe,
                offset: 0,
                cdb: pioneer_optical::cdb::transfer(Role::Kernel, 0, 0x200),
                data: Cow::Owned(bdr212_generated_kernel_block(seed).to_vec()),
            });
            for (destination, start, len) in [
                (0x1200, 0x200, 0x8000),
                (0x9200, 0x8200, 0x8000),
                (0x11200, 0x10200, 0x1000),
            ] {
                out.push(OemTransfer {
                    stage: TransferStage::KernelFe,
                    offset: destination,
                    cdb: pioneer_optical::cdb::transfer(Role::Kernel, destination, len as u32),
                    data: Cow::Borrowed(&bytes[start..start + len]),
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
