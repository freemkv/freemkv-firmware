//! Data-out framing shared by the traced Pioneer protocols.
//! Selection and envelope validation belong to the caller; this module does
//! not infer a protocol from an image's size, revision, or filename.

use super::{
    bdr212_generated_kernel_block, cdb_wb_flash_entry, cdb_wb_flash_finish, OemTransfer,
    TransferStage, CONTROL_LEN, FLASH_CHUNK,
};
use anyhow::{bail, Result};
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
                cdb: pioneer_optical::transfer_normal(0, 0x1200),
                data: Cow::Borrowed(&bytes[..0x1200]),
            });
            out.push(OemTransfer {
                stage: TransferStage::KernelFe,
                cdb: pioneer_optical::transfer_kernel(0, 0x200),
                data: Cow::Owned(bdr212_generated_kernel_block(seed).to_vec()),
            });
            for (destination, start, len) in [
                (0x1200, 0x200, 0x8000),
                (0x9200, 0x8200, 0x8000),
                (0x11200, 0x10200, 0x1000),
            ] {
                out.push(OemTransfer {
                    stage: TransferStage::KernelFe,
                    cdb: pioneer_optical::transfer_kernel(destination, len as u32),
                    data: Cow::Borrowed(&bytes[start..start + len]),
                });
            }
        }
    }
    chunks(&mut out, TransferStage::Normal, normal);
    out.push(OemTransfer {
        stage: TransferStage::Finish,
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
    let cdb_for = match stage {
        TransferStage::KernelFe => pioneer_optical::transfer_kernel,
        _ => pioneer_optical::transfer_normal,
    };
    for (index, data) in bytes.chunks(FLASH_CHUNK).enumerate() {
        out.push(OemTransfer {
            stage,
            cdb: cdb_for((index * FLASH_CHUNK) as u32, data.len() as u32),
            data: Cow::Borrowed(data),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linear_chunks_preserve_all_bytes_and_encode_final_fragment() {
        for len in [1, 0x7fff, 0x8000, 0x8001, 0x10000, 0x11200] {
            let bytes: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let steps = data_out(&[0xA5; 256], &bytes, None).unwrap();
            let writes = &steps[1..steps.len() - 1];
            let joined: Vec<u8> = writes.iter().flat_map(|w| w.data.iter().copied()).collect();
            assert_eq!(joined, bytes);
            let last = writes.last().unwrap();
            let off = (len - 1) / 0x8000 * 0x8000;
            let tail = len - off;
            assert_eq!(
                last.cdb,
                [
                    0x3B,
                    7,
                    0xF0,
                    (off >> 16) as u8,
                    (off >> 8) as u8,
                    off as u8,
                    0,
                    (tail >> 8) as u8,
                    tail as u8,
                    0
                ]
            );
            assert_eq!(steps.first().unwrap().data.as_ref(), &[0xA5; 256]);
            assert_eq!(steps.last().unwrap().data.as_ref(), &[0xA5; 256]);
        }
    }

    #[test]
    fn same_kernel_size_does_not_select_a_strategy() {
        let kernel: Vec<u8> = (0..0x11200).map(|i| (i % 251) as u8).collect();
        let normal = [0x33; 0x101];
        let linear = data_out(&[0; 256], &normal, Some(KernelTransfer::LinearFe(&kernel))).unwrap();
        let generated = data_out(
            &[0; 256],
            &normal,
            Some(KernelTransfer::PrefixF0GeneratedFe {
                bytes: &kernel,
                seed: 1,
            }),
        )
        .unwrap();
        assert_eq!(linear.len(), 6); // entry, three FE, Normal, finish
        assert_eq!(generated.len(), 8); // entry, F0 prefix, four FE, Normal, finish
        assert_eq!(linear[1].cdb, [0x3B, 7, 0xFE, 0, 0, 0, 0, 0x80, 0, 0]);
        assert_eq!(generated[1].cdb, [0x3B, 7, 0xF0, 0, 0, 0, 0, 0x12, 0, 0]);
        assert_eq!(generated[3].data.as_ref(), &kernel[0x200..0x8200]);
        assert_eq!(generated[5].data.as_ref(), &kernel[0x10200..0x11200]);
        assert_eq!(kernel[0], 0); // input retained, never overwritten with generated data
    }

    #[test]
    fn invalid_spans_are_rejected_before_materialization() {
        assert!(data_out(&[0; 256], &[], None).is_err());
        assert!(data_out(&[0; 256], &[1], Some(KernelTransfer::LinearFe(&[]))).is_err());
        for size in [0, 0x111ff, 0x11201] {
            let kernel = vec![0; size];
            assert!(data_out(
                &[0; 256],
                &[1],
                Some(KernelTransfer::PrefixF0GeneratedFe {
                    bytes: &kernel,
                    seed: 0,
                })
            )
            .is_err());
        }
        let too_large = vec![0; 0x100_0001];
        assert!(data_out(&[0; 256], &too_large, None).is_err());
        assert!(data_out(&[0; 256], &[1], Some(KernelTransfer::LinearFe(&too_large))).is_err());
    }
}
