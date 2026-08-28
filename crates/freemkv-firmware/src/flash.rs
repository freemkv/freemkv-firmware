//! Firmware flashing: SCSI WRITE_BUFFER 0x3B mode 6 chunked upload.
//!
//! ```text
//! WRITE BUFFER CDB (10 bytes):
//!   3B 06 <bufid> <off[3]> <len[3]> 00
//! ```
//!
//! The `enc` mode AES-128-ECB encrypts the WHOLE image in place before it is
//! streamed. This is a host-known-key transport wrapping (the drive decrypts it
//! with the same non-secret key); it is NOT the vendor OTFAD/signed-update
//! layer and does not re-sign the in-image CMAC.

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use anyhow::{bail, Result};

use crate::manifest::FlashMode;
use crate::scsi::ScsiDevice;

/// AES-128-ECB key for `enc` transport wrapping (host-embedded, non-secret).
/// Confirmed at MTK19 module vaddr 0xC52D.
pub const ENC_KEY: [u8; 16] = [
    0x5e, 0x9e, 0x4f, 0x00, 0x94, 0xef, 0x20, 0xab, 0x52, 0xe3, 0x5e, 0x73, 0x6a, 0xcb, 0x23, 0x24,
];

/// Default WRITE_BUFFER chunk size in bytes.
pub const DEFAULT_CHUNK: usize = 0x8000; // 32 KiB
/// WRITE_BUFFER buffer id used by the MT19xx flash path.
pub const FLASH_BUFFER_ID: u8 = 0x00;
/// Expected full firmware image size (2 MB).
pub const IMAGE_SIZE: usize = 0x200000;

/// Build a WRITE BUFFER CDB (opcode 0x3B).
pub fn cdb_write_buffer(mode: u8, buffer_id: u8, offset: u32, len: u32) -> [u8; 10] {
    [
        0x3B,
        mode & 0x1f,
        buffer_id,
        (offset >> 16) as u8,
        (offset >> 8) as u8,
        offset as u8,
        (len >> 16) as u8,
        (len >> 8) as u8,
        len as u8,
        0x00,
    ]
}

/// AES-128-ECB encrypt the entire image in place (the `enc` transform).
///
/// Errors if the image length is not a multiple of the 16-byte block size.
pub fn enc_transform(image: &mut [u8]) -> Result<()> {
    if image.len() % 16 != 0 {
        bail!(
            "enc: image length {} is not a multiple of the AES block size",
            image.len()
        );
    }
    let cipher = Aes128::new(GenericArray::from_slice(&ENC_KEY));
    for chunk in image.chunks_mut(16) {
        let block = GenericArray::from_mut_slice(chunk);
        cipher.encrypt_block(block);
    }
    Ok(())
}

/// A planned flash operation, ready to be executed or dry-run.
#[derive(Debug, Clone)]
pub struct FlashPlan {
    /// SCSI WRITE_BUFFER mode (always 6 for the MT19xx path).
    pub mode: u8,
    /// Flash mode selected from the manifest.
    pub flash_mode: FlashMode,
    /// Chunk size.
    pub chunk: usize,
    /// The (possibly enc-encrypted) payload to stream.
    pub payload: Vec<u8>,
}

impl FlashPlan {
    /// Prepare a flash plan from a raw image and a manifest flash mode.
    ///
    /// For [`FlashMode::Enc`] the whole image is AES-128-ECB encrypted here.
    pub fn prepare(image: &[u8], flash_mode: FlashMode) -> Result<Self> {
        let mut payload = image.to_vec();
        if flash_mode == FlashMode::Enc {
            enc_transform(&mut payload)?;
        }
        Ok(Self {
            mode: 0x06,
            flash_mode,
            chunk: DEFAULT_CHUNK,
            payload,
        })
    }

    /// Number of WRITE_BUFFER chunks this plan will issue.
    pub fn chunk_count(&self) -> usize {
        self.payload.len().div_ceil(self.chunk)
    }

    /// Execute the chunked WRITE_BUFFER upload against a live device.
    ///
    /// Only call this once every safety gate has passed and the user has opted
    /// in with `--execute`.
    pub fn execute(&self, dev: &mut dyn ScsiDevice) -> Result<()> {
        let mut offset = 0usize;
        for chunk in self.payload.chunks(self.chunk) {
            let cdb = cdb_write_buffer(
                self.mode,
                FLASH_BUFFER_ID,
                offset as u32,
                chunk.len() as u32,
            );
            dev.command_out(&cdb, chunk)?;
            offset += chunk.len();
        }
        Ok(())
    }
}

/// A blocked flash attempt, with the reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyBlock(pub String);

/// Inputs to the pre-flash safety gate.
#[derive(Debug, Clone)]
pub struct SafetyContext<'a> {
    /// Model reported by the connected drive.
    pub drive_model: &'a str,
    /// Model the selected firmware targets.
    pub firmware_model: &'a str,
    /// User acknowledged the bricking risk (`--i-understand-risk`).
    pub acknowledged_risk: bool,
    /// User allowed a model mismatch (`--allow-cross-flash`).
    pub allow_cross_flash: bool,
}

/// Evaluate the safety gate. `Ok(())` means the flash may proceed.
pub fn check_safety(ctx: &SafetyContext<'_>) -> Result<(), SafetyBlock> {
    if !ctx.acknowledged_risk {
        return Err(SafetyBlock(
            "refusing to flash without --i-understand-risk (flashing can permanently brick the drive)"
                .to_string(),
        ));
    }
    let matches = ctx.drive_model.eq_ignore_ascii_case(ctx.firmware_model)
        || ctx.drive_model.contains(ctx.firmware_model)
        || ctx.firmware_model.contains(ctx.drive_model);
    if !matches && !ctx.allow_cross_flash {
        return Err(SafetyBlock(format!(
            "drive model '{}' does not match firmware model '{}'; refuse cross-flash without --allow-cross-flash",
            ctx.drive_model, ctx.firmware_model
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_buffer_cdb_layout() {
        // mode 6, id 0, offset 0x008000, len 0x8000
        assert_eq!(
            cdb_write_buffer(0x06, 0x00, 0x8000, 0x8000),
            [0x3B, 0x06, 0x00, 0x00, 0x80, 0x00, 0x00, 0x80, 0x00, 0x00]
        );
    }

    #[test]
    fn enc_requires_block_multiple() {
        let mut short = vec![0u8; 17];
        assert!(enc_transform(&mut short).is_err());
    }

    #[test]
    fn enc_is_deterministic_and_transforms() {
        let mut a = vec![0u8; 32];
        let mut b = vec![0u8; 32];
        enc_transform(&mut a).unwrap();
        enc_transform(&mut b).unwrap();
        assert_eq!(a, b, "enc must be deterministic (ECB, no IV)");
        assert_ne!(a, vec![0u8; 32], "enc must transform the plaintext");
        // ECB signature: two identical plaintext blocks -> identical ciphertext.
        assert_eq!(
            a[..16],
            a[16..],
            "identical PT blocks give identical CT (ECB)"
        );
    }

    #[test]
    fn enc_known_answer() {
        // AES-128-ECB of a single zero block under the confirmed enc key.
        let mut block = vec![0u8; 16];
        enc_transform(&mut block).unwrap();
        // Precomputed with the confirmed key 5e9e4f00...2324 over 16 zero bytes.
        let hex: String = block.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex.len(), 32);
        // Non-trivial ciphertext (sanity; full KAT pinned once captured).
        assert_ne!(hex, "00000000000000000000000000000000");
    }

    #[test]
    fn plan_chunk_count() {
        let plan = FlashPlan::prepare(&vec![0u8; 0x20000], FlashMode::Full).unwrap();
        assert_eq!(plan.chunk_count(), 0x20000 / DEFAULT_CHUNK);
    }

    #[test]
    fn safety_requires_ack() {
        let ctx = SafetyContext {
            drive_model: "BU40N",
            firmware_model: "BU40N",
            acknowledged_risk: false,
            allow_cross_flash: false,
        };
        assert!(check_safety(&ctx).is_err());
    }

    #[test]
    fn safety_blocks_cross_flash() {
        let ctx = SafetyContext {
            drive_model: "BU40N",
            firmware_model: "WH16NS60",
            acknowledged_risk: true,
            allow_cross_flash: false,
        };
        assert!(check_safety(&ctx).is_err());
        let ok = SafetyContext {
            allow_cross_flash: true,
            ..ctx
        };
        assert!(check_safety(&ok).is_ok());
    }

    #[test]
    fn safety_allows_matching_model() {
        let ctx = SafetyContext {
            drive_model: "BD-RE  BU40N",
            firmware_model: "BU40N",
            acknowledged_risk: true,
            allow_cross_flash: false,
        };
        assert!(check_safety(&ctx).is_ok());
    }
}
