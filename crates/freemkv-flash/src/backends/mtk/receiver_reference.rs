//! Receiver analysis from an explicit current image, never target readback.
//! The protocol crate still recognizes the actual encoding and entry grammars.
//! Reference reads stop before the first session command, including PROBE.
use anyhow::{anyhow, ensure, Context, Result};
use mediatek_optical::{
    cdb,
    drive::{self, Transport},
    envelope::Envelope,
    layout, receiver,
};
use std::cell::Cell;

/// Confirm application startup without claiming full protected readback.
pub(super) fn confirm_started(
    dev: &mut dyn crate::platform::ScsiDevice,
    image: &[u8],
) -> Result<()> {
    let inquiry = dev.command_in(&cdb::inquiry(36), 36)?;
    let descriptor = dev.command_in(
        &cdb::read_memory(
            layout::DESCRIPTOR.start as u32,
            layout::DESCRIPTOR.len as u32,
        ),
        layout::DESCRIPTOR.len,
    )?;
    let expected = layout::DESCRIPTOR
        .of(image)
        .context("target descriptor missing")?;
    ensure!(
        inquiry.len() == 36
            && inquiry[8..36] == expected[..28]
            && &inquiry[32..36] != b"BOOT"
            && descriptor.len() == layout::DESCRIPTOR.len
            && descriptor[..0x58] == expected[..0x58],
        "requested firmware startup was not confirmed by live INQUIRY and build metadata"
    );
    Ok(())
}

pub(super) fn limited_verification(error: &str) {
    crate::diagnostics::record(format!("MediaTek limited verification: {error}; target application INQUIRY and build metadata confirmed; protected firmware readback remains incomplete"));
    crate::output::field("Verification warning", "Target firmware is running, but protected code could not be fully read back. Full byte-for-byte verification was NOT completed.");
}

#[derive(Clone)]
pub(super) struct Reference {
    image: Vec<u8>,
    inquiry: Vec<u8>,
    banner: Vec<u8>,
    descriptor: Vec<u8>,
}

impl Reference {
    pub(super) fn image(&self) -> &[u8] {
        &self.image
    }
    pub(super) fn bind<T: Transport<Error = anyhow::Error>>(
        t: &mut T,
        input: &[u8],
    ) -> Result<Self> {
        let image = Envelope::load(input)
            .context("invalid Current MediaTek image")?
            .image()
            .to_vec();
        let mode = receiver::detect_mode(t).map_err(|e| anyhow!("{e}"))?;
        ensure!(
            mode.mode() == receiver::Mode::Firmware,
            "Current-file receiver fallback requires running application firmware, not BOOT"
        );
        let mut banner = vec![0; layout::BANNER.len];
        drive::read_memory(t, layout::BANNER.start as u32, &mut banner)
            .map_err(|e| anyhow!("{e}"))?;
        let mut descriptor = vec![0; layout::DESCRIPTOR.len];
        drive::read_memory(t, layout::DESCRIPTOR.start as u32, &mut descriptor)
            .map_err(|e| anyhow!("{e}"))?;
        ensure!(mode.inquiry()[8..36] == image[layout::DESCRIPTOR.start..layout::DESCRIPTOR.start + 28]
            && banner[..16] == layout::BANNER.of(&image).expect("validated image")[..16]
            && descriptor[..0x58] == image[layout::DESCRIPTOR.start..layout::DESCRIPTOR.start + 0x58],
            "Current firmware does not match the running drive's identity, boot banner and build metadata. Select the firmware currently running (for BH16NS40 INTM, select intermediate.bin), not the original or target firmware");
        crate::diagnostics::record(format!("MediaTek receiver source: explicit Current image sha256={}; live INQUIRY, banner and build metadata match; code analysis is file-derived, not a full live-image verification", crate::mediatek_package::digest(&image)));
        Ok(Self {
            image,
            inquiry: mode.inquiry().to_vec(),
            banner,
            descriptor,
        })
    }

    pub(super) fn revalidate<T: Transport<Error = anyhow::Error>>(&self, t: &mut T) -> Result<()> {
        let current = Self::bind(t, &self.image)?;
        ensure!(
            current.inquiry[8..36] == self.inquiry[8..36]
                && current.banner == self.banner
                && current.descriptor[..0x58] == self.descriptor[..0x58],
            "Current receiver changed before writing; re-plan the operation"
        );
        Ok(())
    }
}

pub(super) fn detect(
    dev: &mut crate::backend::ReadDevice<'_>,
    input: &[u8],
) -> Result<(receiver::Receiver, Reference)> {
    let shared = crate::transport::SharedDevice::new(dev);
    let mut live = crate::transport::ScsiTransport::reads(&shared);
    let reference = Reference::bind(&mut live, input)?;
    let analysis = Cell::new(true);
    let mut reads = crate::transport::ScsiTransport::reads(&shared)
        .receiver_source(Some(reference.image()), &analysis);
    let mode = receiver::detect_mode(&mut reads).map_err(|e| anyhow!("{e}"))?;
    let receiver = receiver::detect(&mut reads, &mode)
        .map_err(|e| anyhow!("Current image receiver analysis failed: {e}"))?;
    reference.revalidate(&mut live)?;
    Ok((receiver, reference))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{ScsiTransport, SharedDevice};
    use mediatek_optical::drive::Data;
    impl crate::platform::ScsiDevice for Restricted {
        fn command_in(&mut self, command: &[u8], len: usize) -> Result<Vec<u8>> {
            let mut bytes = vec![0; len];
            let n = Transport::exec(self, command, Data::In(&mut bytes))?;
            bytes.truncate(n);
            Ok(bytes)
        }
        fn command_out(&mut self, command: &[u8], bytes: &[u8]) -> Result<()> {
            Transport::exec(self, command, Data::Out(bytes)).map(|_| ())
        }
        fn describe(&self) -> String {
            "restricted fixture".into()
        }
    }
    fn detect_device(
        live: &mut Restricted,
        input: &[u8],
    ) -> Result<(receiver::Receiver, Reference)> {
        detect(
            &mut crate::backend::ReadDevice::without_unlocks(live),
            input,
        )
    }
    struct Restricted {
        image: Vec<u8>,
        writes: usize,
    }
    impl Transport for Restricted {
        type Error = anyhow::Error;
        fn sense(&self) -> Option<(u8, u8, u8)> {
            None
        }
        fn exec(&mut self, command: &[u8], data: Data<'_>) -> Result<usize> {
            let Data::In(buf) = data else {
                self.writes += 1;
                anyhow::bail!("write rejected")
            };
            if command.first() == cdb::inquiry(36).first() {
                let mut inquiry = [0; 36];
                inquiry[0] = 5;
                inquiry[4] = 31;
                inquiry[8..36].copy_from_slice(
                    &self.image[layout::DESCRIPTOR.start..layout::DESCRIPTOR.start + 28],
                );
                buf.copy_from_slice(&inquiry);
                return Ok(buf.len());
            }
            ensure!(
                command[..3] == cdb::read_memory(0, 0)[..3],
                "unexpected command"
            );
            let off =
                ((command[3] as usize) << 16) | ((command[4] as usize) << 8) | command[5] as usize;
            let end = off + buf.len();
            ensure!(
                [
                    (0x3000, 0x3020),
                    (0x1ec000, 0x1ec100),
                    (0x1e84e4, 0x1e85e4),
                    (0x1f0000, 0x200000)
                ]
                .iter()
                .any(|&(lo, hi)| off >= lo && off < hi && end <= hi),
                "restricted read at {off:#x}"
            );
            buf.copy_from_slice(&self.image[off..end]);
            Ok(buf.len())
        }
    }
    fn image() -> Vec<u8> {
        let mut bytes = super::super::fixture::image(&super::super::fixture::BU3, "BD-RE BU40N", 1);
        bytes[layout::DESCRIPTOR.start + 24..layout::DESCRIPTOR.start + 28]
            .copy_from_slice(b"INTM");
        mediatek_optical::image::cmac::resign(&bytes).unwrap()
    }
    #[test]
    fn restricted_current_file_supports_full_receiver_analysis_without_writes() {
        let image = image();
        let mut live = Restricted {
            image: image.clone(),
            writes: 0,
        };
        let mode = receiver::detect_mode(&mut live).unwrap();
        assert!(matches!(
            receiver::detect(&mut live, &mode),
            Err(receiver::Error::Unknown)
        ));
        let (receiver, _) = detect_device(&mut live, &image).unwrap();
        assert_eq!(receiver.encoding(), receiver::Encoding::Plaintext);
        assert!(receiver.prepare_command().is_some());
        assert_eq!(live.writes, 0);
    }
    #[test]
    fn stale_current_reference_is_rejected_and_revalidated() {
        let image = image();
        let mut live = Restricted {
            image: image.clone(),
            writes: 0,
        };
        let reference = Reference::bind(&mut live, &image).unwrap();
        live.image[layout::DESCRIPTOR.start + 24..layout::DESCRIPTOR.start + 28]
            .copy_from_slice(b"1.V1");
        assert!(reference
            .revalidate(&mut live)
            .unwrap_err()
            .to_string()
            .contains("does not match"));
        assert!(detect_device(&mut live, &image).is_err());
        assert_eq!(live.writes, 0);
    }
    #[test]
    fn retained_compatible_boot_code_is_not_confused_with_application_identity() {
        let image = image();
        let mut live = Restricted {
            image: image.clone(),
            writes: 0,
        };
        live.image[0x3014] ^= 1;
        let reference = Reference::bind(&mut live, &image).unwrap();
        reference.revalidate(&mut live).unwrap();
        live.image[0x3014] ^= 2;
        assert!(
            reference.revalidate(&mut live).is_err(),
            "the actual live boot snapshot must remain unchanged"
        );
    }
    #[test]
    fn limited_verification_requires_actual_target_startup_and_build_metadata() {
        let target = image();
        let mut live = Restricted {
            image: target.clone(),
            writes: 0,
        };
        confirm_started(&mut live, &target).unwrap();
        live.image[layout::DESCRIPTOR.start + 24..layout::DESCRIPTOR.start + 28]
            .copy_from_slice(b"BOOT");
        assert!(confirm_started(&mut live, &target).is_err());
        live.image = target.clone();
        live.image[layout::DESCRIPTOR.start + 0x40] ^= 1;
        assert!(confirm_started(&mut live, &target).is_err());
        assert_eq!(live.writes, 0);
    }
    #[test]
    fn first_session_command_disables_file_reads_even_when_it_fails() {
        let image = image();
        let mut live = Restricted {
            image: image.clone(),
            writes: 0,
        };
        let reference = Reference::bind(&mut live, &image).unwrap();
        let analysis = Cell::new(true);
        let cmd = cdb::read_memory(0x98000, 32);
        let mut buf = [0; 32];
        let shared = SharedDevice::new(&mut live);
        let mut reads =
            ScsiTransport::reads(&shared).receiver_source(Some(reference.image()), &analysis);
        let mut writes = ScsiTransport::flash(&shared).starts_session(&analysis);
        mediatek_optical::drive::Transport::exec(&mut reads, &cmd, Data::In(&mut buf)).unwrap();
        assert!(mediatek_optical::drive::Transport::exec(
            &mut writes,
            &cdb::enter_update(),
            Data::None
        )
        .is_err());
        assert!(!analysis.get());
        assert!(
            mediatek_optical::drive::Transport::exec(&mut reads, &cmd, Data::In(&mut buf)).is_err(),
            "verification must never read reference bytes"
        );
    }
    #[test]
    #[ignore = "requires FREEMKV_HOARD with the production 1.V9 package"]
    fn exact_v9_intm_has_encrypted_receiver_with_restricted_live_reads() {
        let root =
            std::path::PathBuf::from(std::env::var_os("FREEMKV_HOARD").expect("FREEMKV_HOARD"));
        let bytes=std::fs::read(root.join("packages/mediatek/ef64ae9e3f5471e0a1cd091544f577757a969cba6e2faca34d18028ecb755270.tar")).unwrap();
        let package = crate::mediatek_package::Package::parse(&bytes).unwrap();
        let image = package.intermediate().unwrap();
        let mut live = Restricted {
            image: image.to_vec(),
            writes: 0,
        };
        let (receiver, _) = detect_device(&mut live, image).unwrap();
        assert_eq!(receiver.encoding(), receiver::Encoding::Encrypted);
        assert!(receiver.prepare_command().is_some());
        assert_eq!(live.writes, 0);
    }
}
