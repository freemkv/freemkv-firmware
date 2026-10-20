//! Explicit file-derived receiver evidence; transport always reads the drive.
use anyhow::{anyhow, ensure, Context, Result};
#[cfg(test)]
use mediatek_optical::drive::Transport;
use mediatek_optical::{cdb, envelope::Envelope, layout, receiver};

pub(super) fn detect(
    dev: &mut crate::backend::ReadDevice<'_>,
    input: &[u8],
) -> Result<receiver::Receiver> {
    let envelope = Envelope::load(input).context("invalid Current MediaTek image")?;
    let shared = crate::transport::SharedDevice::new(dev);
    let mut live = crate::transport::ScsiTransport::reads(&shared);
    let receiver = receiver::reference::detect(&mut live, &envelope)
        .map_err(|e| anyhow!("Current image receiver analysis failed: {e}"))?;
    crate::diagnostics::record(format!(
        "MediaTek receiver source: explicit Current image sha256={}; live identity and build metadata match; receiver code is file-derived",
        crate::mediatek_package::digest(envelope.image())
    ));
    Ok(receiver)
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn detect_device(live: &mut Restricted, input: &[u8]) -> Result<receiver::Receiver> {
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
        // Detection captures receiver code once before analyzing it. A refused
        // physical capture retains the transport error instead of becoming an
        // unknown signature after a scan of unreadable blocks.
        let Err(error) = receiver::detect(&mut live, &mode) else {
            panic!("restricted physical receiver detection must fail");
        };
        match error {
            receiver::Error::Read(mediatek_optical::drive::Error::Transport(error)) => {
                assert_eq!(error.to_string(), "restricted read at 0x98000");
            }
            other => panic!("expected refused physical code capture, got {other}"),
        }
        let receiver = detect_device(&mut live, &image).unwrap();
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
        let reference =
            receiver::reference::detect(&mut live, &Envelope::load(&image).unwrap()).unwrap();
        live.image[layout::DESCRIPTOR.start + 24..layout::DESCRIPTOR.start + 28]
            .copy_from_slice(b"1.V1");
        assert!(reference
            .revalidate(&mut live)
            .unwrap_err()
            .to_string()
            .contains("changed"));
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
        let reference =
            receiver::reference::detect(&mut live, &Envelope::load(&image).unwrap()).unwrap();
        reference.revalidate(&mut live).unwrap();
        live.image[0x3014] ^= 2;
        assert!(
            reference.revalidate(&mut live).is_err(),
            "the actual live boot snapshot must remain unchanged"
        );
    }
    #[test]
    fn reference_analysis_never_substitutes_physical_session_or_readback_bytes() {
        let image = image();
        let mut live = Restricted {
            image: image.clone(),
            writes: 0,
        };
        let receiver = detect_device(&mut live, &image).unwrap();
        assert_eq!(
            receiver.provenance(),
            receiver::reference::Provenance::CurrentReference
        );
        let shared = crate::transport::SharedDevice::new(&mut live);
        let mut reads = crate::transport::ScsiTransport::reads(&shared);
        let mut buf = [0; 32];
        assert!(Transport::exec(
            &mut reads,
            &cdb::read_memory(0x98000, 32),
            Data::In(&mut buf)
        )
        .is_err());
        let mut writes = crate::transport::ScsiTransport::flash(&shared);
        assert!(Transport::exec(&mut writes, &cdb::enter_update(), Data::Out(&[])).is_err());
        assert!(Transport::exec(
            &mut reads,
            &cdb::read_memory(0x98000, 32),
            Data::In(&mut buf)
        )
        .is_err());
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
        let receiver = detect_device(&mut live, image).unwrap();
        assert_eq!(receiver.encoding(), receiver::Encoding::Encrypted);
        assert!(receiver.prepare_command().is_some());
        assert_eq!(live.writes, 0);
    }
}
