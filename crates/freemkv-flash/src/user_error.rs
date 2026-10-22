//! Customer guidance selected from error evidence. Technical chains stay in diagnostics.
use crate::backend::{
    BackupReadRestricted, CurrentFirmwareRequired, HardwareMismatch, UnverifiedUpdateOutcome,
    UpdateFailure, UpdateImpact,
};
use crate::localization::{self, Language};

/// A stable UI message with data arguments; no diagnostic error text is exposed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserError {
    /// Catalog message id.
    pub id: &'static str,
    /// Data such as installed and selected model names.
    pub arguments: Vec<(&'static str, String)>,
}

impl UserError {
    /// Classify structured evidence first. Unknown failures receive conservative guidance.
    pub fn of(error: &anyhow::Error) -> Self {
        let mut arguments = Vec::new();
        let id = if let Some(mismatch) = error.downcast_ref::<HardwareMismatch>() {
            arguments.push((
                "installed",
                crate::style::printable(crate::style::ident_or_unknown(&mismatch.installed_model))
                    .to_string(),
            ));
            arguments.push((
                "selected",
                crate::style::printable(crate::style::ident_or_unknown(&mismatch.target_model))
                    .to_string(),
            ));
            "errors.hardware_mismatch"
        } else if error.is::<CurrentFirmwareRequired>() {
            "errors.current_required"
        } else if error.is::<BackupReadRestricted>() {
            "errors.backup_restricted"
        } else if let Some(unverified) = error.downcast_ref::<UnverifiedUpdateOutcome>() {
            match &unverified.0 {
                crate::backend::UpdateOutcome::Completed(e) if e.temporary_firmware => {
                    "errors.temporary_firmware"
                }
                _ => "errors.update_uncertain",
            }
        } else if let Some(inspection) = error.downcast_ref::<crate::inspection::InspectionError>()
        {
            use crate::inspection::InspectionError;
            match inspection {
                InspectionError::UnsupportedFormat(_) => "modify.not_supported",
                InspectionError::UnrecognizedFormat => {
                    "domain.this_firmware_format_was_not_recognized"
                }
                InspectionError::UnsupportedPair => {
                    "domain.these_firmware_formats_cannot_currently_be_compared"
                }
                InspectionError::PackageRequired => {
                    "domain.for_pioneer_inspection_select_the_tar_package_containing_the_firmware"
                }
                InspectionError::Cancelled => {
                    arguments.push(("operation", "ui.firmware_analysis".into()));
                    "status.operation_cancelled"
                }
                InspectionError::TwoDrives => {
                    "domain.select_two_firmware_files_or_one_firmware_file_and_one_drive"
                }
            }
        } else if let Some(failure) = error
            .downcast_ref::<UpdateFailure>()
            .filter(|failure| failure.impact() != UpdateImpact::Blocked)
        {
            match failure.impact() {
                UpdateImpact::Blocked => unreachable!("filtered above"),
                UpdateImpact::EntryUncertain => "errors.update_not_started",
                UpdateImpact::PayloadUncertain => "errors.update_uncertain",
                UpdateImpact::TemporaryFirmware => "errors.temporary_firmware",
                UpdateImpact::Unknown => "errors.update_uncertain",
            }
        } else if let Some(io) = error
            .chain()
            .find_map(|cause| cause.downcast_ref::<std::io::Error>())
        {
            match io.kind() {
                std::io::ErrorKind::NotFound => "errors.file_missing",
                std::io::ErrorKind::PermissionDenied => "errors.permission_denied",
                std::io::ErrorKind::AlreadyExists => "errors.file_exists",
                std::io::ErrorKind::WriteZero | std::io::ErrorKind::StorageFull => {
                    "errors.save_failed"
                }
                std::io::ErrorKind::TimedOut => "errors.connection",
                _ => "errors.file_access",
            }
        } else {
            let detail = format!("{error:#}").to_ascii_lowercase();
            if error
                .downcast_ref::<UpdateFailure>()
                .is_some_and(|failure| failure.phase == "risk acknowledgement")
            {
                "errors.acknowledgement"
            } else if detail.contains("no preflash backup path") {
                "errors.backup_destination"
            } else if detail.contains("does not match the target drive") {
                "errors.backup_mismatch"
            } else if detail.contains("already modified")
                || detail.contains("already patched")
                || detail.contains("already contains freemkv firmware")
                || detail.contains("predates editable boot settings")
            {
                "errors.already_modified"
            } else if detail.contains("current")
                && (detail.contains("does not match") || detail.contains("mismatch"))
            {
                "errors.current_mismatch"
            } else if detail.contains("scsi")
                || detail.contains("transport error")
                || detail.contains("device disconnected")
            {
                "errors.connection"
            } else if detail.contains("signature")
                || detail.contains("cmac")
                || detail.contains("integrity")
                || detail.contains("archive")
                || detail.contains(".tar")
                || detail.contains("firmware image")
            {
                "errors.firmware_invalid"
            } else if error
                .downcast_ref::<UpdateFailure>()
                .is_some_and(|failure| failure.phase == "backup")
            {
                "errors.backup_failed"
            } else {
                "errors.cannot_finish"
            }
        };
        Self { id, arguments }
    }

    /// Keep the message unresolved until the UI renders it in the chosen language.
    pub fn encoded(&self) -> String {
        localization::message(self.id, &self.arguments)
    }

    /// Render guidance without changing the stored diagnostic evidence.
    pub fn render(&self, language: Language) -> String {
        localization::render(language, &self.encoded())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancelled_inspection_is_not_a_failure_or_retry_prompt() {
        let error = anyhow::Error::new(crate::inspection::InspectionError::Cancelled);
        let guidance = UserError::of(&error);
        assert_eq!(guidance.id, "status.operation_cancelled");
        for language in Language::ALL {
            let text = guidance.render(language);
            assert!(!text.contains("{operation}"), "{}: {text}", language.code());
        }
        assert_eq!(guidance.render(Language::En), "Firmware analysis cancelled");
    }

    #[test]
    fn inspection_error_variants_have_specific_localized_guidance() {
        use crate::inspection::InspectionError;
        for (error, expected) in [
            (
                InspectionError::UnsupportedFormat("Pioneer".into()),
                "modify.not_supported",
            ),
            (
                InspectionError::UnrecognizedFormat,
                "domain.this_firmware_format_was_not_recognized",
            ),
            (
                InspectionError::UnsupportedPair,
                "domain.these_firmware_formats_cannot_currently_be_compared",
            ),
            (
                InspectionError::PackageRequired,
                "domain.for_pioneer_inspection_select_the_tar_package_containing_the_firmware",
            ),
            (
                InspectionError::TwoDrives,
                "domain.select_two_firmware_files_or_one_firmware_file_and_one_drive",
            ),
        ] {
            let error = anyhow::Error::new(error);
            let guidance = UserError::of(&error);
            assert_eq!(guidance.id, expected);
            for language in Language::ALL {
                let message = guidance.render(language);
                assert!(!message.is_empty());
                assert_ne!(message, expected);
            }
            assert!(!guidance.render(Language::En).contains("try again"));
        }
    }

    #[test]
    fn unverified_outcome_retains_temporary_firmware_evidence() {
        let outcome = crate::backend::UpdateOutcome::Completed(crate::backend::UpdateEvidence {
            target_started: false,
            target_identity: String::new(),
            verified_regions: Vec::new(),
            unverified_regions: Vec::new(),
            completed_stages: Vec::new(),
            temporary_firmware: true,
        });
        let error = anyhow::Error::new(UnverifiedUpdateOutcome(outcome));
        assert_eq!(UserError::of(&error).id, "errors.temporary_firmware");
        assert!(format!("{error:#}").contains("temporary_firmware: true"));
    }

    #[test]
    fn unverified_target_startup_does_not_suggest_generic_retry() {
        let outcome = crate::backend::UpdateOutcome::Completed(crate::backend::UpdateEvidence {
            target_started: false,
            target_identity: String::new(),
            verified_regions: Vec::new(),
            unverified_regions: Vec::new(),
            completed_stages: Vec::new(),
            temporary_firmware: false,
        });
        let error = anyhow::Error::new(UnverifiedUpdateOutcome(outcome));
        let guidance = UserError::of(&error);
        assert_eq!(guidance.id, "errors.update_uncertain");
        assert!(!guidance.render(Language::En).contains("then try again"));
    }

    #[test]
    fn technical_causes_stay_in_diagnostics_and_never_enter_user_guidance() {
        let error =
            anyhow::anyhow!("SCSI CHECK CONDITION cdb=[3c,06,00,09,80] offset=0x98000 [E4000]")
                .context(BackupReadRestricted);
        let guidance = UserError::of(&error);
        assert_eq!(guidance.id, "errors.backup_restricted");
        let text = guidance.render(Language::En);
        assert_eq!(
            text,
            "This firmware cannot be backed up. This is normal for many MediaTek drives."
        );
        assert!(!text.contains("CDB") && !text.contains("E4000"));
        assert!(format!("{error:#}").contains("offset=0x98000 [E4000]"));
    }

    #[test]
    fn disk_and_connection_errors_do_not_claim_a_normal_mediatek_restriction() {
        for error in [
            anyhow::Error::new(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "private/path",
            )),
            anyhow::anyhow!("transport error: SCSI timeout"),
            anyhow::anyhow!("backup failed: disk full"),
        ] {
            let text = UserError::of(&error).render(Language::En);
            assert!(!text.contains("normal for many MediaTek"));
            assert!(!text.contains("private/path"));
        }
    }

    #[test]
    fn a_started_update_never_suggests_an_immediate_retry() {
        let error = anyhow::anyhow!("SCSI transport error").context(UpdateFailure {
            phase: "upload".into(),
            write_started: true,
            progress: crate::backend::UpdateProgress::PayloadAttempted,
            payload_bytes_accepted: Some(0),
            temporary_firmware: false,
            completed_stages: Vec::new(),
        });
        let guidance = UserError::of(&error);
        assert_eq!(guidance.id, "errors.update_uncertain");
        assert!(!guidance.render(Language::En).contains("try again"));
        assert!(format!("{error:#}").contains("SCSI transport error"));
    }

    #[test]
    fn failure_guidance_uses_typed_progress_across_every_catalog() {
        use crate::backend::UpdateProgress;
        for (progress, temporary, expected) in [
            (
                UpdateProgress::EntryAttempted,
                false,
                "errors.update_not_started",
            ),
            (
                UpdateProgress::PayloadAttempted,
                false,
                "errors.update_uncertain",
            ),
            (
                UpdateProgress::PayloadAccepted,
                false,
                "errors.update_uncertain",
            ),
            (
                UpdateProgress::UploadComplete,
                false,
                "errors.update_uncertain",
            ),
            (
                UpdateProgress::EntryAttempted,
                true,
                "errors.temporary_firmware",
            ),
            (UpdateProgress::Unknown, false, "errors.update_uncertain"),
        ] {
            let error = anyhow::anyhow!("private SCSI detail").context(UpdateFailure {
                phase: "test".into(),
                write_started: true,
                progress,
                payload_bytes_accepted: Some(0),
                temporary_firmware: temporary,
                completed_stages: Vec::new(),
            });
            let guidance = UserError::of(&error);
            assert_eq!(guidance.id, expected);
            for language in Language::ALL {
                let text = guidance.render(language);
                assert!(!text.contains("private SCSI detail"));
                assert!(!text.trim().is_empty());
            }
        }
    }

    #[test]
    fn model_arguments_remain_data_even_when_they_contain_template_characters() {
        let error = anyhow::Error::new(HardwareMismatch {
            installed_model: "DRIVE {selected}".into(),
            target_model: "TARGET".into(),
            source: anyhow::anyhow!("family hashes abcdef0123456789 != 1234567890abcdef"),
        });
        let guidance = UserError::of(&error).render(Language::En);
        assert!(guidance.contains("DRIVE {selected}"));
        assert!(guidance.contains("TARGET"));
        assert!(!guidance.contains("abcdef0123456789"));
    }
}

#[cfg(test)]
mod legacy_guidance_tests {
    use super::*;

    #[test]
    fn previous_modified_images_keep_the_instruction_to_choose_an_original_oem() {
        for detail in [
            "image already contains freemkv firmware; creating a new build requires a clean, unmodified OEM image",
            "This firmware predates editable boot settings. Select its original OEM image to create firmware with boot settings.",
        ] {
            let error = anyhow::anyhow!(detail);
            let guidance = UserError::of(&error);
            assert_eq!(guidance.id, "errors.already_modified");
            assert!(guidance.render(Language::En).contains("Choose an original OEM firmware file"));
            assert_eq!(format!("{error:#}"), detail);
        }
    }
}
