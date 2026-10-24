//! Customer guidance selected from error evidence. Technical chains stay in diagnostics.
use crate::backend::{
    BackupReadRestricted, CurrentFirmwareRequired, HardwareMismatch, UnverifiedUpdateOutcome,
    UpdateFailure, UpdateImpact,
};
use crate::localization::{self, Language};

/// Stable application causes attached where an operation can explain its failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IssueCode {
    /// A selected installed-firmware reference lacks required components.
    CurrentIncomplete,
    /// A selected target cannot be decoded or validated.
    FirmwareInvalid,
    /// The selected installed firmware does not describe the connected drive.
    CurrentMismatch,
    /// The drive changed or could not be bound to the prepared session.
    DriveChanged,
    /// No live connection could be established.
    Connection,
    /// A prepared session cannot be reused or was lost.
    PreparationExpired,
    /// A backup destination must be chosen.
    BackupDestination,
    /// Backup contents do not match the drive.
    BackupMismatch,
    /// Backup acquisition or verification failed.
    BackupFailed,
    /// The user has not acknowledged the update risk.
    Acknowledgement,
    /// The existing firmware cannot be modified again.
    AlreadyModified,
    /// This application cannot prepare the selected update format.
    UnsupportedFirmware,
    /// The firmware's hardware differs; no display identity was available.
    IncompatibleFirmware,
    /// Device completion or verification needs attention.
    UpdateUncertain,
    /// Command options were rejected before any device operation.
    CommandOptions,
    /// No supported classification could explain an unexpected application fault.
    Unexpected,
    /// No optical drive was available for the operation.
    NoDrive,
    /// Automatic drive selection found more than one candidate.
    ChooseDrive,
    /// The drive's tray must be closed before updating.
    TrayOpen,
    /// A loaded disc must be removed before updating.
    DiscPresent,
    /// No supported update method exists for the connected drive.
    UnsupportedDrive,
    /// The operator declined before the update began.
    Cancelled,
    /// The live drive did not confirm that freemkv firmware is installed.
    FirmwareNotDetected,
}

impl IssueCode {
    /// Localized cause and next action, independent of diagnostic wording.
    pub fn message_id(self) -> &'static str {
        match self {
            Self::CurrentIncomplete => "errors.current_incomplete",
            Self::FirmwareInvalid => "errors.firmware_invalid",
            Self::CurrentMismatch => "errors.current_mismatch",
            Self::DriveChanged => "errors.drive_changed",
            Self::Connection => "errors.connection",
            Self::PreparationExpired => "errors.preparation_expired",
            Self::BackupDestination => "errors.backup_destination",
            Self::BackupMismatch => "errors.backup_mismatch",
            Self::BackupFailed => "errors.backup_failed",
            Self::Acknowledgement => "errors.acknowledgement",
            Self::AlreadyModified => "errors.already_modified",
            Self::UnsupportedFirmware => "errors.unsupported_firmware",
            Self::IncompatibleFirmware => "errors.incompatible_firmware",
            Self::UpdateUncertain => "errors.update_uncertain",
            Self::CommandOptions => "errors.command_options",
            Self::Unexpected => "errors.unexpected",
            Self::NoDrive => "errors.no_drive",
            Self::ChooseDrive => "errors.choose_drive",
            Self::TrayOpen => "errors.tray_open",
            Self::DiscPresent => "errors.disc_present",
            Self::UnsupportedDrive => "errors.unsupported_drive",
            Self::Cancelled => "ui.cancelled_no_firmware_was_written",
            Self::FirmwareNotDetected => "errors.drive_firmware_unconfirmed",
        }
    }
}

impl std::fmt::Display for IssueCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message_id())
    }
}

impl std::error::Error for IssueCode {}

/// Give an unclassified internal cause its domain boundary's explicit meaning.
/// Existing typed causes and transport/file evidence always retain their guidance.
pub fn explain(error: anyhow::Error, code: IssueCode) -> anyhow::Error {
    if UserError::of(&error).id == "errors.unexpected" {
        error.context(code)
    } else {
        error
    }
}

/// Evidence attached only by workflows whose capabilities cannot write firmware.
#[derive(Debug)]
pub struct NoFirmwareWrite;

impl std::fmt::Display for NoFirmwareWrite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("operation has no firmware write capability")
    }
}
impl std::error::Error for NoFirmwareWrite {}

/// Preserve diagnostic causes while recording a read-only operation's effect.
pub fn read_only<T>(result: anyhow::Result<T>) -> anyhow::Result<T> {
    result.map_err(|error| error.context(NoFirmwareWrite))
}

/// A stable UI message with data arguments; no diagnostic error text is exposed.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct UserError {
    /// Catalog message id.
    pub id: &'static str,
    /// Data such as installed and selected model names.
    pub arguments: Vec<(&'static str, String)>,
    /// Evidence-backed consequences are kept with the reason through every sink.
    pub consequence: Option<&'static str>,
}

impl UserError {
    /// Classify structured evidence first. Unknown failures receive conservative guidance.
    pub fn of(error: &anyhow::Error) -> Self {
        let mut arguments = Vec::new();
        let failure = error.downcast_ref::<UpdateFailure>();
        let consequence = match failure {
            Some(f) if f.impact() == UpdateImpact::Blocked => Some("errors.update_blocked"),
            Some(_) => None,
            None if error.is::<NoFirmwareWrite>() => Some("errors.no_firmware_write"),
            None => None,
        };
        let id = if let Some(failure) = failure.filter(|f| f.impact() != UpdateImpact::Blocked) {
            match failure.impact() {
                UpdateImpact::Blocked => unreachable!("filtered above"),
                UpdateImpact::EntryUncertain => "errors.update_not_started",
                UpdateImpact::PayloadUncertain | UpdateImpact::Unknown => "errors.update_uncertain",
                UpdateImpact::TemporaryFirmware => "errors.temporary_firmware",
            }
        } else if let Some(mismatch) = error.downcast_ref::<HardwareMismatch>() {
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
        } else if let Some(code) = error.downcast_ref::<IssueCode>() {
            code.message_id()
        } else if error.is::<crate::backend::UnsupportedFamilyOverride>() {
            "recovery.family_override_unsupported"
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
        } else if error.is::<crate::platform::ScsiSenseError>() {
            "errors.connection"
        } else {
            "errors.unexpected"
        };
        if let Some(evidence) = error.downcast_ref::<crate::backend::UpdateVerification>() {
            use crate::backend::ComponentVerification as V;
            let state = |value| {
                match value {
                    V::Matched => "domain.verified",
                    V::Mismatched => "domain.mismatch",
                    V::Unavailable => "domain.unavailable",
                    V::NotChecked => "verification.not_checked",
                    V::NotRequested => "verification.not_requested",
                }
                .to_string()
            };
            let guidance = localization::message(id, &arguments);
            return Self {
                id: "errors.verification_details",
                consequence,
                arguments: vec![
                    ("guidance", guidance),
                    ("selected_label", "ui.firmware_to_flash".into()),
                    (
                        "selected",
                        crate::style::printable(&evidence.selected_identity).to_string(),
                    ),
                    ("drive_label", "domain.drive".into()),
                    (
                        "observed",
                        evidence
                            .observed_identity
                            .clone()
                            .unwrap_or_else(|| "domain.not_reported".into()),
                    ),
                    ("kernel_label", "domain.kernel".into()),
                    ("kernel", state(evidence.kernel)),
                    ("normal_label", "domain.normal".into()),
                    ("normal", state(evidence.normal)),
                    ("startup_label", "verification.startup".into()),
                    (
                        "startup",
                        if evidence.startup_confirmed {
                            "domain.verified"
                        } else {
                            "status.target_uncertain"
                        }
                        .into(),
                    ),
                ],
            };
        }
        Self {
            id,
            arguments,
            consequence,
        }
    }

    /// Keep the message unresolved until the UI renders it in the chosen language.
    pub fn encoded(&self) -> String {
        let cause = localization::message(self.id, &self.arguments);
        match self.consequence {
            Some(consequence) => localization::message(
                "ui.join",
                &[("first", consequence.into()), ("second", cause)],
            ),
            None => cause,
        }
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
    fn every_application_issue_has_guidance_in_every_catalog() {
        use IssueCode::*;
        for code in [
            CurrentIncomplete,
            FirmwareInvalid,
            CurrentMismatch,
            DriveChanged,
            Connection,
            PreparationExpired,
            BackupDestination,
            BackupMismatch,
            BackupFailed,
            Acknowledgement,
            AlreadyModified,
            UnsupportedFirmware,
            IncompatibleFirmware,
            UpdateUncertain,
            CommandOptions,
            Unexpected,
            NoDrive,
            ChooseDrive,
            TrayOpen,
            DiscPresent,
            UnsupportedDrive,
            Cancelled,
            FirmwareNotDetected,
        ] {
            for language in Language::ALL {
                let text = localization::get(language, code.message_id());
                assert!(!text.trim().is_empty());
                assert_ne!(text, code.message_id(), "{language:?}: {code:?}");
            }
        }
    }

    #[test]
    fn incomplete_current_has_one_localized_cause_action_and_no_write_consequence() {
        let error = UpdateFailure::before_write(
            "recovery precheck",
            anyhow::anyhow!(
                "Current firmware must include Kernel and Normal; private offset 0x98000"
            )
            .context(IssueCode::CurrentIncomplete),
        );
        let guidance = UserError::of(&error);
        assert_eq!(guidance.id, "errors.current_incomplete");
        assert_eq!(guidance.consequence, Some("errors.update_blocked"));
        for language in Language::ALL {
            let rendered = guidance.render(language);
            assert!(rendered.contains(localization::get(language, "errors.update_blocked")));
            assert!(rendered.contains(localization::get(language, "errors.current_incomplete")));
            assert!(!rendered.contains("0x98000") && !rendered.contains("{component}"));
        }
        let rendered = guidance.render(Language::En);
        assert!(rendered.contains("No firmware was written."));
        assert!(rendered.contains("Read from drive"));
        assert!(format!("{error:#}").contains("0x98000"));
    }

    #[test]
    fn write_evidence_overrides_even_a_typed_file_or_hardware_reason() {
        for cause in [IssueCode::FirmwareInvalid, IssueCode::CurrentIncomplete] {
            let error = anyhow::Error::new(cause).context(UpdateFailure {
                phase: "transfer".into(),
                write_started: true,
                progress: crate::backend::UpdateProgress::PayloadAttempted,
                payload_bytes_accepted: Some(0),
                temporary_firmware: false,
                completed_stages: Vec::new(),
            });
            let guidance = UserError::of(&error);
            assert_eq!(guidance.id, "errors.update_uncertain");
            assert_eq!(guidance.consequence, None);
            assert!(!guidance
                .render(Language::En)
                .contains("No firmware was written"));
        }
    }

    #[test]
    fn english_diagnostic_words_cannot_change_error_classification() {
        for detail in [
            "SCSI",
            "CMAC signature",
            "current mismatch",
            "already patched",
            "archive.tar",
        ] {
            assert_eq!(
                UserError::of(&anyhow::anyhow!(detail)).id,
                "errors.unexpected"
            );
        }
    }

    #[test]
    fn verification_failure_preserves_independent_results_in_every_language() {
        use crate::backend::{ComponentVerification as V, UpdateVerification};
        let error = anyhow::anyhow!("technical transport detail").context(UpdateVerification {
            kernel: V::Matched,
            normal: V::Mismatched,
            startup_confirmed: true,
            observed_identity: Some("PIONEER BDR-UD04 1.14".into()),
            selected_identity: "Slimtype EB1 HLE2".into(),
        });
        let guidance = UserError::of(&error);
        for language in Language::ALL {
            let text = guidance.render(language);
            assert!(text.contains("PIONEER BDR-UD04 1.14") && text.contains("Slimtype EB1 HLE2"));
            assert!(!text.contains("technical transport detail") && !text.contains("{kernel}"));
        }
        let text = guidance.render(Language::En);
        assert!(text.contains("Kernel: Verified"));
        assert!(text.contains("Normal: Mismatch"));
        assert!(text.contains("Startup: Verified"));
    }

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
            let error = anyhow::anyhow!(detail).context(IssueCode::AlreadyModified);
            let guidance = UserError::of(&error);
            assert_eq!(guidance.id, "errors.already_modified");
            assert!(guidance.render(Language::En).contains("Choose an original OEM firmware file"));
            assert!(format!("{error:#}").contains(detail));
        }
    }
}
