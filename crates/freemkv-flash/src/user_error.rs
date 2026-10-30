//! Customer guidance selected from error evidence. Technical chains stay in diagnostics.
use crate::backend::{
    BackupReadRestricted, CurrentFirmwareRequired, HardwareMismatch, UnverifiedUpdateOutcome,
    UpdateFailure, UpdateImpact,
};
use crate::localization::{self, Language};

macro_rules! define_issue_codes {
    ($( $(#[$meta:meta])* $variant:ident => $id:literal, )*) => {
        /// Stable application causes attached where an operation can explain its failure.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum IssueCode { $( $(#[$meta])* $variant, )* }
        impl IssueCode {
            /// Every declared cause, generated with its message mapping.
            pub const ALL: &'static [Self] = &[$(Self::$variant),*];
            /// Localized cause and next action, independent of diagnostic wording.
            pub fn message_id(self) -> &'static str {
                match self { $(Self::$variant => $id,)* }
            }
        }
    };
}

define_issue_codes! {
    /// A selected installed-firmware reference lacks required components.
    CurrentIncomplete => "errors.current_incomplete",
    /// The selected Current reference could not be decoded or validated.
    CurrentInvalid => "errors.current_invalid",
    /// A selected target cannot be decoded or validated.
    FirmwareInvalid => "errors.firmware_invalid",
    /// Installed-firmware evidence does not describe the connected drive.
    CurrentMismatch => "errors.current_mismatch",
    /// The drive changed or could not be bound to the prepared session.
    DriveChanged => "errors.drive_changed",
    /// No live connection could be established.
    Connection => "errors.connection",
    /// The operating system denied access to the optical device.
    DriveAccess => "errors.drive_access",
    /// A prepared session cannot be reused or was lost.
    PreparationExpired => "errors.preparation_expired",
    /// A backup destination must be chosen.
    BackupDestination => "errors.backup_destination",
    /// Backup contents do not match the drive.
    BackupMismatch => "errors.backup_mismatch",
    /// Backup acquisition or verification failed.
    BackupFailed => "errors.backup_failed",
    /// The update implementation requires a complete installed-firmware backup.
    BackupRequired => "errors.backup_required",
    /// The user has not acknowledged the update risk.
    Acknowledgement => "errors.acknowledgement",
    /// The existing firmware cannot be modified again.
    AlreadyModified => "errors.already_modified",
    /// This application cannot prepare the requested update from this firmware.
    UnsupportedFirmware => "errors.unsupported_firmware",
    /// No safe authenticated code hole can hold the requested modifications.
    FirmwareNoCodeSpace => "errors.firmware_no_code_space",
    /// Firmware metadata or bytes are corrupt, rather than merely unsupported.
    FirmwareCorrupt => "errors.firmware_corrupt",
    /// A known settings adaptation has not been validated for this transition.
    SettingsUnresolved => "errors.settings_unresolved",
    /// The firmware's hardware differs; no display identity was available.
    IncompatibleFirmware => "errors.incompatible_firmware",
    /// A valid selected update does not pair with the installed firmware.
    InstalledFirmwareMismatch => "errors.installed_firmware_mismatch",
    /// A failed update preparation restored and verified the original startup setting.
    StartupSettingRestored => "errors.startup_setting_restored",
    /// The original startup setting could not be restored or verified.
    StartupSettingUncertain => "errors.startup_setting_uncertain",
    /// Device completion or verification needs attention.
    UpdateUncertain => "errors.update_uncertain",
    /// Command options were rejected before any device operation.
    CommandOptions => "errors.command_options",
    /// No supported classification could explain an unexpected application fault.
    Unexpected => "errors.unexpected",
    /// No optical drive was available for the operation.
    NoDrive => "errors.no_drive",
    /// Automatic drive selection found more than one candidate.
    ChooseDrive => "errors.choose_drive",
    /// The drive's tray must be closed before updating.
    TrayOpen => "errors.tray_open",
    /// A loaded disc must be removed before updating.
    DiscPresent => "errors.disc_present",
    /// The requested operation is unavailable for the selected drive.
    UnsupportedDrive => "errors.unsupported_drive",
    /// The operator declined before the update began.
    Cancelled => "ui.cancelled_no_firmware_was_written",
    /// The live drive did not confirm that freemkv firmware is installed.
    FirmwareNotDetected => "errors.drive_firmware_unconfirmed",
    /// Backup bypass needs an interactive answer before an update can start.
    BackupConfirmationRequired => "errors.backup_confirmation_required",
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
    if !error.is::<IssueCode>() && UserError::of(&error).id == "errors.unexpected" {
        error.context(code)
    } else {
        error
    }
}

/// Marks a backup failure that can be investigated with a separate raw dump.
#[derive(Debug)]
pub(crate) struct BackupAttempt;

impl std::fmt::Display for BackupAttempt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("backup did not complete")
    }
}
impl std::error::Error for BackupAttempt {}

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

/// Structured transfer boundary, retained independently of transport prose.
#[derive(Debug)]
pub(crate) struct TransferFailure {
    pub offset: usize,
    pub length: usize,
}

impl std::fmt::Display for TransferFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "firmware transfer stopped at byte {}, block length {}",
            self.offset, self.length
        )
    }
}
impl std::error::Error for TransferFailure {}

/// Presentation severity of a typed issue; expected limitations are not faults.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum IssueSeverity {
    /// Expected limitation or a cancelled request.
    Notice,
    /// The user can resolve a prerequisite or select a different input.
    ActionRequired,
    /// Failed operation, unexpected fault, or uncertain drive state.
    Error,
}

/// Read stable message IDs, never classify severity from translated error prose.
pub fn issue_severity(message: &str) -> IssueSeverity {
    if let Some(encoded) = message.strip_prefix('\u{1e}') {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(encoded) {
            let id = value["id"].as_str().unwrap_or("");
            if id == "ui.join" {
                return value["arguments"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|a| a[1].as_str())
                    .map(issue_severity)
                    .max()
                    .unwrap_or(IssueSeverity::Error);
            }
            return issue_severity(id);
        }
    }
    match message {
        "errors.backup_restricted"
        | "errors.backup_layout_unsupported"
        | "errors.drive_firmware_unconfirmed"
        | "errors.unsupported_drive"
        | "errors.unsupported_firmware"
        | "errors.firmware_no_code_space"
        | "errors.no_drive"
        | "errors.no_firmware_write"
        | "errors.update_blocked"
        | "ui.cancelled_no_firmware_was_written"
        | "status.operation_cancelled"
        | "domain.these_firmware_formats_cannot_currently_be_compared" => IssueSeverity::Notice,
        "errors.drive_access"
        | "errors.choose_drive"
        | "errors.tray_open"
        | "errors.disc_present"
        | "errors.file_missing"
        | "errors.file_exists"
        | "errors.permission_denied"
        | "errors.command_options"
        | "errors.acknowledgement"
        | "errors.backup_destination"
        | "errors.backup_required"
        | "errors.backup_confirmation_required"
        | "errors.current_required"
        | "errors.current_incomplete"
        | "errors.current_invalid"
        | "errors.current_mismatch"
        | "errors.backup_mismatch"
        | "errors.hardware_mismatch"
        | "errors.incompatible_firmware"
        | "errors.installed_firmware_mismatch"
        | "errors.installed_kernel_mismatch"
        | "errors.already_modified"
        | "errors.boot_settings"
        | "errors.firmware_invalid"
        | "errors.firmware_corrupt"
        | "errors.backup_partial"
        | "errors.preparation_expired"
        | "errors.drive_changed"
        | "errors.startup_setting_restored"
        | "errors.settings_unresolved"
        | "errors.analysis"
        | "domain.for_pioneer_inspection_select_the_tar_package_containing_the_firmware"
        | "domain.select_two_firmware_files_or_one_firmware_file_and_one_drive"
        | "recovery.family_override_unsupported" => IssueSeverity::ActionRequired,
        _ => IssueSeverity::Error,
    }
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
        let issue = Self::classify(error);
        if error.is::<BackupAttempt>() {
            issue.with_backup_guidance()
        } else {
            issue
        }
    }

    /// Add the backup investigation action without losing its cause or write evidence.
    /// Repeated callers do not duplicate guidance; uncertain updates remain unchanged.
    pub fn with_backup_guidance(self) -> Self {
        if !matches!(self.id, "errors.backup_failed" | "errors.unexpected")
            || self.consequence != Some("errors.no_firmware_write")
        {
            return self;
        }
        Self {
            id: "errors.backup_dump_guidance",
            arguments: vec![
                ("cause", localization::message(self.id, &self.arguments)),
                ("submit_dump", "action.submit_dump".into()),
            ],
            consequence: self.consequence,
        }
    }

    fn classify(error: &anyhow::Error) -> Self {
        let mut arguments = Vec::new();
        let failure = error.downcast_ref::<UpdateFailure>();
        // Pioneer startup-setting migration may mutate a setting before any
        // firmware-update command. That stage-specific evidence outranks a
        // generic outer update wrapper, which can describe the wrong boundary.
        let startup_setting_issue = error
            .downcast_ref::<IssueCode>()
            .filter(|issue| {
                matches!(
                    issue,
                    IssueCode::StartupSettingRestored | IssueCode::StartupSettingUncertain
                )
            })
            .filter(|_| {
                failure.is_none_or(|failure| {
                    matches!(
                        failure.impact(),
                        UpdateImpact::Blocked | UpdateImpact::EntryUncertain
                    )
                })
            });
        let consequence = match (failure, startup_setting_issue) {
            (
                Some(_),
                Some(IssueCode::StartupSettingUncertain | IssueCode::StartupSettingRestored),
            ) => None,
            (Some(f), _) if f.impact() == UpdateImpact::Blocked => Some("errors.update_blocked"),
            (Some(_), _) => None,
            (None, _) if error.is::<NoFirmwareWrite>() => Some("errors.no_firmware_write"),
            (None, _) => None,
        };
        let mut id = if let Some(
            issue @ (IssueCode::StartupSettingRestored | IssueCode::StartupSettingUncertain),
        ) = startup_setting_issue
        {
            issue.message_id()
        } else if let Some(failure) = failure.filter(|f| f.impact() != UpdateImpact::Blocked) {
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
        } else if let Some(mismatch) =
            error.downcast_ref::<crate::backend::InstalledKernelMismatch>()
        {
            arguments.push((
                "required",
                crate::style::printable(&mismatch.required).to_string(),
            ));
            arguments.push((
                "installed",
                crate::style::printable(&mismatch.installed).to_string(),
            ));
            "errors.installed_kernel_mismatch"
        } else if error.is::<crate::backend::CorruptFirmware>() {
            "errors.firmware_corrupt"
        } else if error.is::<crate::backend::UnsupportedFamilyOverride>() {
            "recovery.family_override_unsupported"
        } else if matches!(
            error.downcast_ref::<IssueCode>(),
            Some(IssueCode::BackupRequired)
        ) {
            "errors.backup_required"
        } else if error.is::<CurrentFirmwareRequired>() {
            "errors.current_required"
        } else if error.is::<BackupReadRestricted>() {
            "errors.backup_restricted"
        } else if (error.is::<BackupAttempt>()
            || matches!(
                error.downcast_ref::<IssueCode>(),
                Some(IssueCode::BackupFailed)
            ))
            && matches!(
                error.downcast_ref::<pioneer_optical::envelope::NormalLayoutError>(),
                Some(pioneer_optical::envelope::NormalLayoutError::Unsupported)
            )
        {
            "errors.backup_layout_unsupported"
        } else if let Some(code) = error.downcast_ref::<IssueCode>() {
            code.message_id()
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
                InspectionError::UnsupportedFormat(_) => "errors.unsupported_firmware",
                InspectionError::UnrecognizedFormat => "errors.firmware_invalid",
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
                std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::NotConnected
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::BrokenPipe => "errors.connection",
                _ => "errors.file_access",
            }
        } else if error.is::<crate::platform::ScsiSenseError>()
            || error.is::<crate::backend::detection::Unavailable>()
        {
            "errors.connection"
        } else {
            "errors.unexpected"
        };
        // Keep the safe disposition, but do not let it erase a known failure
        // boundary. Never infer a cause from arbitrary diagnostic prose.
        if failure.is_some_and(|f| {
            matches!(
                f.impact(),
                UpdateImpact::EntryUncertain | UpdateImpact::PayloadUncertain
            )
        }) {
            let sense = error.downcast_ref::<crate::platform::ScsiSenseError>();
            let cause = if let Some(transfer) = error.downcast_ref::<TransferFailure>() {
                Some(localization::message(
                    if sense.is_some_and(|s| s.sense_key == 5 && s.asc == 0x26 && s.ascq == 2) {
                        "errors.transfer_rejected"
                    } else {
                        "errors.transfer_stopped"
                    },
                    &[
                        ("offset", transfer.offset.to_string()),
                        ("length", transfer.length.to_string()),
                    ],
                ))
            } else if sense.is_some_and(|s| s.sense_key == 4 && s.asc == 8 && s.ascq == 1) {
                Some("errors.update_communication".into())
            } else {
                None
            };
            if let Some(cause) = cause {
                arguments = vec![
                    ("cause", cause),
                    ("guidance", localization::message(id, &arguments)),
                ];
                id = "errors.update_cause";
            }
        }
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

    /// Keep the disposition severity together with nested no-write consequences.
    pub fn severity(&self) -> IssueSeverity {
        issue_severity(&self.encoded())
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
    fn expected_backup_restriction_is_a_notice_not_a_dump_request() {
        let error = anyhow::Error::new(BackupReadRestricted)
            .context(NoFirmwareWrite)
            .context(BackupAttempt);
        let issue = UserError::of(&error);
        assert_eq!(issue.id, "errors.backup_restricted");
        assert_eq!(issue.severity(), IssueSeverity::Notice);
        assert!(!issue.render(Language::En).contains("send it to us"));
    }

    #[test]
    fn unsupported_pioneer_backup_layout_preserves_the_read_success_cause() {
        let error = anyhow::Error::new(pioneer_optical::envelope::NormalLayoutError::Unsupported)
            .context("determining Normal capture layout from the installed Kernel")
            .context(IssueCode::BackupFailed)
            .context(NoFirmwareWrite)
            .context(BackupAttempt);
        let issue = UserError::of(&error);
        assert_eq!(issue.id, "errors.backup_layout_unsupported");
        assert_eq!(issue.severity(), IssueSeverity::Notice);
        assert_eq!(issue.consequence, Some("errors.no_firmware_write"));
        let text = issue.render(Language::En);
        assert!(text.contains("read successfully"));
        assert!(text.contains("raw dump"));
        assert!(!text.contains("connection"));
        assert!(!text.contains("try again"));
        let unrelated =
            anyhow::Error::new(pioneer_optical::envelope::NormalLayoutError::Unsupported);
        assert_ne!(
            UserError::of(&unrelated).id,
            "errors.backup_layout_unsupported"
        );
    }

    #[test]
    fn write_uncertainty_cannot_be_demoted_by_an_expected_limitation() {
        for progress in [
            crate::backend::UpdateProgress::EntryAttempted,
            crate::backend::UpdateProgress::PayloadAccepted,
        ] {
            let error = anyhow::Error::new(BackupReadRestricted).context(UpdateFailure {
                phase: "test".into(),
                write_started: true,
                progress,
                payload_bytes_accepted: Some(0),
                temporary_firmware: false,
                completed_stages: vec![],
            });
            assert_eq!(UserError::of(&error).severity(), IssueSeverity::Error);
        }
        assert_eq!(issue_severity("unknown.id"), IssueSeverity::Error);
    }

    #[test]
    fn prerequisites_are_actionable_and_expected_limitations_are_not_red_errors() {
        for code in [
            IssueCode::DiscPresent,
            IssueCode::TrayOpen,
            IssueCode::ChooseDrive,
            IssueCode::Acknowledgement,
            IssueCode::CurrentIncomplete,
            IssueCode::FirmwareInvalid,
            IssueCode::BackupDestination,
        ] {
            let issue = UserError::of(&anyhow::Error::new(code).context(NoFirmwareWrite));
            assert_eq!(issue.severity(), IssueSeverity::ActionRequired, "{code:?}");
            assert_eq!(issue_severity(&issue.encoded()), issue.severity());
        }
        for code in [
            IssueCode::UnsupportedDrive,
            IssueCode::UnsupportedFirmware,
            IssueCode::NoDrive,
            IssueCode::FirmwareNotDetected,
            IssueCode::Cancelled,
        ] {
            assert_eq!(
                UserError::of(&anyhow::Error::new(code).context(NoFirmwareWrite)).severity(),
                IssueSeverity::Notice,
                "{code:?}"
            );
        }
    }

    #[test]
    fn reported_final_block_retains_rejection_and_uncertainty() {
        let error = anyhow::Error::new(crate::platform::ScsiSenseError::new(
            5,
            0x26,
            2,
            "PRIVATE TRANSPORT DETAIL",
        ))
        .context(TransferFailure {
            offset: 0x1fc000,
            length: 16384,
        })
        .context(UpdateFailure {
            phase: "firmware transfer".into(),
            write_started: true,
            progress: crate::backend::UpdateProgress::PayloadAccepted,
            payload_bytes_accepted: Some(2080768),
            temporary_firmware: false,
            completed_stages: vec![],
        });
        let issue = UserError::of(&error);
        for language in Language::ALL {
            let text = issue.render(language);
            assert!(text.contains("2080768") && text.contains("16384"));
            assert!(text.contains(localization::get(language, "errors.update_uncertain")));
            assert!(!text.contains("PRIVATE TRANSPORT DETAIL"));
        }
    }

    #[test]
    fn communication_failure_keeps_entry_disposition() {
        let error = anyhow::Error::new(crate::platform::ScsiSenseError::new(4, 8, 1, "private"))
            .context(UpdateFailure {
                phase: "update entry".into(),
                write_started: true,
                progress: crate::backend::UpdateProgress::EntryAttempted,
                payload_bytes_accepted: Some(0),
                temporary_firmware: false,
                completed_stages: vec![],
            });
        let text = UserError::of(&error).render(Language::En);
        assert!(text.contains("communication failure"));
        assert!(text.contains("no firmware data was sent"));
        assert!(!text.contains("private"));
    }

    #[test]
    fn corrupt_input_has_actionable_guidance_in_every_language() {
        let error = anyhow::Error::new(crate::backend::CorruptFirmware {
            detail: "Normal tail cannot be reconstructed".into(),
        })
        .context("input validation");
        let guidance = UserError::of(&error);
        assert_eq!(guidance.id, "errors.firmware_corrupt");
        assert!(guidance
            .render(Language::En)
            .contains("Download a fresh copy"));
        for language in Language::ALL {
            let rendered = guidance.render(language);
            assert!(!rendered.is_empty() && !rendered.contains("errors.firmware_corrupt"));
        }
    }
    #[test]
    fn backup_guidance_is_idempotent_and_does_not_relabel_uncertain_writes() {
        let read_only =
            UserError::of(&anyhow::Error::new(IssueCode::Connection).context(NoFirmwareWrite));
        let guided = read_only.with_backup_guidance();
        assert_eq!(guided.clone().with_backup_guidance(), guided);
        let uncertain = UserError {
            id: "errors.update_uncertain",
            arguments: Vec::new(),
            consequence: None,
        };
        assert_eq!(uncertain.clone().with_backup_guidance(), uncertain);
    }

    #[test]
    fn failed_live_capture_does_not_claim_a_selected_current_file_is_incomplete() {
        let error = UpdateFailure::before_write(
            "current firmware capture",
            anyhow::Error::new(CurrentFirmwareRequired {
                source: anyhow::anyhow!("captured Kernel only")
                    .context(IssueCode::CurrentIncomplete),
            }),
        );
        let issue = UserError::of(&error);
        assert_eq!(issue.id, "errors.current_required");
        assert_eq!(issue.consequence, Some("errors.update_blocked"));
        for language in Language::ALL {
            assert!(issue
                .render(language)
                .contains(localization::get(language, "errors.current_required")));
        }
    }

    #[test]
    fn an_explicit_unexpected_cause_is_never_guessed_by_a_later_boundary() {
        for boundary in [
            IssueCode::FirmwareInvalid,
            IssueCode::Connection,
            IssueCode::UnsupportedFirmware,
            IssueCode::BackupFailed,
        ] {
            let cause = anyhow::anyhow!("private library failure")
                .context(IssueCode::Unexpected)
                .context("preparation wrapper");
            let error = explain(cause, boundary);
            assert_eq!(UserError::of(&error).id, "errors.unexpected");
            assert!(format!("{error:#}").contains("private library failure"));
        }
        let error = explain(
            anyhow::anyhow!("untyped boundary failure"),
            IssueCode::FirmwareInvalid,
        );
        assert_eq!(UserError::of(&error).id, "errors.firmware_invalid");
    }

    #[test]
    fn every_application_issue_has_guidance_in_every_catalog() {
        for &code in IssueCode::ALL {
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
        for cause in [
            anyhow::Error::new(IssueCode::FirmwareInvalid),
            anyhow::Error::new(IssueCode::CurrentIncomplete),
            anyhow::Error::new(HardwareMismatch {
                installed_model: "installed model".into(),
                target_model: "selected model".into(),
                source: anyhow::anyhow!("private compatibility details"),
            }),
            anyhow::Error::new(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "private file error",
            )),
        ] {
            let error = cause.context(UpdateFailure {
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
                "errors.unsupported_firmware",
            ),
            (
                InspectionError::UnrecognizedFormat,
                "errors.firmware_invalid",
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
            let error = anyhow::Error::new(error).context(NoFirmwareWrite);
            let guidance = UserError::of(&error);
            assert_eq!(guidance.id, expected);
            for language in Language::ALL {
                let message = guidance.render(language);
                assert!(!message.is_empty());
                assert_ne!(message, expected);
                assert!(message.contains(localization::get(language, "errors.no_firmware_write")));
            }
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
            localization::get(Language::En, "errors.backup_restricted")
        );
        assert!(!text.contains("CDB") && !text.contains("E4000"));
        assert!(format!("{error:#}").contains("offset=0x98000 [E4000]"));
    }

    #[test]
    fn operating_system_disconnects_do_not_become_file_access_errors() {
        for kind in [
            std::io::ErrorKind::NotConnected,
            std::io::ErrorKind::BrokenPipe,
            std::io::ErrorKind::ConnectionReset,
            std::io::ErrorKind::ConnectionAborted,
        ] {
            let issue = UserError::of(&anyhow::Error::new(std::io::Error::from(kind)));
            assert_eq!(issue.id, "errors.connection", "{kind:?}");
        }
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
            assert!(guidance.render(Language::En).contains("Choose an original firmware file"));
            assert!(format!("{error:#}").contains(detail));
        }
    }
}
