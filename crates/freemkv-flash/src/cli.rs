//! Shared terminal error presentation; native parser details stay in diagnostics.

use std::process::ExitCode;

/// Parse options without exposing untranslated parser errors as user guidance.
pub fn parse<T: clap::Parser>() -> Result<T, ExitCode> {
    match T::try_parse() {
        Ok(options) => Ok(options),
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            let _ = error.print();
            Err(ExitCode::SUCCESS)
        }
        Err(error) => {
            let result: anyhow::Result<()> = crate::diagnostics::run("command options", || {
                Err(anyhow::Error::new(error)
                    .context(crate::user_error::IssueCode::CommandOptions)
                    .context(crate::user_error::NoFirmwareWrite))
            });
            if let Err(error) = result {
                print_error(&error);
            }
            Err(ExitCode::FAILURE)
        }
    }
}

/// Render the same structured issue as the GUI in the user's saved language.
pub fn print_error(error: &anyhow::Error) {
    let language = crate::localization::Preferences::user().load();
    eprintln!(
        "{}",
        crate::user_error::UserError::of(error).render(language)
    );
}
