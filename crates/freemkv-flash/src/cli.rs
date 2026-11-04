//! Shared terminal error presentation; native parser details stay in diagnostics.

use std::process::ExitCode;

#[derive(Debug, PartialEq, Eq)]
enum ErrorClass {
    Info,
    UsageHelp,
    Diagnose,
}

fn classify(kind: clap::error::ErrorKind) -> ErrorClass {
    use clap::error::ErrorKind;
    match kind {
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => ErrorClass::Info,
        ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => ErrorClass::UsageHelp,
        _ => ErrorClass::Diagnose,
    }
}

/// Parse options without exposing untranslated parser errors as user guidance.
pub fn parse<T: clap::Parser>() -> Result<T, ExitCode> {
    match T::try_parse() {
        Ok(options) => Ok(options),
        Err(error) if classify(error.kind()) == ErrorClass::Info => {
            let _ = error.print();
            Err(ExitCode::SUCCESS)
        }
        Err(error) if classify(error.kind()) == ErrorClass::UsageHelp => {
            let _ = error.print();
            Err(ExitCode::FAILURE)
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Options {
        #[command(subcommand)]
        command: Command,
    }
    #[derive(clap::Subcommand)]
    enum Command {
        Run,
    }

    #[test]
    fn bare_command_with_required_subcommand_prints_usage_not_diagnostics() {
        let error = Options::try_parse_from(["bin"]).err().unwrap();
        assert_eq!(classify(error.kind()), ErrorClass::UsageHelp);
        let error = Options::try_parse_from(["bin", "--bogus"]).err().unwrap();
        assert_eq!(classify(error.kind()), ErrorClass::Diagnose);
        let error = Options::try_parse_from(["bin", "--help"]).err().unwrap();
        assert_eq!(classify(error.kind()), ErrorClass::Info);
    }
}
