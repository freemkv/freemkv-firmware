# UD02 report failures, 2026-10-30

Reports ca053108 and 6f8f61b6 show separate pre-write failures:

- Normal Flash reads production parameters and rejects factory product `BDR-UD02FAN`; both embedded conversion profiles previously admitted only `BDR-UD02TBD`.
- Recovery prepares the same transition without binding live factory parameters and returns `pioneer.settings.original_hardware_required`.

The second report includes a diagnostic capture. Its parameters section has a verified SHA-256 of `14b91f41e3e4eac2b46cb8c4ab80e5594ba08576f5929f945d2c6890f06e45cf`, factory product `BDR-UD02FAN`, and required mechanism word 0x28F = 1. Raw parameters and personal diagnostic data are not committed.

The dependency fix adds FAN to both existing exact-image profiles. Firmware byte guards, output digests, original identity revalidation and mechanism prerequisite remain required. The app fix requests live original parameters for Recovery only after preparation positively requires them, matching normal Flash. Family override does not bypass these settings requirements.

Validation: 233 Pioneer app tests passed, eight existing tests ignored; the held firmware-pair regression ran with PIONEER_SETTINGS_HOARD explicitly set. It exercises both product codes through normal authorization and Recovery live factory binding, checks unchanged converted Normal hash ca09032288c62b8b26bb983431af11b52aaeec8da9bd0e80afcccdf3b07f0815, and rejects native UD04 factory identity. Clippy with warnings denied passed. Dependency adaptation tests passed; its separate environment-gated raw-image test was not configured and is not counted as corpus evidence.

Physical test pending: SSH to the configured bench failed because the YubiKey agent refused signing. No firmware or settings were written on the bench. Changes are isolated from dev and MT1959 research.
