# Pioneer REC capture regression

Report: `faf748cb-8a02-4097-9011-877a949b84a5`, Flash 0.15.3,
Windows x86_64, BDR-L13SH 1.11, hardware `REC 8C00`, Kernel/Normal `ID92`.

## What happened

Backup was refused before firmware reads because valid REC identities were
routed to a dump-only backend. Backup also required a SAT identity, and the
Pioneer envelope builder/decoder only recognized SAT Kernel bodies. Missing
OEM seeds were not the cause of this rejection. No firmware flash was attempted.

Raw Dump captured all low memory through `0x880000`. Three optional probes
failed (E7, E6/03 without a disc, A8), making the diagnostic dump partial;
they did not leave holes in the firmware images used below.

## Reproduction and fix

The report replay failed with the old identity gate. The corrected shared protocol backend consumes one optical-library CDB response
contract. Backup, reconstruction and program-content comparison no longer use
SAT/REC allowlists. Hardware-field framing is validated centrally; exact identity
comparisons remain consistency and target checks. The captured Kernel's receiver
instructions establish the encoding and Normal address/extent. No identity label
authorizes a write; receiver preparation and execution gates remain separate.

The replay reconstructs both components without original OEM seeds and validates
the package. Decoding its envelopes reproduces the captured images byte for byte:

- Kernel: address `0x400000`, length `0x10000`, BE32 checksum zero.
- Normal: address `0x410000`, length 1,851,648 bytes, BE32 checksum zero.

Reconstructed update metadata is labeled as such. This proves capture and
round-trip preservation, not an original OEM release or drive-side acceptance.

## Validation

- Always-on synthetic REC capture test preserves both images without OEM seeds.
- Library REC seed-zero round-trip test rejects an unrecognized dispatcher.
- Real report replay via `PIONEER_REC_REPORT_DUMP` verifies both decoded bodies.
- Flash library suite: 705 passed, 18 ignored.
- Pioneer library all-feature tests and both libraries' clippy checks pass.

The optional report fixture remains local; its raw dump SHA-256 is
`08dd60de0669ddcdf2b888d4b7ce558f7f7103be9d9ec29c2fa145f7f0e51340`.
