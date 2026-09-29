# freemkv-flash command contract

`info` identifies a drive or local firmware file without flashing. `backup`
creates one firmware rollback file only when the drive's complete update
image is readable and validates. Pass that file directly to `flash -i` to
restore the prior firmware. `flash` also accepts a supported firmware image.
`flash` without `--execute` is the dry run for every supported backend.
For Pioneer it accepts one `.enc` envelope or an extractor-produced
`.firmware.tar` bundle and prints the audited OEM transfer shape:

```sh
freemkv-flash flash /dev/sg0 -i BDR-UD04_FW111EU.fw.bin -v
freemkv-flash flash /dev/sg0 -i BDR-UD04_FW111EU.EXE.firmware.tar -v
freemkv-flash flash /dev/sg0 -i BDR-S09_FW130EU.enc -v
freemkv-flash flash /dev/sg0 -i BDR-212_ULBK_EBK_FW105EU.exe.firmware.tar -v
```

The executable flash path currently targets the proven MediaTek MT1959
family. For this family, a successful `backup` requires every byte of the
2-MiB firmware image, no read gaps, a valid AES-CMAC, matching drive
model/family, and coherent per-unit regions. The archive contains
`backup.toml`, `firmware.bin`, and six per-unit reference files. The archive
is parsed and hash-checked before it is saved. A flash execution captures
and saves a fresh complete archive, reads it back, and validates it before
the first firmware write. An existing output path is not overwritten.
If any backup check fails, the flash stops before writing. A dry run does
not create a backup or issue firmware writes.

A `.tar` input selects the archived `firmware.bin` for firmware rollback.
The per-unit files document the captured state and are checked for
coherence; they are **not** automatically written after reboot. This is
not a promise to restore every mutable NVRAM or calibration byte.

For Pioneer, `backup DRIVE --template matching-UD04-1.14.tar` has a bounded
BDR-UD04 1.14 read-only path: it captures Kernel and Normal twice and saves
only if the reconstructed tar equals the supplied signed OEM pair byte for
byte. Other Pioneer backups and live `flash` remain blocked. Renesas identity alone
selects no flash protocol. The known
`READ_BUFFER 02/B0` view is a runtime address-space mapping, not a proven
restorable `.enc` or persistent flash backup. A `flash` dry run can print the
UD04 1.11 or S09 1.30EU/1.30AEU OEM **Normal-only** data-out transcript from a local
envelope. S09's updater uses `PIONEER  BDR-209`
as its control descriptor, while the resource banner and stated drive model
must say `BDR-S09`; no model alias is inferred from that descriptor.
For bundles, the tool checks every member's path, size, role, and SHA-256.
It accepts a sole Normal component through an audited Normal-only profile.
It also recognizes 38 local packages with exactly one matching updater and
one exact Kernel/Normal resource pair. Their pinned Rust table records the
constructor, control buffer, and resource hashes recovered from the
bounded-flow updater cluster. The plan describes a Kernel prefix, a 512-byte
clock-seeded CRT-rand block, four FE slices, and the full Normal resource.
The clock seed is unavailable in the package, so the plan is parameterized;
an explicit seed can materialize a data-out example in the library. Four
packages containing two different matching updater executables fail closed
pending explicit variant selection. Unmatched or modified Kernel/Normal
resources fail closed. The profile records the audited
updater and OEM-envelope hashes as evidence; neither original updater nor
sidecar is a runtime input. A changed same-model envelope is labeled an
uncertified offline candidate. The updater's full 48-byte F1 identity
comparison is not yet implemented as a live preflight. Pioneer live writes, drive acceptance, and
modified-envelope integrity remain unproven. The 6-MiB research sweep
and experimental read probes are outside this flash package.

The proposed explicit-base selection contract for modified Kernel+Normal
bundles is recorded in `docs/pioneer-modified-profile-contract.md`. It is not
yet a CLI route; the exact-resource selector continues to reject changed
components.

A bundle preserves complete Kernel `.enc` bytes as evidence. It does not
imply the updater streams that file verbatim: observed OEM paths use
profile-specific offsets, lengths, and control framing for Kernel transfer.
The bounded-flow plans cover data-out only. Full read/clear/poll/status and
reset handling, verified drive-side identity gates, and restorable backup
remain unresolved. The package alone does not contain the clock seed.

## Adding a controller protocol

The object being updated is firmware on a device; a backend represents the
controller's host command protocol, not a device brand alone. INQUIRY
vendor/product/revision stays separate from the protocol match. Add an
implementation of `drive::FirmwareBackend` in `drive/xyz.rs` and register it
once in `drive::BACKENDS`. `probe` must use read-only evidence and return
`ProbeEvidence`; the resolver fails closed if more than one backend matches.

The common engine owns backup-first orchestration, atomic file save and
readback, dry-run/execute gates, streaming, and verification. A backend owns
its backup format and extension, input classification, complete-backup and
image validation, protocol CDBs, and readback ranges. Unsupported methods
must fail closed. Implementing a backend does not establish hardware safety:
`is_supported` should become true only with a proven restorable backup and
working update/verify route. The SCSI transport and optical-medium guard are
still shared assumptions, so a non-optical protocol would also need a
transport/guard adaptation.
