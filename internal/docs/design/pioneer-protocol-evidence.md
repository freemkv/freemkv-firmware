# Pioneer protocol evidence and identity

Pioneer operation selection uses the response contract of INQUIRY plus the
vendor F1 CDB. Vendor, product and hardware labels are metadata, not lists of
supported drives. A successful command alone is insufficient: response framing
must match the library contract.

## Ownership

- `pioneer-optical::protocol::Response::parse` decodes the CDB response pair once.
  It retains identity metadata and separately exposes validated `Evidence`.
  `Evidence::parse` is a compatibility wrapper over that same parser.
- `pioneer-optical::drive::probe` reads those responses. `identify` returns the
  metadata; `identify_protocol` additionally requires matching protocol evidence.
- App discovery consumes `Response` directly. The registry selects the single
  Pioneer backend from validated evidence; there is no SAT/REC backend split.
- Backup calls `identify_protocol`, attempts the bounded firmware reads and
  derives the capture geometry and envelope codec from the captured Kernel.
- Envelope reconstruction shares the hardware-field framing validator and
  Kernel-body validation. Receiver instructions select the encoding dialect.
  No platform-prefix allowlist selects an encoder or grants OEM provenance.
  Kernel cloning and program-content comparison share the same field framing;
  a different valid hardware label does not become a different code family.

## Separate checks that remain necessary

Recognizing the command protocol offers operations; it does not authorize a
firmware write. Receiver preparation, exact identity/target comparisons,
hardware-family compatibility, authentication, backup coverage and the existing
execution gates still determine whether the particular update may proceed.

An exact hardware-label comparison between the F1 response and captured Kernel
is a consistency check. It must not be replaced with a recognized-label list.
Missing OEM seeds/signatures affect reconstruction/provenance, not whether the
firmware read is attempted. Unknown receiver instructions or unreadable bytes
remain explicit capture failures, with raw Dump available for diagnosis.

## Regression coverage

SAT, REC, NEW, SCSI and ATA labels with the same valid CDB framing select the
same backend and pass capture/reconstruction when their receiver code matches.
Changing the receiver dispatcher prevents encoding despite retaining the same
identity. Malformed/incomplete responses do not become protocol evidence.
The BDR-L13SH REC report additionally verifies exact preservation of both bodies.
