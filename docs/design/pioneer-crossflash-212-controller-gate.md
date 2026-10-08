# Pioneer 212M → 212U failure: receiver framing defect

Review date: 2026-10-07. Source reviewed: freemkv-firmware dev `f5a4a36`
and local pioneer-optical based on `e080d46`. No physical flash was performed.
This replaces the earlier controller-gate design and its contradictory R2
recommendations. The 0.10.8 worktree now uses library-prepared Kernel and Normal transfer bytes.
Release validation and the remaining receiver coverage are still pending.

## 1. Review decision

Change the design: normalize the kernel file envelope into the receiver's wire
layout. Do not extend the SAT/tag/date refusal as the fix for this failure.

Receiver disassembly and an executable staging reproduction establish a concrete
host defect for the matching archive 212M/212U 1.05 images. Our generated-block
schedule places ciphertext in the receiver's key slot, then supplies the same
ciphertext as the start of its payload. The first 4096 decoded bytes become zero.
The receiver rejects the resulting zero generation marker with precisely the
reported sense `04/4C/02`, before its checksum check and kernel programming path.

This establishes a reproducible mechanism matching the report, not the identity
of the reporter's exact files: their hashes and captured backup were not supplied.
It also does not certify the full corrected update session on physical hardware
or every Pioneer receiver generation.

The author was right to withdraw the claimed foreign-controller rejection and
treat the same-family failure as an update-session defect. The proposed next step
should now be a format conversion fix and receiver-based tests. The complete OEM session explains the difference: its F0 preload comes from
the Normal resource and supplies the actual key before the Kernel FE overlays.
The application incorrectly substituted the Kernel prefix (see the OEM preload
correction below).

## 2. Original report and scope

The reporter used v0.10.7, force disabled, to go from 212M 1.05 to 212U 1.05:

```text
OEM KernelFe write failed at offset 0x11200, length 4096 — the drive may now hold a partial firmware; re-flash the captured pre-flash backup to restore it:
SCSI transport failure on \\.\CdRom0: E4000: 0x3b/0x02/0x04/0x4c/0x02
(cdb=[3b, 07, fe, 01, 12, 00, 00, 10, 00, 00], direction=ToDevice, requested=4096, attempt=1)
```

The error formatter's fields are opcode/status/sense-key/ASC/ASCQ:
WRITE BUFFER, CHECK CONDITION, HARDWARE ERROR, `4C/02`. The last pair is
mapped to a specific marker-check failure below. The tool's partial-firmware
warning does not establish that the drive was bricked. No successful v0.10.5
retry or rollback was reported.

Both variants have computed hardware family `cf3183a51bc41e42`;
212M is SAT 8F00/ID56 and 212U is SAT 8F01/ID58. The Normal-body family
fingerprint and SAT tag are different kinds of metadata. Neither their equality
nor difference substitutes for tracing what the installed receiver does.

The additional report about crossing the pre-12/22 generation boundary remains
open. Earlier corpus work associates 1.00 with KernelFront/marker FF and
1.04–1.05 with KernelDerived/marker 01; this review does not certify either
upgrade or downgrade session across that boundary.

## 3. Input evidence

All addresses below refer to the decoded 212M 1.05 kernel loaded at `0x400000`.
Full SHA-256 hashes, rather than model names, identify the analyzed artifacts:

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| 212M `S8F00560.105.enc` | 70144 | `7c4e8f4a45f2f555d425d7dce3fb6362bdcfc8ff1a78bfa914ca8470c70c97e6` |
| Decoded 212M kernel | 65536 | `1094f85595c817503265c32a5bf25a39a9c6bbdaca3a274504cac9d9b7de4855` |
| 212U `S8F01580.105.enc` | 70144 | `c93c16245310b6f2b4a4c15bffee6ced46f604dcada296173d95ebb4acb8ad23` |
| Decoded 212U kernel | 65536 | `4f8fc0631bada2500142ff2d0aa80f2487d27fe1986099f6ae768407a2355634` |

The target kernel was independently extracted from `Updater.exe` at file offset
`0x19AB48`, length `0x11200`, in OEM package `BDR-212JBK_UBK_FW105EU.exe`
(package SHA-256 `aa0f7b730c815b954b9c20aa8060bb807e533c925fe3e05fc6cbe216499a078b`).
Both decoded bodies have marker `01` at body offset `0xFE` and BE32 sum zero.
Recovered encoding seeds are 7036594 (212M) and 5787657 (212U).

Disassemble the decoded source kernel using GNU binutils:

```sh
objdump -D -b binary -m h8300sx --adjust-vma=0x400000 decoded-212m-kernel.bin
```

On this machine the executable is `/opt/homebrew/opt/binutils/bin/objdump`.
Only traced code is treated as instructions; indiscriminate disassembly of data
elsewhere in the image is not evidence.

## 4. Receiver trace

| Receiver address | Established behavior |
| --- | --- |
| `0x403420` | WRITE BUFFER dispatch, including F0 and FE handling. |
| `0x403574–0x40360E` | F0 and FE copy into the staging base plus the command offset. FE offset zero resets its received-byte counter. |
| `0x404F92` | Mode 2 staging base is `0x10200`. |
| `0x4052D8–0x4052E0` | Kernel finalization requires FE received-byte count `0x11200`. This is a count, not the highest destination written. |
| `0x4052EA–0x405320` | Decode body at staging + `0x1200`, length `0x10000`, with key at staging + `0x200`, length `0x1000`. Calls `0x404FF6`. |
| `0x404FF6` | Decode routine, including an already-plain recognition path. The encrypted path reads repeating key words, XORs and rotates. |
| `0x405336–0x405340` | Calls marker check `0x405862` with mode zero; a return value of 1 selects `0x405386`. |
| `0x405862` | Kernel-mode marker is staging + `0x12FE`, i.e. decoded body + `0xFE`. Values `00` and `FF` are rejected in the ordinary case. |
| `0x405386` | Selects internal sense index `0x0B`. |
| `0x40331A`, table `0x406B88` | Sense index `0x0B` maps to key/ASC/ASCQ `04/4C/02`. Index `0x0A` maps to `04/4C/01`. |
| `0x405342–0x405348` | Only after the marker check, a nonzero checksum selects index `0x0A`. |
| `0x40536A–0x405376` | Subsequent success path prepares programming and calls RAM code at `0x2800`. |

The marker check has a special bypass when RAM `0x67E` bit 0 is set AND the
resident Normal word at `0x410014` is `FFFFFFFF`. It is not an unconditional
logging/read-unlock bypass and must not be assumed for a normally installed image.

There is no SAT or kernel-tag comparison in this rejection branch. This finding
is narrower than claiming there are no identity checks anywhere in the firmware.
Likewise, rejection before this kernel programming path does not prove that
nothing earlier in an entire update session could have modified persistent state.

## 5. Why our current framing fails

The on-disk KernelDerived layout is:

```text
[0x00000, 0x00200)  banner
[0x00200, 0x10200)  encrypted kernel body
[0x10200, 0x11200)  trailer from which the codec derives the key
```

The receiver expects:

```text
[0x00000, 0x00200)  header
[0x00200, 0x01200)  actual decoding key
[0x01200, 0x11200)  encrypted kernel body
```

Our `PrefixF0GeneratedFe` schedule is:

| Command | Destination | Source in file | Length |
| --- | ---: | ---: | ---: |
| F0 | `0` | `0` | `0x1200` |
| FE | `0` | generated header | `0x200` |
| FE | `0x1200` | `0x200` | `0x8000` |
| FE | `0x9200` | `0x8200` | `0x8000` |
| FE | `0x11200` | `0x10200` | `0x1000` |

F0 puts the first `0x1000` bytes of ciphertext in the key slot. FE puts those
same bytes at the start of the payload; replacing only the header does not fix
the key. The final FE slice brings the FE byte count to `0x11200` and triggers
finalization. That explains why the error appears on that final command.

For each little-endian word the encrypted path computes:

```text
decoded = rotate_right(ciphertext XOR key, key AND 31)
```

Here ciphertext equals the erroneous key for the first 4096 bytes, so every word
becomes zero. The decoded marker at `0xFE` is therefore zero, causing `04/4C/02`.
The checksum is also wrong, but the marker check runs first.

This does not require crossing SATs: the same bad framing also corrupts the
matching 212M target. A SAT-only guard neither diagnoses nor fixes the defect.

The earlier analyzer decoded the original file and compared copied staging
ranges; it did not decode the assembled staging buffer as the receiver does.
Consequently its valid-file checksum and round-trip results missed this bug.
A claimed match to an OEM tuple list is insufficient: the OEM working buffer,
branch conditions and any preceding normalization must also be established.
The earlier assertion that matching tuples refuted a transfer defect is withdrawn.

## 6. Proposed generic correction

Convert the decoded envelope's representation to the receiver layout:

```text
original header (0x200) + recovered key (0x1000) + ciphertext (0x10000)
```

Do not copy the derived trailer into the receiver payload. The result is
`0x11200` bytes. A candidate linear FE transfer is:

| Destination | Length |
| ---: | ---: |
| `0x00000` | `0x8000` |
| `0x08000` | `0x8000` |
| `0x10000` | `0x1200` |

This supplies the expected total count and layout for the traced receiver.
Offline reconstruction verifies exact decoding; full-session entry/state/finish
compatibility and other receiver variants still require validation before release.

Responsibilities:

- `pioneer-optical`: expose a typed, checked envelope-to-kernel-transfer conversion.
  Reuse the codec's recovered key. Define layout offsets and lengths centrally;
  do not duplicate seed recovery or introduce a model/SAT lookup in the app.
- Flash app: obtain the validated transfer image before update entry and send it
  through the protocol transfer path. If a generation patch is necessary, apply
  it to the decoded image and re-encode before normalization.
- Apply the same structural validation in normal, force/recovery and automatic
  restore sessions. Force must not make malformed framing valid. Preserve unknown
  installed identity as unknown instead of manufacturing target equality.
- Keep the existing hardware-family compatibility policy. Remove the speculative
  cross-SAT generated-layout restriction as part of the verified framing fix;
  do not replace it with model, tag or firmware-date exceptions.

The earlier discovered routing bypass remains a useful test case: CLI `--force`
sets `recover`, which returns before the old generated-framing guard, and the
unknown-installed branch substitutes target controller identity. Closing the old
SAT guard alone is no longer the recommended remedy. Validate the actual invariant
at the shared preparation boundary across every route.

## 7. Reproduction and required tests

The standalone research harness is preserved in
[evidence/pioneer-kernel-framing-repro.rs](evidence/pioneer-kernel-framing-repro.rs).
It reconstructs the old transfers, independently decodes receiver staging,
normalizes using the codec's recovered seed, and asserts byte-exact agreement
with the intended decoded body. It performs no device I/O.

To run, create a scratch Cargo binary, copy the harness to `src/main.rs`, and add
`pioneer-optical` from the reviewed local checkout with feature `envelope`:

```sh
cargo new --bin /tmp/pioneer-framing-review
cp docs/design/evidence/pioneer-kernel-framing-repro.rs /tmp/pioneer-framing-review/src/main.rs
cargo add --manifest-path /tmp/pioneer-framing-review/Cargo.toml pioneer-optical --path ../pioneer-optical --features envelope
cargo run --quiet --manifest-path /tmp/pioneer-framing-review/Cargo.toml -- /path/to/S8F00560.105.enc /path/to/S8F01580.105.enc
```

Actual results, reproduced on 2026-10-07:

```text
212M: old marker=00 old sum=79e99976; normalized marker=01 sum=00000000, exact body match
212U: old marker=00 old sum=049ff057; normalized marker=01 sum=00000000, exact body match
```

This harness is a receiver decoding model, not an instruction-level emulator or
full update-session simulation. Its LCG regeneration is for independent research;
the production conversion should use the codec's key directly. Firmware files
are not checked into the repository.

Required implementation acceptance tests:

1. Reproduce the old failure from actual staged bytes, including final-byte-count
   timing, zero marker and the mapped sense result.
2. Normalize supported KernelFront and KernelDerived inputs and independently
   decode emitted transfer bytes to the exact intended kernel. Cover multiple
   keys, chunk boundaries and generation markers with synthetic CI fixtures.
3. Verify same-family cross-SAT and same-SAT routes use the same conversion.
   Preserve rejection of incompatible families and structurally invalid inputs.
4. Test normal, CLI force/recover, unknown installed identity and automatic OEM
   restore routes at the common preparation boundary. Rejected inputs must issue
   no update-entry or write command. Validate second-session failures and readback.
5. Reject truncated envelopes, inconsistent lengths, bad checksums and unsupported
   layouts before transfer. Keep required tests independent of private corpus files.
6. Extend the receiver contract comparison across supported generations. The
   pre-12/22 upgrade/downgrade observation is not closed by testing this one receiver.

## 8. Remaining limits

The previous 107/107 envelope validation, 42/46 OEM host-code grouping and other
aggregate counts are historical research claims, not independently reproduced
coverage in this review. Retain full input manifests and analyzer revisions before
using them as release evidence. Codec success alone is not receiver acceptance.

The framing defect and its matching rejection mechanism are established offline
for the hashed artifacts above. The proposed normalization fixes their decoded
staging bytes. Production code changes, full OEM-session comparison, wider
receiver validation and physical acceptance of the corrected session remain
separate work. This document approves the correction direction, not universal
Pioneer support or an already-completed release.

## 9. Library API ownership (design update, 2026-10-07)

The public operation should be `receiver.flash(envelope)`: consumers should not
select codecs, assemble key tables or switch on KernelDerived. Names here are
proposed API names, not implemented types.

- `Envelope` is the common file-facing abstraction. Internal `EnvelopeCodec`
  implementations own structural recognition, validation, decoding and repacking.
  Shared transforms remain shared code. Registration is by supported format,
  never a model/SAT table. Detection reports unsupported and ambiguous formats
  explicitly; decoding success alone does not grant flashing permission.
- `Receiver` owns the device session and the installed receiver evidence. An
  internal `ReceiverCodec` trait has one implementation per proven receiver
  protocol. Detection uses read-only installed-firmware evidence and structural
  protocol recognition, independently of envelope detection. No model lookup or
  trial write selects a receiver. Unknown or ambiguous matches fail before update
  entry. Each implementation owns the proven receiver encoding and framing
  contract. Session sequencing, entry, completion and verification belong to the
  receiver protocol implementation, not to file codecs.
- `receiver.flash(envelope)` validates the complete update before the first
  mutating command. A Kernel/Normal update must supply both components as one
  validated update input; independent component calls cannot expose a partially
  flashed Kernel before discovering a Normal compatibility error. The exact
  container type remains a naming/API decision.
- The flash app handles user interaction, backup destination/durable storage and
  progress presentation. Required backup and compatibility checks must not become
  optional merely because the execution API is convenient. Force/recovery and
  automatic restore use the same validated preparation rules.
- A receiver replacement during an update invalidates the old receiver evidence.
  Subsequent sessions must use the newly installed receiver's proven contract.

The model-specific `raw_ud04_payload` decoder and its RawKernel/RawNormal cases
have been deleted from the local pioneer-optical implementation. No model-specific
replacement was introduced. Zero-key inputs may still match ordinary KernelFront
or Normal structure; that is ordinary codec recognition, not special backup or
receiver authorization. Normal decoding with a kernel must still satisfy the
receiver-policy path. Regression tests exercise multiple hardware identities.

The corpus/receiver audit remains a prerequisite to enabling the corrected live
transfer path. The codec architecture change must preserve exact round trips and
keep malformed/unknown inputs from reaching update entry.


### Corrected OEM preload trace (2026-10-07)

The OEM 212U 1.05 host does NOT send a 0x1200-byte Kernel prefix via F0.
At 0x402001–0x402003 it calls loader404350(1), selecting the Normal resource
and its length. The F0 loop then sends Normal[0..Normal.len()-0x10000]. At
0x4020CA–0x4020CC it reloads Kernel with loader404350(0) before generating
the 0x200-byte header and sending FE. Loader404350's branches at404384–4043DD
explicitly select resource pointer/length pairs59AA2C/59AA30 (Kernel) and
59AA34/59AA38 (Normal), updating working pointer59AA5C and length5ADA6C.

For the target212U package, Normal resource132 is0x1EA500 bytes at PE file
offset0x1ABD48, SHA-256
96abb6e00bc1d2a1c6802216ea82019ab2ab9b2b64647d5bd919c3b231c65f69.
The preload extent is therefore0x1DA500, not0x1200. Its key bytes200..1200
are byte-identical to the Kernel's independently recovered4096-byte key
(seed5787657). That supplies the correct key slot before FE writes.
The previously documented Kernel-prefix schedule describes our defective
implementation, not the OEM transaction. The normalized front-key candidate
supplies those same required key bytes directly; full-session equivalence
and all receiver generations remain distinct validation work.

## DVR scope and complete envelope census

Compatible DVR-to-DVR flashing is explicitly in scope. Hardware-family checks
reject incompatible pairs, including DVR-to-BDR; a shared DVR label alone does
not establish compatibility. Legacy formats are research targets for additional
codecs and receiver implementations, not permanent exclusions.

All 1,121 canonical envelope paths were loaded with the refactored codec registry:
305/367 Kernel,468/664 Normal and90/90 Plane load and repack byte-exactly.
256 have unsupported layouts (62Kernel,194Normal);2Normal payloads fail metadata
validation. These are path counts and file-codec results, not receiver acceptance.
The per-file hash manifest is retained in the private research archive under
pioneer-flash-framing-2026-10-07/all-envelope-census.json.

## Incremental receiver support (owner clarification)

Envelope loading and permission to flash are independent. A supported file codec
may load an envelope for which no receiver implementation currently supports
flashing. That is an explicit unsupported receiver/envelope pairing, checked
before update entry, not an invalid-file diagnosis and not a reason to guess.

Compatibility must include hardware family, component role and Kernel/Normal
pairing, authentication, image/receiver geometry, generation requirements and
transfer protocol. Missing hardware identity remains unknown; it is never filled
from the target. A different SAT tag within a supported matching hardware family
is not by itself a reason to refuse. Cross-family DVR/BDR combinations remain
incompatible. Force/recovery cannot invent a supported protocol pairing.

Additional file codecs and receiver implementations can be added incrementally.
Shipping the initial refactor does not require enabling every legacy DVR format;
unsupported matches must remain clear, deterministic and non-mutating.

## Exhaustive directional compatibility matrix

The release audit must exercise every held installed firmware against every held
complete target package in the same proven hardware family. A -> B and B -> A
are separate cases: the installed receiver determines initial acceptance, and a
replacement Kernel determines acceptance of the subsequent Normal component.
Include same-version reflashes, upgrades, downgrades and cross-SAT pairs. Do not
infer family membership from model names or SAT equality.

Run the library's real compatibility and transfer planning path for each cell.
For supported receiver protocols, independently decode the staged transfer and
compare the result with the intended component, checking authentication,
generation, geometry and component ABI. Include cross-family negative cases and
assert that every rejected or unsupported pair issues zero update commands.
Malformed corpus files remain explicit failures, not silently omitted fixtures.

Record source and target hashes, inferred hardware families, codecs, receiver
protocol, outcome, precise refusal reason, and independent validation status.
Keep verified, rejected and unresolved outcomes distinct. An exhaustive offline
matrix does not establish physical flashing success on every device.

Current envelope checkpoint: 989 of 1,121 paths load and repack byte-for-byte,
including 126 sparse checksum wrappers. Another 129 layouts remain unsupported;
two keyed Normals have declared/actual payload length mismatches and one sparse
Normal ends in a partial word. These counts are file paths, not unique devices
or certified flash combinations. Sparse-wrapper support removes and validates
the wrapper; it does not identify the enclosed instruction set or flash protocol.

### Hardware-family contract clarification

Matching hardware families mean valid complete firmware packages are expected
to work in both directions. Protocol and generation differences are the receiver
implementation's responsibility. A failed same-family matrix cell is a bug or
an unresolved implementation gap to investigate, not evidence of incompatible
hardware by itself. Do not make the matrix green by relabeling same-family
failures as expected incompatibilities. Damaged files, mismatched component
packages, and missing evidence remain distinct from a hardware mismatch and
must still stop before writes while the implementation gap is resolved.

### Release acceptance: preserve 0.10.7 functionality

Version 0.10.8 must retain every working 0.10.7 command and workflow while making
its implementation more robust. Establish the command and behavior baseline
from the 0.10.7 tag and test it against the integrated application. A previously
working path that becomes unsupported is unfinished implementation work, not an
acceptable release outcome. Temporary fail-closed guards during development do
not satisfy this requirement and cannot substitute for completing the receiver.
Correct rejection of corrupt inputs is separate from removal of valid behavior.
Target library version: pioneer-optical 0.11.0. Target application version:
freemkv-flash 0.10.8. Validate QA to green; do not promote main or publish without
an explicit subsequent user instruction.

## 0.10.8 QA candidate checkpoint

The application now sends the library's canonical Kernel representation for both
front-key and derived-key files. Normal validation authenticates the continuous
representation that is actually transferred. The former generated-prefix route,
its model-specific profile table, and the resulting cross-SAT refusal are removed.
Control-key and marker-policy recognition belong to `pioneer-optical` 0.11.0.

OEM restoration errors propagate; intermediate and pristine Kernel readbacks are
required. Restore feasibility is checked before the first update entry. This does
not make a failed or interrupted update transactional: component programming can
happen before the finish command.

Local validation at this checkpoint: 231 library tests plus a doctest, 593 firmware
workspace tests (two ignored), Clippy, and the no-std image build pass. The private
331-package directional matrix is a separate offline check; its results must not
be presented as physical-drive certification. Expanded legacy envelope/receiver
coverage remains research work after the QA candidate, per the revised sequencing.
The full `Receiver`/`ReceiverCodec` transaction API is not implemented by these
preparation helpers. No live firmware write was performed during this work.
