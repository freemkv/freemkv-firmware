# MT1939 detection investigation for 0.15.5

Current priority: hold further MT1939 hardware candidates while MT1959 OEM
operation and missing-media conversion are investigated first. The internal
reacquisition comparison below is retained evidence, not a ready tester BIN.

Branch starts from validated 0.15.4 dev 620b05f. The full prior research is
retained on research/mt1939-uhd-detection (7bcab5f), including unsuccessful
format-1/5 detection candidate 8a7ffc47. Production UHD conversion remains
unavailable. The first 0.15.5 initialization experiment below failed physical
detection; subsequent work remains an isolated research comparison.

## Milestones and constraints

Disc detection first, sector reading second. Keep DVD/BD working and use only
processor-supported Thumb instructions. Production locators must bind native
instruction roles/signatures and reject missing or ambiguous contracts.
Compare acquisition and DI-ready prerequisites against native UHD-capable BU40N
and MT1959 references; do not infer physical acquisition from supplied-DI CPU
checks, force DI-ready, or transplant hardware constants without a mapping.

## Tester evidence

The latest Windows PnP HardwareID output identifies HL-DT-ST BD-RE BH16NS48,
revision 1.02, and generic CD-ROM compatible IDs. The transcript has concatenated
fragments and a malformed displayed Where-Object expression. None of the supplied
fields report a disc profile, capacity, DI state, or SCSI sense. It does not locate
the UHD failure or imply damaged firmware identity.

The tester previously reported DVD and ordinary BD working after the Thumb-1
fix, and no improvement in UHD detection with the format-1/5-only experiment.
The screenshots show no matching recent cdrom events and a command-paste error;
those red messages are not a captured drive sense response. Which medium was
present for the MediaLoaded=False query remains unconfirmed.

The standalone administrator diagnostic executable was rejected by the user.
Do not ask the tester to run it again. Built-in PnP/WMI queries identify the
registered drive and media visibility but do not supply the missing vendor SRAM
snapshot or acquisition control flow.

## Isolated post-DI initialization mode experiment

The BH16NS48 native initialization caller runs DI parsing at 0x69190, then its
mode function at 0x692e8 (callee 0x67728). Accepting U/5 creates C7. With native
routing unchanged, that mode function leaves mode 7 at 0x01ffa20d. Its native
C8 path selects 0x1c. BU40N OEM 1.00 independently selects 0x1c for both C7 and
C8 in its complete native mode function at 0xdae00. This is a post-DI software
difference, not proof that the tester reached DI or that it caused the failure.

The new research comparison changes only MediaDefaults in addition to the
previous U/1 + U/5 recognizer. The component is selected by ClassicConsumer's
source-bound instruction/parent/state contracts. Addresses above are receipts
for the held source, not patch selectors. It routes into the original image's
own C8 continuation; no hardware constant or routine is copied from BU40N.
The DI stub is 160 bytes and the mode selector 280 bytes (440 total). The wider
routing, read, position, calibration, authentication and acquisition components
stay native. Both additions compile only into research tests, not production
Create/Modify. The retained component emitter no longer includes the full-group
production installer.

Build producer: FREEMKV_MT1939_RESEARCH_SOURCE, FREEMKV_MT1939_RESEARCH_SHA256
and FREEMKV_MT1939_RESEARCH_OUTPUT select a provenance-pinned comparison via
mt1939_initialization_tests::build_selected_initialization_comparison.
It writes baseline and mode BIN/JSON pairs. The experiment's research flag is
fixed On; it does not advertise complete Unrestricted support.

Validation on BH16NS48 1.02:

- Base structural audit, metadata, signing/CMAC and offline Flash admission pass.
- Independent ARM926 execution: 16,384 complete native mode-function comparisons
  (256 states, four runtime flags, all 16 incoming NZCV combinations). Baseline
  matches OEM; only C7/On changes RAM, and only the one mode byte changes to 0x1c.
  Native C8 and native BU40N C7/C8 executions independently produce the same mode.
  Saved registers, SP and native returns remain balanced.
- Complete installed DI parent: 6,400 cases (48 recognition, 6,352 preservation),
  plus eight unchanged early failure/abort boundaries. Hardware acquisition is
  explicitly simulated; these checks do not establish physical detection.
- BE14NU40 classic fixture installation/preservation check passes; Clippy with
  test code and warnings denied, formatting and whitespace checks pass.

Candidate SHA-256:
618ebd55cd109ba37188ab0d4e294c66d73d51f3eb5ee43fb64a1b972616285a.
Full source/installation receipts and CPU results accompany this note in JSON.

This hypothesis affects the two-layer C7 path. A three-layer C8 disc already
uses the native dense mode and is not a test of this specific difference. Tester
capacity/title confirmation is pending. No physical detection or sector-read
success is claimed.

## Resident acquisition boundary checked across known UHD references

Native DI parents in BU40N OEM 1.00, BU40N MK 1.03, WH16NS60 MK 1.02 and ASUS
BW-16D1HT MK 3.10 call ARM literal veneers whose targets are respectively
0x01f95087, 0x01f95143, 0x01f94c5f and 0x01f91be7 (Thumb bit included).
These addresses are outside the supplied 2 MB images. The decoded boot and
application scatter tables do not map/copy any of these target bodies. This
narrows the available evidence; it does not prove that they are immutable mask
ROM or rule out another runtime loader. Do not subtract an assumed flash base
and treat unrelated bytes as the missing acquisition implementation.

## Failed physical trial and downstream audit

The tester reported "Same 🙂 It tries hard but still not working" for candidate
618ebd55. Detection is therefore still unachieved. Preserve the Desktop image
unchanged for attribution; do not present its CPU checks as hardware success.

`scripts/audit-mt1939-mode-consumers.py` executes the held original, failed
candidate and native BU40N position and setup functions (192 executions). Controller busy bits
are supplied idle and arithmetic results are synthetic. It proves differences
in operand programming and result scaling, not controller mathematics.

The mode byte is an offset into seven-byte records: 0x1c selects the fifth row.
It is not a literal laser-power or speed setting. At C7 the failed candidate
retains classic position scaling, while native BU40N explicitly treats C7 like
C8. The classic C8 path quarters the coefficient and shifted input, then doubles
the controller result before final scaling. Selecting the dense row alone does
not reproduce this behavior. Secondary-bank consumers and their caller guards
still require tracing; not every table bank has five meaningful records.

The complete setup function independently confirms the same missing C7 branch:
BU40N C7 and C8 program identical values, while classic C7 leaves the input and
coefficient unquartered and supplies 10 where its dense path supplies 20 to a
later controller operation. Controller operation semantics remain unproven.

Executing the actual DI parent on re-entry supplies another concrete mismatch:
with initial C7 and profile 0x1c, the native pre-acquisition selector stores 7;
C8 preserves 0x1c. Native BU40N explicitly recognizes C7 at this stage. This is
a software incompatibility, not evidence the physical trial reached re-entry.
Two recovery stores of 7 also exist in BU40N and must not be indiscriminately
removed.

The research builder now separately emits a `reacquisition` comparison using
the source-bound DiMode role alongside MediaDefaults. The original baseline
and mode-only outputs remain reproducible. Read, position and acquisition
components remain native. `scripts/test-mt1939-reacquisition.py` exercises the
complete installed parent to check the intended C7/On profile change and
preservation of other states, flags, registers and stack.
Both research builder tests pass. ARM926 execution passes 4,096 complete-parent
comparisons across all 256 starting states, four settings and four incoming NZCV
patterns. Only C7/On changes the profile from 7 to 28; other observed RAM and
return values match the mode-only baseline. Hardware readiness remains supplied.

Next: validate the reacquisition fix, trace position setup and the remaining
initialization/readiness consumers against native BU40N, then produce one
coherent detection experiment. Sector reading remains the second milestone.

## Hardware-versus-logic evidence gate

An explicit C7 branch in BU40N is not sufficient evidence that BH16 must take
that branch: controller design, optical mechanism and parameter interpretation
may differ. The existing native BH16 C8 path makes reuse a hypothesis worth
testing, not a demonstrated hardware mapping. The reacquisition build remains
internal while this distinction is investigated; no new tester image is ready.

First build a read-only scanner over the held MediaTek corpus, then compare five
OEM MT1959 families and our own modifications of the same source bytes. Keep MK
and OmniDrive categorized separately and out of the five OEM references. The
scanner example `mtk_uhd_scan` uses existing library instruction contracts for
DI recognition, control-bit/field selectors, forward/reverse calculations,
parameter selection and read-only hardware defaults. Unknown/ambiguous layouts
remain unknown, never evidence of absent support. Neither a six-role native
classification nor an authoring success establishes complete acquisition,
physical reading or permission to read protected content.

`--modify-pairs` additionally builds unrestricted-On images offline and reports
which original reviewed regions remain byte-identical, each emitted hook and
the modified image's separate scan. This distinguishes existing native media
logic from what our unlock actually changes, with no device or flash access.
