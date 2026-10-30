# MT1939 UHD candidate hardware check

Status: experimental software candidates exist for 24 source hashes. Physical
UHD recognition, data reading and decoding are unverified. Normal Modify and
website capabilities remain unchanged.

The candidate builder, original hashes, output hashes and offline admission
results are recorded in `mt1939-uhd-candidate-builds-20261026.json`. Three
settings per original produce 72 candidates. This is one shared authentication
hook, selected from the native VID/auth contract. It does not replace the
optical decoder or change classification thresholds.

## Representative input

WH14NS40 1.02, build N0002A0, native MT1939 boot banner:

- Original SHA-256:
  `40eb760e23f100d55e86e9c061c73428d4087ef712294e4dbfcefa3093837a1a`.
- Research On output SHA-256:
  `172fe1816302150fbca494dcd0624179800850fe59a0f101db1f0198f32e89f6`.
- Media-state byte: `0x01ff9dd3`.
- Runtime control table: `0x02001208`; Unrestricted is slot 3,
  at `0x0200120b`.

These addresses belong to this exact image. Other candidates carry their own
`state_address`, `flag_base`, and parsed `source_identity` in the manifest.
Select the candidate using the matching original hardware/firmware contract;
the shared model name alone is insufficient. No live installation has been
attempted by the research build or CPU tests.

## Evidence to collect

1. Record live drive identity, the exact installed candidate hash and its
   settings. Confirm the installed hook against candidate bytes or successful
   firmware readback; a matching revision string alone is insufficient.
2. Establish a normal BD read baseline on the same connection. Preserve the
   transport/sense result of each operation.
3. Test a known 66 GB UHD disc, then a known 100 GB UHD disc. BDA's ROM4 format
   includes 50/66 GB dual-layer and 100 GB triple-layer media, so a 50 GB UHD
   test alone does not exercise the higher-density/triple-layer cases.
   [BDA ROM4 format description](https://blu-raydisc.info/format-spec/rom4-spec.php).
4. Capture the packed media-state byte after insertion and after the failed or
   successful read attempt. Also capture runtime Unrestricted through GET
   immediately before and after the attempt. A client may change runtime flags;
   the baked setting alone does not establish the setting used for the read.
5. Collect capacity, raw disc-information responses and native sense errors.
   Exercise VID retrieval and actual content reads through the existing client.
   Validate sampled content across the layers against known-good content or a
   decoding check. Capacity or a VID response alone does not prove UHD reading.
6. Compare OEM, On and Off on the same candidate using the existing runtime
   feature controls and verified GET readback. SET changes RAM; avoid SAVE or
   RESET-to-OEM during this comparison because they have persistent effects.
   Use memory reads that retain explicit command errors; an error-filled zero
   buffer must not be interpreted as a genuine zero media state.

## How the result changes the next action

- A failure before VID/auth preparation, with no usable capacity or disc
  information, points to recognition or an earlier read path. The new hook is
  not sufficient for that case.
- OEM VID refusal changing to successful VID retrieval under On establishes
  the authentication gate's effect on the real disc. It still needs content
  reading and decoding checks.
- Successful VID retrieval followed by a data-read failure requires tracing
  the read permission, address/layer mapping and encryption path from that
  actual result. Do not keep widening unrelated signatures.
- On must preserve ordinary BD/DVD behavior. Off must reach the native failure
  for the selected BD band; OEM must retain its original alternate behavior.

No physical optical drive was present on the development Mac when enumerated.
A suitable MT1939 drive and UHD media are the outstanding external inputs.
