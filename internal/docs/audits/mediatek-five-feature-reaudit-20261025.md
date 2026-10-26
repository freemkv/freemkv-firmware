# Re-audit of the 97 baseline five-feature images

The baseline inventory had 97 accepted images with HRL, Encryption, Speed and
Region controls, but no Unrestricted control. The current exact-image planner
builds all 97 with all five controls, including OEM/On/Off for Unrestricted.
The set contains 40 OEM, 19 dump, 33 MK and five Omni objects; comparison inputs
are not a publication allowlist.

All 97 actual output builds pass `modify --json --audit`, match their preview
output SHA-256, and leave the source SHA-256 unchanged. The flasher admits 95.
Two dump objects are correctly refused as raw readbacks with copied boot pages:
`40118f8171da...` (BW-16D1HT) and `d286c5a7ea4a...` (BE16NU50). A successful
Modify build does not override this gate or approve a dump for publication.

The shared auth hook selects four operand/register contracts in this set:
62 R1StateR1, 23 R0StateR0, 11 R1StateR4 and one R0StateR5. They reuse two
register-parameterized emitted bodies, rather than model-selected patches.
BU40N's R0StateR4 also uses the same r0 body. The research classic alternate
path remains distinct and does not acquire refusal support from this change.

OEM replays the displaced CMP/BNE. On returns to the allowed continuation.
Off takes the validated native refusal continuation. An independent ARM CPU
executes 128 BU40N/WH state-and-setting combinations, checking the continuation,
r0-r12, SP and CMP flags. Before this fix, Off incorrectly accepted state C on
WH; that red case now passes. Older partial-capability records retain their
original On/OEM choices even under the new application.

Native UHD/BD discriminator hooks remain unavailable on these images; the
combined control is provided by the role-validated auth decision. This is
software build/behavior evidence, not proof of physical UHD reading. The complete
per-image hook reports, source/output hashes, producer binary hashes and flasher
results are in the adjacent JSON.

Reproduce:

```sh
python3 scripts/audit-mtk-capabilities.py --bucket five-feature \
  --hoard /path/to/hoard --fw target/debug/freemkv-fw \
  --flash target/release/freemkv-crossflash \
  --output internal/docs/audits/mediatek-five-feature-reaudit-20261025.json
```

The seven OEM allocation cases were also rebuilt and re-audited after this
change; their preview hashes and flasher admissions still pass. Other corpus
buckets and final publication integration remain open.
