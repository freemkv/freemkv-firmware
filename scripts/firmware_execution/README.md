Current readiness and remaining dependency are recorded in [the status report](../../internal/docs/audits/mt1939-plus-earliest1959-status-20261031.md). The earliest image is deliberately refused; a conditional helper pass is not complete conversion readiness.

The acceptance entry point is `corpus.py`. It accounts for every record in the supplied inventory, constructs outputs using the production `modify_with_defaults` API, compares the shipping CLI output bytes, and executes bounded OEM/patched hook traces with Unicorn's ARM926 model and an additional Thumb-1 legality check. It never flashes hardware.

Run with the private Python environment described in `requirements.txt`:

```sh
/tmp/mt1939-recognition-venv/bin/python scripts/firmware_execution/corpus.py \
  --build \
  --inventory internal/docs/audits/mediatek-uhd-corpus-20261030.json \
  --hoard /Users/matthew/Developer/firmware-extractor/hoard \
  --builder target/release/examples/firmware_execution_evidence \
  --fw target/release/freemkv-fw \
  --output /tmp/mediatek-corpus-differential-20261030 --workers 6 \
  --dependency-commit 54bf1e5648516abce4f70ae91ce489d743ee6123
```

The example is a test harness for production APIs, not an alternate emitter. Its source-bound contracts bind native instructions/continuations and actual installed facts; expected differences are separately implemented in `stages.py`. Neither a changed byte nor an emitted hook automatically passes. All registered hook roles are listed, including unsupported contracts. Missing, unrecognized, refused and failed inputs retain explicit per-image records. DE-only outputs receive static-only status.

The independently encoded software oracles are:

* Auth-cell: On selects the native accept continuation; Off refuses; OEM/invalid settings preserve the original comparison, every live GPR, stack and NZCV. The alternate native-class implementation instead preserves On/OEM and only refuses native class C on Off.
* CDB gates: replay the native byte load and native comparison; Off forces non-equal. The retired BD slot has no effect. These are command-key classes, **not optical media classification**.
* HRL: Off selects the native clean continuation; On/OEM and invalid settings preserve the native decision and live registers. It does not manufacture a successful certificate or execute the lookup worker.
* Speed: modern ramp ceilings are 255 for On, 50 for OEM, otherwise the explicit byte; the classic selector uses a native maximum only for On and a valid maximum in 1..48. The current modern implementation's Off=0 ceiling differs from the ABI enum comment describing Off as uncapped; these tests document the implemented stub contract and do not resolve that product-policy conflict.
* Region: native store sequence for OEM/invalid; [0,0,0,0] for RPC-1, [native-TypeCode,255,1,0] for Off, independently computed inverted DVD masks. The advertised ABI BD-force states 0x0a..0x0c conflict with the emitted <0x11 guard and are explicitly reported as a contract conflict; the stale source comments naming 0x2a..0x2c are not used as an oracle. These are observed software stores to a mapped FIFO address, not a physical FIFO model. Forced region encodings retain the production source's hardware-validation limitation.
* Boot: all original native arguments and R4 survive, the selected production defaults are written exactly, and the actual initialization target receives an aligned stack. Execution stops before that native target. Its effects and return remain unknown.
* VID/AKE/deny-reset: native decisions and live state are compared through the actual next continuation or native call entry. The suite stops at reset/setter boundaries; no callback returns invented hardware success. Unexecuted call bodies, their effects and return paths remain coverage gaps.
* Vendor-handler: every ordinary mode except the freemkv mode must reach the exact OEM handler; safe SET prefixes check feature bounds and the exact flag write before the first source-resolved writer call. GET/identity/unknown safe prefixes reach that same first writer with its clear-response arguments. Reply loops, commit, save/flash/debug paths and all native services remain unqualified.

Installed classic conversion helpers are tested at their actual production BL sites. Source branch decoding independently binds native C8 accept/reject continuations. Every state byte and all relevant incoming C/V combinations are compared for native selectors; only C7/On may add the C8 route. The actual in-image ARM divide worker executes in the forward/reverse numerical comparisons. No worker return is fabricated. Read-position decoding and calibration loads use this same image's source contracts/tables.

MediaSelected getters also execute from their actual function entry. C7 retains its OEM rate list, count and selected index; On selects that image's native exact-C8 coefficient at that index. The coefficient oracle executes the OEM CMP/accepted branch independently. Every C7 request byte and representative rate boundaries for all 256 states are checked across flags, with unprovided RAM reads rejected. Out-of-range requests stop at the real logger call; its return and later clamp remain gaps. State-independent getters have no installed selector helper and are reported separately. A native BU40N getter receipt independently establishes the C7/default-rate and exact-C8 coefficient-table policy.

The native BU40N startup oracle independently confirms that C7/exact-C8 select the same special table used by their getter. It executes all state bytes and four native indices through the real startup lookup, plus entry rate thresholds up to the first service. Runtime-only coefficient tables use separately labeled synthetic software input patterns for selection/index tests; actual initialized profile values and their producer remain unqualified. The startup/calibration tests use the source-bound signed base adjustment, index count and working-pointer register, including earlier application layouts.

`--baseline-receipt prior.json.gz` adds exact canonical/output byte comparisons. A preserved output can establish absence of a new byte regression while a CPU case remains failed, as for the modern AKE WideB/requested ARM926 profile mismatch. This comparison never turns failed CPU execution into a pass.

DI admission is checked against all 1,024 state/attribute results of an immutable native BU40N predicate, entered after its prefix validation and diagnostics and stopped before identifier routing. That predicate calls no service. Ordinary identifier/format/layer classes and Off/OEM/invalid flags preserve the original prefix; accepted U/5 inputs traverse the installed helper, actual native format dispatcher and layer store, compared with the OEM shared routine using the independently selected identity. These entry points exclude acquisition and full drive readiness. Every image retains explicit whole-pipeline gaps and a false conversion-goal qualification until those gaps are closed.

Use `--only-conversion` with `internal/docs/audits/mt1939-production-differential-inputs-20261030.json` for the focused 29-image run; ordinary hooks are explicitly marked not-requested. The default run executes every registered available contract.

Generated helper CFGs are walked without decoding literal pools as code. Receipts contain instruction/conditional-edge coverage and explicit unvisited edges; static CFG resolution failures are gaps. Per-case gzip JSONL logs bind inputs, continuation, GPRs, SP/LR, NZCV, writes and instruction traces. Rejected instruction attempts retain failure traces. Exact input/canonical/output, suite/source, dependency, builder, CLI, report, contract and trace digests are retained. A source or binary change during a run invalidates current-source attribution.

Each corpus run freezes a deterministic `source-snapshot.tar.gz` before starting workers. It includes the project execution sources and exact resolved mediatek-optical source files. Build, snapshot and final manifests must agree; the snapshot verifies every captured byte before archiving. Dependency source changes are checked separately from the repository manifest and pinned Cargo.lock revision.

The real-output mutation checks require a builder output directory containing an auth-cell hook:

```sh
MT_CPU_FIXTURE_DIR=/path/to/output/native-auth-image-sha256 \
MT_UHD_CPU_FIXTURE_DIR=/path/to/output/classic-conversion-image-sha256 \
MT_CPU_HOARD=/path/to/hoard \
  /tmp/mt1939-recognition-venv/bin/python -m unittest discover \
  -s scripts/firmware_execution -p 'test_*.py' -v
```

They require passing production auth, DI and native-math contracts. Conversion mutations additionally reject removed recognition/routing edits, incorrect UHD identity/continuation and unintended native coefficient changes. The auth mutations require a passing production auth contract and reject a no-op intended patch, unconditional acceptance, live-register corruption, a cleared Thumb continuation bit, and Thumb-2 injection. CPU-specific tests also validate branch-gap accounting and refusal of an unknown CPU family.

`run.py` is the earlier two-stage runner retained for reproducibility. Its media profiles repeat CDB gate tests and do not establish optical-path coverage. Use `corpus.py` for the broader acceptance record.

No finite set of RAM-input executions proves all firmware paths, optical acquisition, native/resident/MMIO workers, dynamic branch targets, physical layer boundaries, real AACS completion or successful physical UHD reads. Complete conversion is qualified only if a production group is installed and every required contract is independently established; an unavailable conversion hook remains unavailable.
