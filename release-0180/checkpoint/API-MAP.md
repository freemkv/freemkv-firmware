# Current API map for A/B/C/H/I

Extraction only, 2026-11-08 UTC. No implementation, physical-recipe or feasibility decisions. No tests, builds, device access, export, publication, commits or pushes performed.

## Source authority

- PO root `${EVIDENCE_ROOT}/filter-execution-0180/po-integrate`, HEAD `f16f0e9e381df138aa8d6f3ab97b9ee42b58a73b`, clean.
- FW root `${EVIDENCE_ROOT}/filter-execution-0180/fw-integrate`, HEAD `4e80beb252125f9a4606bc4804cc945a1c817d9c`; pre-existing ` M CHANGELOG.md`, `?? filters.md`, untouched. All 45 bound source/test/manifest files match their HEAD bytes.
- Global `~/.claude/CLAUDE.md` read. No local AGENTS.md/CLAUDE.md in frozen trees or checked tmp/Developer ancestry. Hindsight searched first; all findings below independently extracted from current sources, not historical claims.
- `source-bindings.json` records absolute paths, SHA256, HEAD-byte comparison, line counts and exact declaration source/line locations (including full type/trait declarations). `input_bindings` pins both filters.md copies, A/B/C/H/I packets and existing report scripts. No missing requested files. The main checkout filters.md is current planning authority; the scratch copy differs only in its first status paragraph (main says planning active and states the November 8 evidence/work deadlines).
- Paths below are relative to PO unless prefixed FW. The binding JSON is the exact signature inventory; line references below locate the important contract boundaries.

## A: registry, native observations and identity

`src/filters.rs:59` defines `Value::{Bool,U8,U16,U32,Bytes,Sequence,Variant}` and canonical encoding. `Finding::{Known,NotApplicable,Unresolved,Conflicting}`, `Assessment`, `Role`, `Comparison`, `Correctability`, `Rules` and `Policy` are the shared model. `Filter` (`:447`) supplies `id`, `name`, optional `rules`, `inspect`, `parameters`, `compare`, `candidate`, `plan`. Default planning compares observations and refuses unsupported differences; owner planning is invoked even when projected family identities match.

`register_filters!` (`:522`) currently registers **geometry, initialization, host, loading, layout, phase, startup**. `filters() -> &'static [&'static dyn Filter]` (`:538`) drives context inspection, runner and report definitions. There is no registered Controller owner. Existing `irq::Value::Controller` and phase `ControllerMode` are different concepts and cannot be mistaken for that new owner.

`Context<'a> { firmware: Firmware<'a>, sat: Option<SatEvidence>, ata: Vec<AtaEvidence>, native_phase: Observation<NativePhase> }` (`:275`) caches native discovery. `Context::new(Firmware)` is called for original and final inspections. `Firmware<'a>` (`src/compatibility.rs:69`) is `{ hardware: &'a str, normal: &'a [u8], kernel: Option<&'a [u8]> }`. No independent final identity authority type exists.

`src/filters/identity.rs`: `Domain`, `NativeValue`, `Entry`, `Key`, `Identity`; `discover(&Context) -> Option<Identity>` and `discover_with(&Context, &[&dyn Filter])`. `Key::canonical_bytes` (`:134`) prefixes `PIONEER-FAMILY\0\x07`, sorts by owner id during discovery, and includes typed owner contributions. Candidate projection and as-is values remain distinct. This is currently version 7; packet A's version 8 is future work.

`src/image/layout.rs`: `Observation<T>`, `Unresolved`, `H8ReaderComponent`, `H8ReaderRole`, `H8ReaderFunction`, `H8ReaderEvidence`, `AddressBasis`, `HeaderTest`, `WordEncoding`, `RecordRegion`, `LogicalDomain`, `ParameterLayout`. `RecordRegion` binds address/basis/allocation_bytes/record_bytes/record_count/header_bytes/header_test. `ParameterLayout::FlashRecords` has regions/encoding/domains. `src/image/layout/h8.rs:214` constructs exactly one region, `record_bytes:320`, `allocation_bytes:None`, and domain `0..=159`; this is the observed constructor limitation, not just renderer text. `discover_h8(normal, kernel)` and `discover_h8_reader(normal, kernel)` preserve explicit reader authority. `src/filters/layout.rs` serializes those observations into `Value`; `src/filters/initialization.rs::inspect` supplies current Inputs projection/initialization values.

Packet A's `DeclaredCodeEntry`, `FixedRamCallbackDeclaration`, `NativeVectorDeclaration`, `ProtectedByteRegion`, `DirectMemberTableDeclaration` are **not existing type names in current filters source**. Their ownership/execution distinction must remain an explicit interface decision supplied by A/native packets, not an assumed available API.

## B: exact current Normal-only composition boundary

```rust
// src/filters.rs
pub struct Preparation<'a> {
    pub target: Firmware<'a>,
    pub normal: Option<&'a Envelope>, // cfg(envelope)
    pub kernel: Option<&'a Envelope>, // cfg(envelope)
}
fn Operation::prepare(&self, context: &Preparation<'_>)
    -> Result<Option<Vec<u8>>, Error>;
fn Operation::verify(&self, context: &Preparation<'_>, normal: &[u8])
    -> Result<(), Error>;
fn Operation::required_words(&self) -> Vec<prerequisites::Word>;
fn Operation::integrity(&self) -> Option<Integrity>;
```

`Integrity` (`src/filters.rs:354`) has `id`, checksum `fields: Vec<Range<usize>>`, and `repair: fn(&Preparation<'_>, &[u8]) -> Result<Vec<u8>, Error>`. `be32_normal_integrity` insists original and output lengths/header fields match, preserves 16..20 as checksum input, and declares only 16..20 as repair fields. It has no component discriminator, Kernel checksum or extension certificate.

`src/filters/runner.rs`: `evaluate/evaluate_with -> Result<Plan<'a>,Error>` retain every `Decision`; `plan/plan_with` additionally call `admit`. `Plan` borrows original target `Firmware`, not installed bytes. It exposes `decisions`, `operations`, `required_words`, `admit`, `matches_components`.

- `Plan::prepare/prepare_with(&Preparation, [registry]) -> Result<Option<Vec<u8>>,Error>` (`:135`): checks registry/components, calls every operation against the same immutable original Preparation, refuses length changes, merges non-checksum differences, repairs once, calls final verification.
- `compose` (`:333`) requires equal integrity id/fields for multiple outputs; overlapping non-checksum changes refuse even if values match; repair may change only checksum fields. One output without integrity retains the legacy direct path.
- `Plan::verify/verify_with(&Preparation, normal, [registry])` (`:179`): reconstructs Context with **original hardware and original Kernel**, invokes selected operation verifiers, then compares untouched owner observations. This is the exact final-pair migration boundary.

`src/compatibility.rs`: `CorrectionPlan { target, expected: Option<Key>, runner, corrections }`. `plan_with_policy(installed: Firmware, target: Firmware, runner::Policy)` builds Contexts and runner plan; Strict stores installed as-is expected identity. `prepare_image(normal:&Envelope,kernel:Option<&Envelope>) -> Result<Option<Vec<u8>>,Error>` validates original envelopes, invokes runner, and `verify_image` rediscovers with original target hardware/Kernel. `prepare_normal` is raw wrapper; `prepare_file` invokes `rebuild_normal`.

`PreparedCorrection { id:String, image:Vec<u8>, corrections:Vec<Correction>, required_words:Vec<OwnedWord> }` (`:25`) and `CorrectionRequirements` are the receiver handoff; no decoded-pair/effect/result type exists. `representation::matching_components` checks Normal/Kernel kinds and nonempty equal hardware/destination/kernel_version/kernel_version2. `rebuild_normal(normal,kernel,image) -> Result<Vec<u8>,Error>` requires unchanged length, repacks Normal, signs according to the supplied Kernel policy, checks authentication and exact decoded equality. TailKey/BootKey/SparseChecksum use their own guarded branches.

Actual receiver chain (`src/receiver/preparation.rs`):

`prepare/prepare_without_family_check -> prepare_inner -> prepare_corrections -> plan_native_correction -> compatibility::plan_with_policy -> CorrectionPlan::required_words + prepare_image -> PreparedCorrection::native -> encode_correction -> rebuild_normal -> Update::load`.

`prepare_corrections:125` runs original Startup under ExplicitCrossflash **before correction** on family override. It deliberately retains a prerequisite-only result by cloning unchanged Normal when requirements exist. `encode_correction:203` emits only Normal. `prepare_inner:358` repacks the original requested Kernel, performs final family/startup checks, `plan_kernel`, settings, Handoff/ReceiverMarker/Target stages; verifies final stage Kernel equals target Kernel. Marker restoration therefore currently follows the unchanged target Kernel variable.

`src/receiver/stages.rs::PreparedStage::pair` repeats Startup Checks and Kernel handoff for each actual intermediate pair and validates transfer planning. `PreparedStage` owns receiving Receiver, decoded/encoded optional Kernel, decoded/encoded Normal, settings, bridge kind and Normal region. Its public image/transfer/settings/target_info accessors already expose per-stage evidence. `PreparedUpdate` owns stages, final Update and kernel steps; `PreparedNormal` owns a stage. These types, `compatibility/kernel.rs` and bridge preparation are downstream B migration dependencies, even though stages.rs is not on B's original exclusive-file list.

## C: requirement ownership and enforcement

`src/filters/prerequisites.rs`: `Word { parameter:u16,value:u16 }`, `OwnedWord { filter:&'static str,word:Word }`; `collect` rejects empty ids, parameter>=0x400, contradictory values and retains distinct owners. `check<E>(&[OwnedWord], impl FnMut(u16)->Result<u16,E>) -> Result<(),CheckError<E>>` deduplicates reads, refuses mismatch, accepts no writes.

`Operation::required_words -> runner::Plan::required_words -> CorrectionPlan::required_words -> PreparedCorrection/CorrectionRequirements -> settings::update::Plan::with_correction -> Plan::required_words(&self)->&[OwnedWord]` is the current plumbing.

`src/receiver/execution_safe.rs:664` `preflight_requirements<T:Transport,H:ExecutionRuntime<T::Error>>(stages:&[PreparedStage], reads:&mut T,runtime:&mut H,mode:ExecutionMode) -> Result<(),ExecutionError<T::Error>>` collects across **all stages**, rejects conflicts and settings ParameterWord overlap, binds stage0, refuses loader, calls `startup::migration::read` through the read transport. `execute_stages:707` runs transfer preflight and requirement preflight before its first stage; wraps failures BeforeWrite. PreparedUpdate/PreparedNormal `execute` consume this shared executor. No physical-case requirement, PreparedAlternatives or sealed branch/receipt type exists today.

FW `src/transport.rs:260` `read_memory_exact(&mut dyn ScsiDevice, off:u32,len:u32)->Result<Vec<u8>>` allocates len, invokes `drive::read_memory`, truncates to returned n, and returns Ok. A short read is currently not an error.

FW `src/crossflash.rs:58` `RouteRequirement` has only serde-tagged `ParameterWord { filter:String,parameter:u16,value:u16 }`. `Route { status:RouteStatus,requirements:Vec<RouteRequirement> }`, `RouteStatus::{Allowed,Conditional,Future}`, `CompatibilityStatus::{Yes,Conditional,SoftNo,HardNo}` are report contracts. There are exhaustive ParameterWord destructures in pair-combination conflict logic (`:237`), so adding a variant requires more than serialization changes.

FW `pioneer/mod.rs::offline_evaluation:486` derives requirements exclusively from prepared stage settings and classifies empty as Allowed, nonempty as Conditional. Both `offline_routes` and `OfflinePackage::routes_to` reach it; the cached package path reruns pair admission. `pioneer/flash.rs::report_settings` prints requirements. These three consumers and crossflash pair merging need the same closed requirement model as the executor.

## H: actual app admission and evidence seams

FW production Flash:

`pioneer::execute_plan -> classify_flash_input + header/tail/size checks -> authorize_installed -> authorize_installed_inner -> receiver_from_components -> normal_prepare::pair -> Receiver::prepare -> PreparedUpdate -> flash::execute_prepared -> execute_with_sleep -> PreparedUpdate::execute -> PO execute_stages`.

Normal-only branch in `authorize_installed_inner` checks installed Kernel tag/header agreement, decodes Normal using that Kernel, calls `normal_prepare::prepare`, then `Receiver::prepare_normal`. It cannot acquire authority for a replacement Kernel from an implicit pair.

Recovery chain: `recovery::Target::load -> classify_flash_input -> normal_prepare::pair`; `Target::bind(self,current:&Current,bypass_family_check:bool)->Result<Plan> -> Plan::assemble_policy -> Receiver::detect_with_kernel -> prepare/prepare_without_family_check`; `Plan::execute` uses `PreparedFlash::Complete` with Recovery mode. `Current::load` loads exact Kernel and Kernel-decoded Normal, checks kinds/protocol/vendor and receiver discovery.

`normal_prepare::load_pair(kernel:&[u8],normal:&[u8])->Result<Update>` retries only `UpdateError::Authentication` plus all-zero signature 0x170..0x1c0, signs an owned transfer copy, then reruns Update::load. Nonzero invalid signature fails. `pair` additionally prepares Normal for actual receiving Kernel, reloading if transfer representation changed. `prepare` checks complete recovered source, checksum, exact decoding/roundtrip and original receiver policy before re-encoding/signing. Fresh transfer authentication does not construct original provenance.

`flash::execute_with_sleep(dev:&mut WriteDevice,plan:PreparedFlash,mode:ExecutionMode,sleep:&mut dyn FnMut(Duration))->Result<UpdateOutcome>` makes separate read/write adapters, constructs runtime, reports settings, and invokes PO executor. It contains the current message "restoring the unmodified target Kernel" (`flash.rs:92`); related pristine text exists in routing warnings. Tests already supply recording ScsiDevice implementations. No real drive is necessary or authorized for H.

Focused extension points: `prepared_tests.rs` models prepared Flash and readback/write outcomes; `recovery_tests.rs` exercises original codecs, unsigned captures, family override and actual Recovery; `offline_cache_tests.rs` compares cached/uncached pair gates and conditionals. Existing corpus-wide ignored/golden runs are not a local requirement.

## I: report and measurement interfaces

PO owns `examples/hardware_matrix/{main.rs,page.rs,template.html}`. `page::rules()` iterates registered Filter metadata, requires rules for every owner, and emits id/name/role/correctability/description/correction/policies. `known_label` is still owner-id/value-specific presentation; A schema changes may require renderer updates. `page::analyze` and `data` use registry identity and observations.

`page::data(packages:&[Package],analyses:&[Analysis],failures:&[Failure],source:&Source,routes:Option<&Json>)->Result<Json,String>`; `check_routes(&Json)` checks object with routes array of objects only. It does not validate that routes match native/app revisions. `render(&Json)->String` substitutes one `__MATRIX_DATA__` slot and escapes script text. CLI usage is `hardware_matrix HOARD --out PAGE.html [--routes ROUTES.json] [--data MODEL.json]`; source revision derives from its compiled manifest root HEAD with dirty suffix.

Existing measurement scripts are pinned under `E/w5-hardened/cmp-guard/scripts/`:

- `freeze_app.py --firmware-revision REV --pioneer-revision REV --mediatek-revision REV --source-out JSON --firmware-dir DIR --build-dir DIR`: requires exact clean tracked FW HEAD, Cargo.lock dependency pins, sibling app-build.log, baseline input-integrity with842 verified packages; copies release executable once, records all hashes. **ROOT is script parent.parent**, so copying unchanged script changes where its baseline inputs are resolved.
- `run_export.py --source-manifest JSON`: checks frozen binary digest; uses manifest inputs/output/log and script-relative archive/state/routes-baseline.json; requires exact842 evaluated package set.
- `collect_route_decisions.py COMPARISON --binary BIN --packages ROOT --cache DIR --source-manifest JSON [--all-witnesses] [--workers N]`: executes `BIN --why --json SOURCE.tar TARGET.tar`, caches decisions; filenames derive package SHA256.
- `collect_rec_route_decisions.py --source-manifest JSON --binary BIN --tasks JSON --hoard ROOT --cache DIR --out JSON`: requires source/binary/task model revision agreement; executes same actual app CLI for supplied exact paths.
- `compare_routes.py BASELINE CURRENT --hoard ROOT --out JSON`: compares directed hardware identities and package witnesses with package indexes; retains separate MediaTek accounting.
- `matrix_routes.py EXPORT HOARD OUT`: reads export groups `{source,targets,status,requirements}`, evaluated_packages/version/freemkv_flash; expands actual package routes, adds source export digest and metadata. `rec_decisions_to_matrix_routes.py DECISIONS OUT` makes REC view.
- `combine_views.py --benchmark-view JSON --comparison JSON --rec-view JSON --source-manifest JSON --out JSON` joins views. `render_route_matrix.py MATRIX ROUTES --repo PO --out HTML --data JSON [--template-revision REV]` uses exact native model source revision and git-show template; optional presentation override is explicitly separate.

These are interface descriptions, not commands executed or an authorization to run exports. Renderer/generator provenance checks must be done by the executing parent; structural `check_routes` alone does not establish provenance.

## File collision ownership for implementation handoff

| Shared seam | Packet owner | Required coordination |
|---|---|---|
| filters.rs registry + Operation/Preparation/Integrity | B composition; A registry/metadata consumer; C requirements | One B editor; supply A owner registration/Rules and C requirement signatures before migration |
| identity.rs / initialization.rs / image/layout{,/h8}.rs | A, plus Layout E native producer | Complete schema/type from native packet; renderer I consumes resulting values |
| runner.rs / compatibility{,/representation}.rs / receiver/preparation.rs | B | Every owner Operation implementer, C handoff requirements, H receiver caller adapt together |
| receiver/stages.rs, compatibility/kernel.rs, handoff_bridge.rs | Existing B downstream dependencies | Assign explicitly if changed; original packet list does not give stages.rs exclusive ownership |
| prerequisites.rs / settings/update.rs / execution_safe.rs | C | B prepared artifact and H recording transport integration |
| FW crossflash.rs / transport.rs | C | I JSON consumer/export and H length-negative checks |
| FW pioneer/mod.rs / flash.rs | C and H overlap | C requirement/offline/report_settings; H app adaptation/execution tests; one editor or sequenced changes |
| FW normal_prepare.rs / recovery.rs / flash_plan.rs | H | B final pair identity/envelope API, C selected alternatives; preserve ordinary rejection gates |
| PO matrix example and docs | I | A Rules/schema and C typed route payload |
| FW Cargo manifest/lock + CHANGELOG | I | Final exact PO pin; preserve current unrelated CHANGELOG edit |

## Focused commands for later implementation (not run)

Set PO/FW to the roots above and CARGO_TARGET_DIR to a named scratch directory under `${EVIDENCE_ROOT}/`. Use only relevant rows after a change; CI runs full suites. Exact test names are present in bound sources.

```sh
cargo fmt --manifest-path "$PO/Cargo.toml" --check
cargo clippy --manifest-path "$PO/Cargo.toml" --features envelope,drive --lib -- -D warnings
cargo test --manifest-path "$PO/Cargo.toml" --features envelope,drive --lib disjoint_owners_compose_atomically_and_repair_one_shared_checksum
cargo test --manifest-path "$PO/Cargo.toml" --features envelope,drive --lib identical_overlapping_claims_refuse_instead_of_silently_collapsing
cargo test --manifest-path "$PO/Cargo.toml" --features envelope,drive --lib composition_requires_same_proved_integrity_and_repair_cannot_edit_code
cargo test --manifest-path "$PO/Cargo.toml" --features envelope,drive --lib registry_native_planning_runs_every_owner_even_when_family_hashes_match
cargo test --manifest-path "$PO/Cargo.toml" --features envelope,drive --lib final_filter_requirement_is_checked_before_any_bridge_write
cargo test --manifest-path "$PO/Cargo.toml" --features envelope,drive --lib conflicting_stage_requirements_refuse_before_device_io
cargo test --manifest-path "$PO/Cargo.toml" --features envelope,drive --lib recovery_loader_does_not_bypass_read_only_filter_requirements
cargo test --manifest-path "$PO/Cargo.toml" --features envelope --test hardware_matrix_page every_rule_statement_comes_from_code_not_the_template
cargo test --manifest-path "$PO/Cargo.toml" --features envelope --test hardware_matrix_page malformed_route_exports_are_refused
cargo test --manifest-path "$FW/Cargo.toml" -p freemkv-flash --lib cached_packages_preserve_pair_gates_and_conditional_requirements
cargo test --manifest-path "$FW/Cargo.toml" -p freemkv-flash --lib unsigned_targets_are_signed_only_for_transfer_and_invalid_signatures_still_fail
cargo test --manifest-path "$FW/Cargo.toml" -p freemkv-flash --lib prepared_flash_requires_matching_live_receiver_before_entry
cargo test --manifest-path "$FW/Cargo.toml" -p freemkv-flash --lib flash_without_live_requirements_never_accesses_persistent_parameters
```

Snapshot regeneration exists specifically in `tests/hardware_matrix_page.rs:184`: `PIONEER_UPDATE_SNAPSHOTS=1 cargo test --manifest-path "$PO/Cargo.toml" --features envelope --test hardware_matrix_page generator_model_matches_the_committed_snapshot`. This intentionally writes the repository snapshot and is for the later authorized implementation only. No expected hashes were edited here.

New Kernel/extension/finite-branch/Controller tests requested by A/B/C/H do not yet exist as passing API guarantees; add directly targeted cases after interfaces/native manifests are supplied. The six exact app positives remain fixture-ledger obligations under `E/w3-final/FINAL-INDEX.json`; existing tests must not be relabeled as those receipts without their exact source and component bindings.
