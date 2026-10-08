# Firmware inspection and comparison: generic Flash workflows and Pioneer analysis

Status: implementation and local user review in progress. 2026-10-08.
Versions: Pioneer Optical 0.12.0; FreeMKV Flash 0.11.0.
QA remains a delivery gate; local preview is not a release or QA sign-off.

## Ownership decision (supersedes the original proposal)

Pioneer Optical analyzes one envelope. It exposes regions, decoded/expanded
bytes, recognized metadata and tables, and image-local instruction/reference
facts and runtime mappings. It has no pairwise comparison API, matching engine,
difference classifications or percentages.

Flash projects provider facts into a vendor-neutral comparison model.
Its shared engine owns pairing, alignment, reference correspondence, metadata
exclusion, record differences and byte accounting. It does not decode Pioneer
instructions or discover COMP layouts. The generic report layer supplies the
reviewed Inspect/Compare presentation.

## User review decisions

Inspect and Compare open a separate, resizable results window. Hardware family
remains first, with both source IDs and their relationship in Compare. Inspect
uses aligned values and bold labels. The normal user view omits codec names,
the semantic-coverage footnote, raw hex pages and logical-byte fields. Signature
status is plain English. Remove the record filter, Use in Compare as A and Swap.

Compare defaults to a short component summary and an expanded Changes by region
table. Technical details and excluded relocations remain collapsed. Show the
percentage different after alignment per component and region. The metric is
the sum of changed logical bytes on A and B divided by their combined logical
sizes. Decoded body bytes and expanded stream bytes each count once; compressed
storage is replaced by expanded data. Verified relocation and metadata changes
do not enter the changed numerator. Unresolved work is reported separately.
This is a byte-content metric, not behavioral equivalence.

The earlier UI proposals below are superseded by these user-review decisions
where they conflict. Requirements for analysis accuracy and QA validation remain.


## Outcome and scope

FreeMKV Flash gains two vendor-neutral tabs: Inspect firmware accepts one firmware file or connected drive; Compare accepts two firmware files, or one firmware file and one connected drive. The first supported analysis provider handles Pioneer TAR packages. For a supported live source it captures once through the existing backup workflow, then performs all analysis offline. Pioneer Optical owns firmware decoding, decomposition and single-image structural interpretation. Flash owns generic alignment and pairwise comparison of analyzed facts. The app owns input selection, capture, orchestration, English presentation, pairwise comparison, and report export.

The question answered is: what changed in the decoded firmware, after accounting for packaging, compression and verified relocation? The result is not a behavioral equivalence proof or a flash authorization. Different hardware families may be compared. No receiver preparation or update-entry operation runs during comparison.

Include BDR and DVR envelopes supported by the existing codecs. Structural/code/table support is independently reported; a successfully decoded envelope does not imply all its contents are understood. No model-name profiles, corpus dependency, or OEM recognition requirement. The implementation targets Optical 0.12.0 and Flash 0.11.0.

## Existing implementation to reuse

Verified against current source:

- Optical `Envelope::load` and `load_with_kernel`, envelope inspection, family and ABI APIs.
- Optical public `envelope::comp_streams`, `CompStream`, and `CompStreamInfo` already provide directory discovery, bounded decompression, expanded bytes, offsets and hashes. The private `comp` directory parser is shared infrastructure.
- Optical `CodedError` provides stable namespaced identifiers and typed diagnostic parameters.
- Flash `pioneer_bundle::Bundle` validates TAR members; `from_backup_tar_bytes` additionally admits Kernel-only partial backups for inspection. Flash input restrictions remain separate.
- Flash `workflow` is shared by front ends; GUI `ops::Job` and `app::Task` provide the worker and tab integration points.

Do not add a second inflater, envelope decoder, family calculator, backup reader or banner parser. Refactor shared internals when richer errors are required, preserving existing public API behavior. The existing COMP API returns Option; new analysis must distinguish absence, invalid structure, ambiguity and resource limits through a shared checked parser rather than interpreting every None as “no streams.”

## Ownership and proposed module layout

Optical: optional `analysis` feature depending on `envelope`; existing no_std/default/drive users acquire no analysis dependencies. Public `analysis` module contains single-image model, region, table, reference, evidence, limits, progress and error types. Internally separate COMP adapters, structural recognizers and architecture instruction decoders. Pairwise matching and relocation correspondence live in Flash. Tests live in sibling test files.

Flash: shared vendor-neutral comparison workflow module accepts sources, detects formats, resolves a supported analysis provider, captures a drive if requested and produces an app report. Its Pioneer adapter calls Optical. GUI owns controls and rendering only. English messages and export DTOs live outside the GUI so a later CLI can reuse them. A new CLI command is not required for the first Compare tab release.

No Ghidra installation, external executable, network lookup or Python dependency in the product. Offline research tools may validate results. Architecture support is explicitly detected; do not interpret arbitrary bytes as H8 instructions.

## Generic provider boundary and hardware-family priority

The app-facing types are `CompareSource`, `DetectedFormat`, `AnalysisCapabilities`, `HardwareFamilyIdentity`, `CompareReport`, and `CompareDiagnostic`. Their core fields contain no Pioneer SAT, Kernel, Normal or COMP assumptions. A report contains named components/regions and structured findings supplied by a provider. Pioneer-specific facts appear as additional typed provider details; the generic renderer needs no SAT/model switch. No Pioneer parsing or instruction decoding moves into Flash; vendor-neutral raw-byte matching belongs in its comparison engine.

Use a small internal `FirmwareAnalysisProvider` interface in the shared app workflow: recognize a source, describe inspection and pair-comparison capabilities separately, analyze supported captured/file inputs, compare supported analyses, and adapt library results into app reports. Keep the Pioneer implementation in its own module. Detection reuses existing format/drive identification; single-source analysis uses Optical; pairwise comparison uses the shared Flash engine. Future MediaTek analysis belongs in an appropriate vendor library and plugs into this boundary. This is not a public dynamic plugin framework.

Capability detection is independent from flash support: a flashable drive can lack comparison support. Resolve both source capabilities and the provider's ability to compare the pair before capture. Device identity discovery may open a drive for inquiry; that does not authorize a firmware backup when comparison is unsupported. A preflight success does not guarantee the captured firmware layout is supported; a later decode error retains the saved capture and reports the precise limitation.

Hardware family is the first result field in GUI, text and JSON summary. Display a relationship of Same, Different, Unknown or NotComparable, followed by A and B family identities and their derivation when available. Family IDs carry a namespace and derivation version; equal-looking values from different vendor schemes are not equal families. Do not substitute a marketing model, SAT string, or broad chipset label for a hardware compatibility family. Unknown on both sides does not mean Same. A missing Normal may mean Pioneer family cannot be derived; report Unknown with the reason.

A different family never blocks comparison and requires no force option or confirmation. The provider still compares every supported component/region. A cross-vendor pair may be NotComparable under current providers: this is a format/analysis limitation, not enforcement of flash compatibility. Family classification is source identity information, independent of excluding descriptive headers from changed-content counts. Matching family does not replace existing receiver/flash checks.

Examples of initial outcomes:

| Selection | Outcome |
| --- | --- |
| Two supported Pioneer packages, same family | Family first: Same; full supported analysis. |
| Two supported Pioneer packages, different families | Family first: Different; analysis still runs. |
| Pioneer file and supported Pioneer live drive | Capability preflight, backup capture, then family result and analysis. |
| MediaTek file or live drive without an analyzer | Show detected identity and “Firmware comparison is not yet supported for this MediaTek format.” No capture. |
| Standalone Pioneer ENC | “For Pioneer comparison, select the TAR package containing the firmware.” |
| Pioneer and MediaTek | “These firmware formats cannot currently be compared.” Include both detected formats. |
| Unknown input | “This firmware format was not recognized.” Distinguish from recognized-but-unsupported. |
| Recognized but malformed supported input | Precise validation error; do not mislabel corruption as unsupported. |

Use stable app error codes such as `compare.unsupported_format`, `compare.unsupported_pair` and `compare.unrecognized_format`, with structured side/format parameters. UI wording is English initially. Unsupported source selection remains visible and replaceable, with an explanation; no generic crash/error popup and no forced device operation. The report's family summary appears as soon as analysis establishes it, even if later comparison fails or is partial.

## Optical API contract

Proposed names, to be checked for consistency during implementation:

| Type / entry point | Contract |
| --- | --- |
| `Envelope::analyze(options, observer)` | Produces an analyzed component from an already decoded envelope. |
| `FirmwareSet` | Groups optional Kernel and Normal references from one source; supplies same-source context for cross-component address resolution. It does not impose flashability. |
| `FirmwareSet::analyze(options, observer)` | Analyzes components once and shares context/caches. |
| `FirmwareAnalysis` | Immutable parsed components, regions, tables, capability/coverage records and diagnostics. |
| Flash comparison engine | Compares two provider-neutral analyses with evidence and limitations. |
| `Comparison` | Per-component findings, separate per-side accounting, exclusions and completeness. |

A consumer can compare the analyses of a simple envelope pair; a package pair supplies more context. Do not define one overloaded equality boolean meaning both byte equality and normalized similarity. Provide explicit exact-decoded equality and a comparison conclusion.

Analyses borrow decoded envelope bytes; inflated streams are owned once by the analysis. Reports own compact findings/IDs, not duplicate firmware images. Byte detail is retrieved from the retained analysis when the app renders it. Avoid self-referential ownership; the worker retains envelopes until its analyses are released. Exported reports are independently owned metadata.

Public structs use accessors and non-exhaustive enums where future recognition is expected. Logical IDs are deterministic within an analysis, never raw memory addresses. No public plugin ABI or dynamic dispatch registry is needed initially. Internal recognizers return NotApplicable, Recognized, or InvalidRecognizedStructure; ambiguity is retained, never resolved by first-match order. Built-in architecture and table recognizers can use small internal traits where multiple implementations exist.

## Source acquisition and package rules

A source has side A/B, source kind, file/capture digest, component inventory, identity facts, tool versions and provenance. A is the baseline and B the comparison; swapping reverses additions/removals but not equality.

- Accept Kernel+Normal and Normal-only TARs. Accept existing Kernel-only partial backup TARs for comparison, labelled incomplete; this does not make them flashable.
- Retain existing member, path, size and duplication checks. Do not extract archive members into arbitrary filesystem paths.
- Identify component roles from decoded/header facts, not filenames or TAR member order.
- Decode each side independently, using only that side's Kernel when required. Never silently borrow the other side's Kernel or query a drive to supply missing context.
- If Normal requires an absent Kernel, report “Normal could not be decoded without its matching Kernel.” Compare other available components. A future explicit context selection may extend this, but is not part of initial UI.
- Missing and failed components are different states. Neither counts as a deleted firmware component or an equal component.
- Duplicate/ambiguous component selection is an input error; do not guess.
- Unknown/zero signature status is provenance, not a comparison veto if decoding and structural validation succeed. Corrupt or unrecovered bytes are never silently treated as valid zero padding.

For live input, use the normal firmware backup path, not the full RAM/register dump. Save a uniquely named capture TAR in the configured backup directory using existing backup naming and collision rules; show the destination before starting. Save the capture before analysis so the result is reproducible. Retain it on analysis failure/cancellation; report any partial backup explicitly. If saving fails, stop rather than claim a reproducible capture exists.

Use one live source at most. Validate the file source before opening the device. Serialize capture with other device operations. Firmware-read unlocking required by backup is permitted; no flash preparation, erase/write/update entry, tray manipulation introduced specifically for comparison, or logging-enable command. Release the device after capture. Offline file comparisons neither discover nor open drives.

## Decomposition and address model

Every decoded source byte has an accountable owner: structural metadata, code/data region, compressed storage, recognized padding, or unknown. Expanded stream bytes have a separate logical accounting domain. Parent regions and their children must not be double-counted.

Locations distinguish envelope-file offset, decoded component offset, expanded-stream offset, and device/runtime address. A compressed byte range does not have a fictitious one-to-one mapping to expanded bytes. Retain its enclosing compressed source range instead. Runtime mappings must carry their derivation; unknown addresses remain unknown.

COMP directory entries expose storage geometry. Their existing addresses must not automatically be treated as the runtime addresses of expanded code: runtime placement requires separate evidence. Copy-to-RAM code can supply a mapping only when source, destination and length are established. Multiple aliases are explicit.

Region kinds: code, media table, other structured table, opaque data, metadata, padding and unknown. Record recognized format and evidence separately from kind. A stream index alone is not a semantic classifier. Structural signatures, boundaries, record validation and relevant code references determine interpretation.

The current XD examples contain BD/DVD/CD media/strategy streams, smaller tables and an H8 code stream. These are research fixtures, not a universal six-stream layout contract.

## What is excluded and what counts

Default comparison is content-focused; envelope headers, keys, signatures and encrypted representation are shown only as source metadata. Recognized embedded identity fields and validated derived checksums are excluded from substantive counts but retained in the audit detail.

Do not exclude a whole embedded header indiscriminately: load addresses, lengths, control flags and unknown fields can affect operation. Only positively identified descriptive fields and correctly validated derived fields qualify. Invalid checksum fields remain diagnostics. Uniform 00/FF runs are not automatically padding; recognition must establish their structural role. Unknown bytes remain in scope.

Verified relocation-only changes are excluded. Constants, changed register addresses, changed call/branch targets, added/removed instructions and changed data/table bytes count. Unsupported or ambiguous interpretations remain unresolved changes, not ignored changes.

## Comparison algorithm

1. Validate and decode; record any incomplete regions.
2. Partition components and expand bounded streams, caching results.
3. Match exact regions by bytes and validated role/structure. Hashes index candidates; confirm bytes before declaring equality.
4. Match structured records by format-defined stable keys. Match remaining regions with unique content anchors and bounded sequence alignment. Never force an ambiguous duplicate match.
5. Decode established executable regions for a recognized architecture. Discover blocks from justified entry points and control flow; handle embedded data, invalid instructions and indirect targets conservatively.
6. Establish a one-to-one map of matched instructions/blocks and data objects. Exact unique anchors seed the map. Operand-normalized candidates are tentative until validated; address masking alone is not proof. Block reordering is permitted only with established correspondence.
7. Validate relocations against this map. An old call/jump/pointer and its new counterpart qualify only when they reference corresponding targets and corresponding offsets, with instruction semantics/width and addressing mode accounted for. Relative branches and pointer tables follow the same rule.
8. Compare remaining instructions, immediates, records and opaque data; emit findings with evidence and coordinates on both sides.
9. Produce totals and coverage, checking that no bytes disappear or are counted twice.

A reference to a matched function can be relocation-only while changes inside that function are still reported. Call sites need not all repeat the callee's changes. Changed flow edges to different blocks count even if both operands are addresses. RAM relocation requires a proven object/copy mapping. MMIO addresses are preserved. Constants merely resembling addresses are preserved. Unresolved indirect calls do not become “equivalent.”

If matching reaches its work budget, return available findings with an explicit unresolved remainder. Do not present a completed equivalence conclusion. Avoid whole-image quadratic alignment; partition, anchor, then align bounded gaps. Cross-architecture comparison can compare data but cannot normalize incompatible instruction sets.

## Media and strategy tables

Expose a table view with format identifier, media class when established, records, source ranges and parse coverage. A record has a format-defined key (media ID plus whatever type/revision/speed selectors that format requires), validated fields and opaque residual bytes. Duplicate keys are disambiguated only by established structure; otherwise retain a group as ambiguous.

Compare additions, removals, field changes, opaque record changes and ordering changes separately. Reordering can be excluded only if table semantics establish that order does not affect selection/priority. Media names found by strings alone are evidence of strings, not validated media records.

Do not invent labels such as laser power or timing for unknown fields. Unknown changed record bytes should say “strategy data changed; field meanings not decoded.” Unsupported tables still get aligned byte comparison. Shared strategy blobs may be referenced by several media records; count the blob once and list affected references.

Each parser must validate record sizes, bounds, counts, references and applicable format version. Different valid formats are not compared field-by-field without a defined common schema. This allows useful first-release comparison without pretending complete strategy reverse engineering is finished.

## Result model and metrics

Findings carry kind, component/region/record IDs, old/new values or bounded byte excerpts, left/right locations, evidence method and resolution state. Useful kinds include CodeAdded/Removed, InstructionChanged, ConstantChanged, ReferenceTargetChanged, RegisterAddressChanged, RecordAdded/Removed, FieldChanged, OpaqueDataChanged, Relocated, MetadataChanged and Unresolved.

Resolution states describe evidence: exact bytes, verified structural correspondence, heuristic candidate or unresolved. Heuristic matches never erase changes from substantive totals. Report code blocks rather than “functions” when function boundaries are not established.

Per-side byte accounting partitions included logical bytes into unchanged, verified relocation operands, resolved changed, unmatched and unresolved. Excluded metadata/padding is counted separately. For an insertion/deletion, retain independent A and B lengths rather than inventing substitutions. Instructions and records have their own counts; do not add them to byte totals.

Show analyzed coverage and unresolved size prominently. Default report has no single “firmware similarity” percentage. Optional detail can show exact/relocation-accounted coverage with explicit denominator, scope and exclusions. Compression bytes and expanded bytes never share a denominator.

Conclusions: IdenticalDecodedContent; NoSubstantiveDifferencesDetected (only with all in-scope regions resolved); DifferencesFound; Inconclusive. Separately report completeness and missing components. “No differences” in one present component must not become “packages identical” when another is absent. A report with both confirmed changes and unresolved regions is DifferencesFound with partial coverage.

## Single-source Inspect firmware tab

Inspection is the first-class single-source presentation of `FirmwareAnalysis`; comparison consumes two of those same objects. Do not implement inspection as self-comparison or add a second decomposition path. Both operations use the same source loader, capture workflow, provider, parsed records, diagnostics and limits. The existing Drive info tab remains a quick device-identity view without firmware capture.

Inspect firmware has one Firmware file / Drive selector, an Inspect button, Cancel, and the same visible capture destination for a live source. The result is shown in that tab; no new top-level tab per file. Lead with hardware family and its derivation/status, then model, revision, date and source provenance. A navigable component/region tree opens detail panels:

| View | Contents |
| --- | --- |
| Overview | Hardware family first; identity, component inventory, hashes, format, completeness and parsing coverage. |
| Components | Kernel/Normal or provider-defined components; decoded sizes and validated metadata. |
| Streams and regions | Purpose when known, stored/expanded sizes, hashes, locations and recognition evidence. |
| Media / strategy tables | Searchable records, media IDs, validated selectors and decoded fields. |
| Record detail | Every recognized field, type, value, units when known, source range, references and opaque residual bytes. |
| Code / other data | Region inventory, established architecture and address mappings, bounded disassembly where supported, otherwise bytes. |
| Diagnostics | Missing context, unsupported structures, invalid fields and unresolved regions. |

Strategy tables show all parsed records, not only changes. Filtering by media class and identifier and sorting are presentation-only: retain original order and record identity. Large tables and byte views use virtualized/paged rendering. Unknown field bytes remain available in hex with their offsets; do not hide them or label them with speculative meanings. A recognized stream without a validated record parser is displayed as an opaque stream with its raw expanded bytes and an explicit “Record layout not yet decoded” explanation.

Inspection can show headers and signature/seed metadata: excluding these from comparison counts is not hiding them from inspection. Clearly distinguish signature status from OEM provenance. Source inspection never modifies firmware, repacks it, edits strategies or performs a flash.

Provide Copy summary and Save text/JSON using the same provenance and privacy rules as Compare. Table export to CSV is available for recognized tables, with defined field columns and explicit unknown fields; quote/escape content and neutralize spreadsheet-formula prefixes in textual cells. Do not export binary firmware automatically. Detailed data retrieval is bounded and uses the existing analysis-owned buffers.

“Use in Compare” transfers the immutable analyzed source as A or B without reopening a drive or recapturing it. Compare also offers Inspect A / Inspect B links that open the corresponding retained analysis and focus the relevant record from a finding. Every live result remains labelled as a timestamped capture; Refresh capture is explicit. Cache analyses only within the bounded session, keyed by actual component digests plus provider/library/options versions, never by filename, device path or model. Report detail remains pinned while displayed; evict unreferenced analyses to stay within budget. Source changes cannot relabel an old capture as current firmware.

Capabilities are independent: identity-only, decoded regions, table records, code analysis and pair comparison. A future provider may support inspection before comparison. Unsupported MediaTek inspection explains “Detailed firmware inspection is not yet supported for this format” while preserving whatever identity is already available; do not capture solely to discover a known unsupported capability. All single-source acquisition rules match Compare except that no second input or pair capability is required.

This is a modest UI addition once the structured analysis exists. Parsing every proprietary strategy field is separate reverse-engineering work. Shipping inspection requires honest coverage and complete access to parsed and opaque data, not claiming every field is understood.

## GUI and report

Compare tab has Source A and Source B cards, each selecting Firmware file or Drive, with at most one drive. File picker uses the existing firmware file types (including BIN, ENC and TAR); actual support is determined from content. The initial Pioneer adapter accepts TAR packages, with a clear TAR-specific message for standalone Pioneer ENC input. All discovered drive vendors remain selectable. Display model, revision, component inventory and family when known after inspection. Controls: Swap, Compare, Cancel; live selection also shows capture destination. Compare enables only with two valid selections and no conflicting operation.

States: idle, validating inputs, capturing drive, decoding, decomposing, matching, comparing, complete/partial, cancelled, failed. Run on the existing background-worker mechanism. Progress is stage plus units where measurable; do not fake precise percentage for matching. Source changes invalidate the current report and cancel the old task; generation IDs prevent late worker results overwriting a newer selection. Cancel is cooperative between bounded work units; during an in-flight SCSI command display that cancellation waits for that command's return/timeout.

Results start with hardware-family relationship and both family IDs, followed by source identities and coverage, then provider-defined component summaries (Kernel and Normal for Pioneer). Expand component -> region/stream -> finding. Default view hides unchanged and excluded details. Filters reveal relocation-only changes, metadata and unresolved regions. Detail shows old/new values and qualified offsets, with plain English descriptions. No warning colors implying that similarity establishes safety.

Offer Copy report, Save text and Save JSON. Text is forum-friendly plain text. JSON is a versioned app export schema containing source/component hashes, app/library/analysis versions, options, findings, diagnostics and coverage; use explicit byte-order/offset units. Exclude raw firmware, serial numbers and full local paths by default. Detailed local diagnostics retain troubleshooting context under existing logging policy. Reports identify a live source as a timestamped capture, never as the drive's current state after capture.

## Errors, limits and cancellation

Optical returns typed single-image analysis errors implementing CodedError and structured nonfatal diagnostics. Flash owns pairwise comparison errors and limits. App maps them to English with side/component/stage and preserves cause codes for future translation. Proposed error namespaces: pioneer.analysis.* and pioneer.compare.*. Cases include invalid/ambiguous directory, malformed table, unsupported architecture, unknown address mapping, resource limit and cancelled. Absent optional structures and unsupported semantic parsing are capabilities/diagnostics, not generic failures.

Fatal input/I/O errors stop that source. Safe partial decoding/analysis is displayed with explicit scope; never silently replace invalid data with zeros or silently omit it. Example: “Source B, Normal, stream 2: decompression failed. Other decoded regions were compared; this stream was not compared.” This is available only when shared parser validation establishes safe independent boundaries.

Initial proposed defaults: preserve the existing 64 MiB package limit and 8 MiB component limit; expanded stream 64 MiB and per-image total 256 MiB, matching current inflater caps. Additional analysis-owned allocation budget 512 MiB across both sides; retained inputs and GUI overhead are reported separately. Bounded local alignment gaps at most 32 KiB with an additional work counter; global work cap initially 50 million comparison steps and 100,000 findings. These last budgets require corpus benchmarking before freezing defaults. Limits are named options, checked before allocation/work; reaching one yields partial coverage and a diagnostic, never a false equal result. Cancellation and progress use a lightweight caller observer; no GUI/runtime dependency in Optical.

## Tests and acceptance

Use deterministic synthetic fixtures in public tests; private corpus validation references locally held OEM data without distributing it. Tests in side files, no model-specific branches in production.

- Equal decoded content with different envelope seed/signature/compression produces no substantive changes.
- Moved code/data with changed absolute and relative references is excluded only with established target correspondence.
- Changed immediate, MMIO address, branch destination, callee, pointer target, instruction insertion/deletion and changed referenced data all remain visible.
- Duplicate functions/records, address-like constants, mixed code/data, unknown opcodes, indirect flow, competing mappings and reordered blocks cannot cause false equivalence.
- Header exclusion is field-specific; operational and unknown header fields remain included. Unknown zero/FF data is not discarded.
- Streams reordered/moved/recompressed are matched by validated content/structure; missing/corrupt/ambiguous directories and expansion bombs have precise outcomes.
- Media records: additions/removals, duplicate IDs, changed selectors/opaque bytes, shared blobs and order-sensitive tables.
- Accounting partitions every byte once; swapping sides preserves equality and reverses additions/removals; repeated runs are deterministic; self-comparison is exact.
- Missing Kernel context, Normal-only and Kernel-only inspection, unsupported BDR/DVR structure, different families, invalid packages and unrecovered tails report correct scope.
- Inspection: one-source analysis matches the same source in Compare; all parsed table records and opaque residual data are accessible; sorting/filtering preserve record identities; Inspect/Compare navigation reuses the capture; explicit refresh creates new provenance; capability-specific unsupported messages; bounded rendering and CSV escaping; source edits never mutate firmware.
- App: family summary precedes content results in every renderer; same/different/unknown/not-comparable cases; cross-family analysis succeeds without force; MediaTek selection yields unsupported capability before capture; cross-vendor pair failure is format-specific; family IDs from different namespaces never compare equal. Same report from GUI worker and shared workflow; safe TAR intake; file-only never opens devices; live capture saved before analysis, device released, cancellation/disconnection/disk-full handled; no flash/update commands reachable from compare; no stale UI completion; export escapes input strings and omits private identifiers.
- Corpus: self-compare every decodable held component/package; compare representative pairs across architectures/layouts and same-family packages; inspect all unrecognized regions and resource-limit cases. Pin input hashes and expected evidence, not an unstable percentage.
- XD06U/XD08U research is a regression for alignment and stream interpretation, not universal format truth. Independently verified instruction/register/constant examples become fixtures. Do not blindly bless current heuristic script output.
- Run library feature matrix/MSRV, format/lint/docs, existing app tests and GUI operation parity. Benchmark peak memory, work count and wall time on representative small/large/repetitive images. No hardware flash needed; live validation uses backup-only capture.

## Delivery sequence and completion gates

1. Shared checked decomposition and public analysis views, preserving current codec/inflater APIs; complete accounting and error tests.
2. Deterministic region alignment and code/reference analysis for established architectures; unknown fallback and adversarial tests before normalized results are exposed.
3. Structural media-table parsers for formats proven by fixtures; explicit opaque fallback for the rest. A parser ships only when record boundaries and keys are established.
4. Structured comparison/report model with limits, cancellation, evidence, export and corpus validation.
5. Shared app source/capture workflow and Inspect firmware tab, then Compare tab using the same retained analyses and presentation components; navigation/export tests and local capture-only smoke test.
6. Audit API reuse, classification accuracy and report language; publish versioned library/app changes only under a separately selected release plan.

Completion means every accepted source has an honest inventory and coverage report, every excluded relocation has auditable correspondence, and unsupported content stays visible. It does not require naming every proprietary strategy field. Implementation and QA delivery are authorized. Main/release promotion awaits user testing and sign-off.

## QA implementation and validation (2026-10-08)

The shipped API names are `inspection::Source`, `Inspection`, `ComparisonReport`
and `Control`. Provider decoding is isolated in `inspection::pioneer`; the
`inspection::comparison` engine has no vendor opcode or layout knowledge.
Optical's `Envelope::analyze` owns the single-image facts. Future providers can
project those same neutral region/reference/table inputs without changing the
matching engine. There is no public plugin registry in this release.

The alignment is deterministic and direction-independent: a stable digest order
selects the internal source orientation, and results are mirrored back to A/B.
Unique 16-byte anchors establish the initial alignment; byte-granular 8-byte
anchors refine each remaining gap. Every anchor is verified against actual
bytes. A work-limit failure remains unresolved rather than becoming equality.
This is not a minimum-edit-distance or semantic-equivalence guarantee.

Runtime overlay placement comes from recognized COMP loader instruction paths,
with directory/magic, source indexing, selector branches and converging
load/decompress paths checked together. Conflicting placement evidence is not
used. No model, fixed stream number or fixed destination-address profile is
used for this recognition. Direct-reference exclusions require aligned
instruction context and at least eight contiguous matching bytes at the mapped
target. Unproven RAM-object shifts and address-looking constants stay changed.

Only structurally recognized text tables have decoded record views today;
unknown write-strategy fields have no invented names or meanings. Table record
comparison is positional. Missing or undecodable components stay explicit.
Source digests and application version are included in JSON; raw firmware and
private filesystem paths are omitted.

Local validation includes the complete available image list (5,103 entries:
1,103 analyzed images, 22 existing decode failures, 3,978 other formats), exact
family parity with the existing API, and complete stored-byte partitioning.
All 666 package inputs inspected and compared identically to themselves.
Reproduce optional corpus checks using `PIONEER_ANALYSIS_CORPUS` with Optical's
`analysis_corpus` integration test and `FREEMKV_INSPECTION_CORPUS` with Flash's
`inspection_corpus` test. Each variable points to a newline-separated path list;
run the relevant test with `-- --ignored`. Firmware is not embedded in tests.

QA is the delivery destination. Main promotion and public release are held for
user approval; the candidate may collect additional fixes first.
