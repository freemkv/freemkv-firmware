# Universal backends and a native GUI for freemkv-flash — design v2

Status: v2, revised after an adversarial review that REFUTED v1 (13 findings;
each is addressed and cross-referenced as **[Rn]**). Baseline: `dev` 04b7516.
Targets: freemkv-flash **0.12.0**, mediatek-optical **0.5.0**.

## 1. Goal and invariants

A drive family is a backend module plus one registry line. The engine,
workflows, CLI and GUI work from what the backend declares, with no code edits
elsewhere. Section 11 lists the project chores that remain.

Invariants (each is enforced by a test, not by convention):

1. **Write gates are generic and enforced at runtime.** The engine is the only
   code that can hand a backend a writable device, and only after its gates have
   passed. Section 5.3 describes the mechanism. [R2]
2. **Pioneer behaviour is byte-identical through the migration.** This covers
   CLI stdout and stderr, output events, files written and their names, and the
   full SCSI transcript, including `medium_status` calls. The proof is the
   phase-0 goldens (section 12). The one deliberate exception is that
   `RecoveryFacet::identify` surfaces Recovery in the GUI for unsupported
   drives. [R3, R7]
3. **No backend code is in a front-end, and no front-end code is in a backend.**
   Backends return typed data and never print. Front-ends render and never
   decide.

## 2. Current problems

These were measured at 04b7516:

| Problem | Evidence |
|---|---|
| A 40-method trait shaped like the MediaTek flash loop (`image_size`, `chunk_size`, `envelope`, `flash_stream`, `readback`, `verification_ranges`, `wait_ready`) | `drive/mod.rs` |
| A closed `Family` enum; `InputKind::PioneerBundle` names a vendor | `drive/mod.rs`, `imageid`, `flashset`, `crossflash`, `inspection` |
| Dead force paths: `FlashOptions.force` and `FlashRequest.{force,skip_backup,recover}`, unreachable from the CLI (`main.rs:198` passes `force: false`) and the GUI (`app.rs:292`), plus `validate_forced_*` | `workflow.rs:67`, `drive/mod.rs:300-339` |
| Four meanings of "recover": `Capabilities.recover` (deep dump salvage), `FlashRequest.recover`, dump's recover flag, the `recover()` workflow | [R5] |
| Output is label strings that differ between CLI and GUI | `engine.rs:31-93`, `info_ui.rs` `section()` |
| `read_surface_map` has no caller | [R5] |
| The GUI has no notion of a backend; Recovery deliberately skips the probe | `freemkv-flash-gui`, `workflow.rs:411-420` |

## 3. Layers (0.12.0)

```
front-ends ── freemkv-flash (CLI)   freemkv-flash-gui (ui.rs model + shells)
                 │ call only `workflow` and render `report` types
core ───────── workflow · engine (gates) · report · standard · backend (trait,
                 facets, registry, devices, conformance) · transport
backends ───── backends/mtk · backends/pioneer        (one directory each)
protocols ──── mediatek-optical 0.5.0 · pioneer-optical =0.12.4 (unchanged)
```

- **`standard` is a module, not a crate, in 0.12.** It wraps the existing
  `pioneer_optical::device::Device::info()` call exactly as today, so info
  transcripts are unchanged. Extracting an `optical-mmc` crate is deferred: it
  would force a pioneer-optical 0.12→0.14 upgrade mid-migration. [R11]
- **Dependency rule, tested by a source scan:**
  - `backends/*` may import only `backend`, `report`, `standard`, `transport`
    and their protocol crate.
  - Core never imports a backend except in `backend/registry.rs`.
  - The GUI crate imports only `workflow` and `report`.

## 4. Backend identity

```rust
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct BackendId(pub &'static str);      // "mtk19xx", "pioneer-oem" (existing backend_name strings)

pub struct Descriptor {
    pub id: BackendId,
    pub display_name: &'static str,          // "MediaTek MT19xx"
    pub flash_summary: &'static str,         // replaces flashset::for_family's info line
    pub formats: &'static [FileFormat],
}
pub struct FileFormat {
    pub id: &'static str,                    // "mtk-image", "mtk-backup", "mtk-legacy-tar", "pioneer-package", "pioneer-envelope"
    pub label: &'static str,                 // dialog / CLI wording
    pub extensions: &'static [&'static str],
}
```

- `Family` and `InputKind::PioneerBundle` are removed.
- `crossflash` is MediaTek-internal and drops its `Family` parameter.
- `flashset` keeps its brand catalogue for `check`, but the per-drive "flash"
  line comes from `Descriptor::flash_summary`.
- `imageid` stays an offline corpus classifier (it labels families we don't
  support). It never selects behaviour. [R9]

## 5. The backend contract

### 5.1 Trait and facets

```rust
pub trait Backend: Send + Sync + 'static {
    fn descriptor(&self) -> &'static Descriptor;
    /// Read-only. `None` = not this protocol.
    fn probe(&self, dev: &mut ReadDevice, identity: &Identity) -> Result<Option<Match>>;
    fn files(&self)    -> Option<&dyn FileFacet>     { None }   // recognize + describe (`check`, `info <file>`)
    fn details(&self)  -> Option<&dyn DetailsFacet>  { None }   // vendor rows for `info`
    fn backup(&self)   -> Option<&dyn BackupFacet>   { None }
    fn dump(&self)     -> Option<&dyn DumpFacet>     { None }
    fn flash(&self)    -> Option<&dyn FlashFacet>    { None }
    fn recovery(&self) -> Option<&dyn RecoveryFacet> { None }
    fn inspect(&self)  -> Option<&dyn InspectFacet>  { None }
    fn settings(&self) -> Option<&dyn SettingsFacet> { None }   // read-only in 0.12 [R13]
}

pub struct Match {
    pub backend: BackendId,
    pub evidence: &'static str,
    pub variant: Option<String>,             // "MT1939"
    pub probe_data: ProbeData,               // backend-private cache (e.g. Pioneer F1 identity) so details/flash don't re-read [R8]
}
pub struct ProbeData(Box<dyn std::any::Any + Send + Sync>);
```

Capabilities are derived from facet presence and drive the CLI help, GUI tabs
and dialogs. "Deep dump" (`Capabilities.recover` today) becomes
`DumpFacet::deep_salvage() -> bool`. The word "recover" now means only
`RecoveryFacet`. [R5]

### 5.2 One recognizer per backend [R13]

```rust
pub trait FileFacet {
    /// Structural (parsed container / exact layout) beats Heuristic (pattern search).
    fn recognize(&self, file: &InputFile) -> Option<Recognized>;
    /// The `check` / `info <file>` report, as rows (section 7).
    fn describe(&self, file: &InputFile, r: &Recognized) -> Result<Report>;
}
pub struct Recognized { pub format: &'static FileFormat, pub confidence: Confidence }
pub enum Confidence { Structural, Heuristic }
pub struct InputFile { pub name: String, pub bytes: Vec<u8> }   // read via workflow::read_capped
```

The same recognizer serves flash input classification, `check`, `info <file>`
and inspect provider choice:
- Structural matches win over heuristic ones.
- Two structural matches, or two heuristic matches with no structural match,
  are an "ambiguous file" error.
- With the current backends, Pioneer is structural (a parsed tar or envelope)
  and MediaTek is heuristic (a tag search), which reproduces today's
  Pioneer-first order. [R9]

### 5.3 Devices: write capability is a runtime handle [R2]

```rust
pub struct ReadDevice<'a>  { /* wraps &mut dyn ScsiDevice */ }   // data-out refused except declared unlocks
pub struct WriteDevice<'a> { /* constructed only in engine::gates */ }

pub trait ReadUnlock { fn allowed_data_out(&self) -> &'static [CdbPattern]; }   // e.g. Pioneer read-unlock knock
```

- `ReadDevice::command_out` fails unless the CDB matches the backend's declared
  read-unlock patterns. Pioneer's memory-read knock is declared; nothing else
  is. Every read-only call gets a `ReadDevice`: probe, details, files, backup
  capture, inspect, flash `plan` and `authorize`, recovery `identify`,
  settings `read`.
- `WriteDevice` has a private constructor in `engine::gates`. Backends receive
  one only in `FlashFacet::execute`, `RecoveryFacet::recover` and
  `DumpFacet::capture` when the dump declares writes (Pioneer RAM logging,
  `pioneer/dump.rs:186,219`).
- Each grant has its own written gate set:

| Write | Gates the engine enforces before creating `WriteDevice` |
|---|---|
| Flash execute | `--execute`, risk ack, tray empty (checked twice), backup saved and verified, `authorize` passed |
| Recovery | `--execute`, risk ack; deliberately no tray check and no backup (documented README behaviour) |
| Dump with RAM logging | the dump command itself; a read-unlock or logging write only, declared in `DumpFacet::writes()` |

- The dead force, skip-backup and recover-flash paths are deleted in phase 1.
  The pre-flash backup becomes unconditional for Flash, as it already is in
  practice.

### 5.4 Flash in two stages [R1, R5]

```rust
pub trait FlashFacet {
    /// Pre-backup, read-only: structure, CMAC, chip, model, boot page, bundle
    /// consistency; a read-only preflight (MTK PROBE + TUR). Returns what the
    /// backup must contain. Must not need the backup.
    fn plan(&self, dev: &mut ReadDevice, m: &Match, input: InputFile, opts: &FlashOptions) -> Result<FlashPlan>;

    /// Post-backup, read-only, before the first write: every gate that needs the
    /// installed firmware (Pioneer installed receiver, header chain, Kernel tags,
    /// downgrade/crossflash routing, Refused), plus backup coverage
    /// (`verify_preflash_backup` today). May refuse. The saved backup is kept on refusal.
    fn authorize(&self, dev: &mut ReadDevice, plan: FlashPlan, backup: &SavedBackup) -> Result<AuthorizedPlan>;

    /// Write, then verify (MTK: wait_ready, read-back of protected ranges and
    /// firmware re-identification; Pioneer: completion/readiness).
    fn execute(&self, dev: &mut WriteDevice, plan: &AuthorizedPlan, p: &mut dyn Progress) -> Result<FlashOutcome>;
}

pub struct AuthorizedPlan {
    pub plan: FlashPlan,
    pub routing: Report,                     // e.g. "downgrade via Kernel mode"
    pub confirmation: Option<String>,        // shown by the front-end; today's confirm_proceed text
}
```

The engine's flash, in the same output order as today:

```
dry run:  plan → emit plan (+ tray warning) → preflight result → done
execute:  plan → ack → tray → backup (save, read-back) → authorize
          → emit plan + backup summary (MTK order) → front-end confirmation
          (CLI: today's y/N prompt text; GUI: sheet) → tray → execute → outcome
```

The Pioneer `confirm_proceed` prompt moves from the backend to the front-end,
using its exact text. The CLI keeps today's TTY and non-TTY behaviour. The GUI
runs the read-only plan, then backup and authorize, and only then shows its
confirmation sheet with the authorized plan, its warnings and the confirmation
text; cancelling keeps the backup and writes nothing (as built in 0.12.0). The
goldens check that CLI output is identical.

### 5.5 Other facets

```rust
pub trait BackupFacet {
    fn format(&self) -> &'static BackupFormat;        // extension, filename infix (".candidate"), sha line label [R5]
    fn capture(&self, dev: &mut ReadDevice, p: &mut dyn Progress) -> Result<CapturedBackup>;
    fn notice(&self, bytes: &[u8]) -> BackupNotice;   // Verified / Unverified (today's backup_notice)
    fn restore_image(&self, bytes: &[u8], target: &Match) -> Result<InputFile>;   // backup → flash input
}
pub trait DumpFacet {
    fn kind(&self) -> DumpKind;                       // Raw (.dump.bin, unvalidated, RAW DUMP line) | Archive [R5]
    fn deep_salvage(&self) -> bool;
    fn writes(&self) -> &'static [CdbPattern];        // declared logging/unlock data-out, else empty
    fn capture(&self, dev: DumpDevice, opts: DumpOptions, p: &mut dyn Progress) -> Result<Vec<u8>>;
}
pub trait DetailsFacet {
    fn rows(&self, dev: &mut ReadDevice, m: &Match, std: &StandardInfo) -> Result<Vec<(Slot, Row)>>;
    fn post_flash_identity(&self, dev: &mut ReadDevice) -> Result<Option<Report>>;   // today's firmware_report (also used by execute) [R5]
}
pub trait RecoveryFacet {
    /// Read-only, NO probe needed: is this a receiver we can recover? [R6]
    fn identify(&self, dev: &mut ReadDevice) -> Result<Option<RecoveryTarget>>;
    fn requirements(&self) -> RecoveryRequirements;   // form fields + wording for front-ends
    fn recover(&self, dev: &mut WriteDevice, t: &RecoveryTarget, input: RecoveryInput,
               execute: bool, p: &mut dyn Progress) -> Result<RecoveryOutcome>;
}
pub trait InspectFacet {                              // uses FileFacet::recognize for selection
    fn inspect(&self, file: &InputFile, c: &Control) -> Result<Inspection>;
    fn capture(&self, dev: &mut ReadDevice, p: &mut dyn Progress) -> Result<InputFile>;
    fn live_state(&self, dev: &mut ReadDevice) -> Result<LiveState>;
}
pub trait SettingsFacet { fn read(&self, dev: &mut ReadDevice) -> Result<SettingsView>; }
```

`read_surface_map` is deleted (no caller). `Progress` is `trait Progress {
fn set(&mut self, label: &str, done: u64, total: u64); }`, the existing
`style::Progress` behind a trait. `Control` is the existing
`inspection::Control`. `LiveState` and `Inspection` are the existing
`inspection::report` types. [R13]

### 5.6 Mapping from today's trait

| Today | v2 |
|---|---|
| `family`, `backend_name`, `capabilities`, `is_supported` | `descriptor`, facet presence |
| `probe`, `identity` | `probe(&mut ReadDevice, &Identity)` → `Match` (with `ProbeData`) |
| `print_device_info`, `firmware_report` | `DetailsFacet::rows`, `post_flash_identity` |
| `describe_file`, `classify_input` | `FileFacet` |
| `print_flash_notes`, `validate_image`, `offline_plan`, `preflight` | `FlashFacet::plan` |
| `verify_preflash_backup`, Pioneer `installed_receiver`/`resolve_flash_plan`/`check_plan_executable`/`confirm_proceed` text | `FlashFacet::authorize` (prompt text → `AuthorizedPlan.confirmation`) |
| `flash_is_bundle`, `flash_bundle`, `flash_stream`, `envelope`, `image_size`, `chunk_size`, `wait_ready`, `readback`, `verification_ranges` | private to each backend, inside `FlashFacet::execute` |
| `backup_extension`, `backup_kind`, `backup_notice`, `capture_backup`, `validate_backup` | `BackupFacet` |
| `capture_dump`, `dump_is_raw`, `read_full_image` | `DumpFacet` |
| `recover`, `force_refusal` | `RecoveryFacet`; force deleted |
| `validate_forced_image`, `validate_forced_backup`, `read_surface_map` | deleted |

## 6. Standard drive facts (`standard`) [R3]

- `standard::read(dev)` is today's `Device::info()` snapshot (INQUIRY,
  vendor-identity probe, MODE SENSE 2A, GET CONFIGURATION features, REPORT KEY),
  issued once, in today's order.
- **It runs only for `info` and `profile`.** Backup, flash, recover and dump
  transcripts are untouched, so no new commands are sent.
- `StandardInfo` reaches `DetailsFacet::rows`, so Pioneer stops re-reading what
  is already there. The info transcript stays identical because today's single
  `Device::info()` is exactly this read.
- The phase-0 goldens cover it.

## 7. Reports that reproduce today's CLI and GUI exactly [R4, R12]

```rust
pub struct Row {
    pub key: &'static str,
    pub gui_label: Option<String>,     // None = not shown in the GUI (e.g. CLI "inquiry" line)
    pub cli_label: Option<String>,     // None = not printed by the CLI (e.g. GUI "Manufacturer")
    pub value: Value,
    pub group: Group,                  // GUI card (General, Additional, Media, Region, Settings, Operations)
}
pub enum Value { Text(Clean), Status(Level, Clean), Size(u64), Hex(String), Path(PathBuf), Unavailable(Clean) }
pub struct Clean(String);              // only constructible through sanitize(): every drive/file string
pub enum Slot { AfterIdentity, AfterInterface, AfterMedia, AfterRegion, End }
pub struct Report { pub rows: Vec<Row> }
```

- **The producer decides order.** The engine builds the standard rows in
  today's order. A backend's `(Slot, Row)` pairs go at named slots: Pioneer
  identity and production rows at `AfterInterface`, Pioneer settings at
  `AfterRegion`, the MediaTek "Chipset" row at `End`. This reproduces today's
  interleaving.
- **Rows can differ per front-end.** GUI-only and CLI-only rows are expressed
  by the two labels, and so are label differences ("Chipset" in the GUI,
  "chipset" in the CLI).
- **Sanitising is enforced by types.** Every drive- or file-derived string is a
  `Clean`. `Hex` (sha256, fingerprints) and `Path` stay raw but typed; the CLI
  renders paths with `display()`.
- **`Event::Field` is replaced by `Event::Report(Report)`.** The CLI renderer
  prints `cli_label: value` lines exactly as today. The goldens check both
  stdout and the event stream.

## 8. Inspect and Compare

- `RegionRole { Code, Integrity, Identity, Configuration, PerUnit, ReadBack, Unknown }`
  is added to `RegionView`.
- Compare classifies differences: `PerUnit` and `ReadBack` are expected, the
  rest unexpected. The verdict counts only unexpected differences.
- The MediaTek provider exposes these regions:
  - identity, provenance (exact OEM build or unknown) and image type
  - the boot page (`ReadBack` in a drive read, `Code` in a stored image)
  - the integrity table as a record table, with integrity-covered ranges as
    `Code`
  - revocation lists, settings and calibration as `PerUnit`
  - the descriptor
  - live state
- Live capture is a raw read, with an "as backup" option.
- MediaTek feature detection (from `freemkv-fw`) is not in 0.12.

## 9. Workflow API

```rust
pub fn drives() -> Vec<DriveChoice>;
pub fn profile(device: &str) -> Result<DriveProfile>;           // probe + recovery identify; never fails merely on "unsupported"
pub fn details(device: &str) -> Result<Report>;
pub fn backup(device: &str, out: &Path, replace: bool, p: &mut dyn Progress) -> Result<BackupOutcome>;
pub fn dump(device: &str, out: &Path, opts: DumpOptions, p: &mut dyn Progress) -> Result<DumpOutcome>;
pub fn plan_flash(device: &str, input: &Path, opts: &FlashOptions) -> Result<FlashPlan>;
pub fn flash(device: &str, input: &Path, opts: &FlashOptions, confirm: &mut dyn Confirm, p: &mut dyn Progress) -> Result<FlashOutcome>;
pub fn recover(device: &str, form: RecoveryForm, execute: bool, p: &mut dyn Progress) -> Result<RecoveryOutcome>;
pub fn check_file(path: &Path) -> Result<Report>;
pub fn inspect(source: &Source, c: &Control) -> Result<Arc<Inspection>>;
pub fn compare(a: &Source, b: &Source, c: &Control) -> Result<ComparisonReport>;

pub struct DriveProfile {
    pub identity: Identity,
    pub backend: Option<(&'static Descriptor, Match)>,
    pub recovery: Option<(&'static Descriptor, RecoveryRequirements)>,  // offered even when unsupported [R6]
    pub capabilities: Capabilities,
    pub backup_format: Option<&'static BackupFormat>,
    pub flash_formats: &'static [FileFormat],
}
pub trait Confirm { fn confirm(&mut self, plan: &AuthorizedPlan) -> bool; }   // CLI: y/N prompt; GUI: sheet result
```

## 10. GUI

### 10.1 A neutral model, then native shells (freemkv pattern) [R10]

`freemkv-flash-gui` adopts freemkv's architecture:
- `src/ui.rs` is the platform-neutral model, `App::view() -> View` plus
  `App::dispatch(Input)`, built on the workflow API. It has no widget types and
  is tested on every host.
- Each shell only draws `View` and forwards `Input`.

| freemkv | flash GUI | Toolkit (pinned like freemkv) |
|---|---|---|
| `ui.rs` | `ui.rs` | none |
| `mac.rs` | `mac.rs` | `objc2 0.6`, `objc2-app-kit 0.3`, `objc2-foundation 0.3` |
| `windows.rs`, `win_layout.rs`, `win_menu.rs` | same names | `winsafe =0.0.29` |
| `linux.rs`, `linux_glue.rs` (gated `target_env = "gnu"`) | same names | `gtk4 =0.9`, `libadwaita =0.7` |
| `gui_gate.rs` | `gui_gate.rs` | none |

The view model covers:
- the drive bar: identity plus profile chips, or "probing…"
- tabs from capabilities, with Recovery offered from `DriveProfile.recovery`
- Overview cards from `Report` groups
- backup and dump with the format from the profile
- flash: picker filtered by formats, plan view, a confirmation sheet showing
  `AuthorizedPlan`, then progress and outcome
- Inspect (tree) and Compare (expected vs unexpected, drill-down)
- read-only Settings
- the diagnostics log

Shells map these to native controls:
- **macOS:** `NSPopUpButton`, `NSTabView`, `NSTableView`/`NSOutlineView`,
  `NSAlert` sheet, `NSProgressIndicator`, `NSSavePanel`/`NSOpenPanel`.
- **Windows:** common controls through winsafe.
- **Linux:** AdwHeaderBar, AdwViewStack, GtkColumnView/ListView and AdwToast.

Build order, so each step is shippable:
1. `ui.rs` model with **egui rendering it**. The GUI keeps working, and the
   egui renderer becomes a thin shell too.
2. macOS shell (owner review on a real Mac).
3. Windows shell.
4. Linux shell.

0.12.0 ships native shells on the OSes where they reached parity and verified
green in qa; any OS that hasn't falls back to the egui shell over the same
model. CI: the Ubuntu clippy/test jobs install `libgtk-4-dev libadwaita-1-dev`
as freemkv's CI does, and the musl CLI builds skip the shell via the
`target_env` gate. `freemkv-fw-gui` stays egui (out of scope). The flasher is
English-only today and stays that way; adding i18n is a separate change.

## 11. Dropping in a backend

**Code edits:** a `backends/<name>/` module plus one line in
`backend/registry.rs`. CLI help, GUI tabs and wording, dialogs, file
recognition, inspect selection and the info flash line all come from the
descriptor and facets.

**Project chores, unavoidable and listed so they aren't missed:**
- the protocol crate dependency and its `deny.toml` licence/source entries
- the CHANGELOG
- fixtures recorded from real hardware for the conformance suite
- optionally, `imageid` corpus labels

**Conformance suite**, run per registered backend; a backend missing from it
fails the registry test:

| Check | Real, non-vacuous because |
|---|---|
| Positive probe on its own recorded hardware fixture; `None` on the generic "unknown MMC drive" fixture and the empty mock | fixtures recorded from hardware, so negatives exercise real refusal [R8] |
| `probe`, `details`, `files`, `backup.capture`, `plan`, `authorize`, `inspect`, `recovery.identify` issue no data-out beyond declared unlock patterns | `ReadDevice` records and refuses; the test asserts the transcript |
| `details` reuses `ProbeData` and `StandardInfo` (no repeated INQUIRY/F1 in the info transcript) | transcript count assertions |
| If backup and flash exist: `restore_image(capture())` → `plan` → `authorize` succeed on its fixture | round trip |
| Dump writes ⊆ `DumpFacet::writes()` | transcript |
| Every `Row` string is `Clean` | the type system, plus a renderer test with escape bytes |
| No raw CDB opcode literals in `backends/<name>/` | today's `no_cdbs`, generalised |

## 12. Phases (each keeps every test and every golden green)

| Phase | Work | Proof |
|---|---|---|
| 0 | Goldens: CLI stdout, stderr and the event stream for `info` (Pioneer, MediaTek, Unknown, ambiguous probe), `info <file>` and `check` for every format (MTK image, MTK backup, legacy tar, Pioneer tar, bare `.enc`, an imageid family, unknown), backup and dump (filenames plus lines), flash dry run and execute for both families (including the Pioneer prompt text, TTY and non-TTY), failure paths (partial backup, coverage refusal, Refused plan, Kernel-tag mismatch, tray refusal), recover dry run and execute; full transcripts including `medium_status` calls. [R7] | recorded at 04b7516 |
| 1 | Delete the force, skip-backup and recover-flash paths and `read_surface_map`; rename "recover" meanings; `BackendId` + `Descriptor` + registry; remove `Family` and `InputKind::PioneerBundle`. | goldens equal |
| 2 | Facets as adapters over existing code; `ReadDevice`/`WriteDevice` with the engine-only constructor; derived capabilities. | goldens equal; device tests |
| 3 | Two-stage flash (`plan`/`authorize`/`execute`); MediaTek loop and Pioneer bundle executor move into backends; front-end confirmation. | goldens + transcripts equal |
| 4 | `standard` module (info/profile only); `Report`/`Row`/`Slot`/`Clean`; CLI renderer; `Event::Report`. | stdout + event goldens equal |
| 5 | `ui.rs` model; egui renders it; Recovery via `identify`; capability tabs. | `ui.rs` tests; GUI event goldens |
| 6 | `RegionRole`; MediaTek inspect provider; role-aware Compare. | provider tests, conformance |
| 7 | macOS shell → owner review | `gui_gate` on macOS; manual review |
| 8 | Windows shell, then Linux shell | `gui_gate` in qa |
| 9 | Release prep: mediatek-optical 0.5.0 to `main` (publish); freemkv-flash 0.12.0 to `qa` green; hold for owner OK | qa green |

## 13. Owner decisions taken

- 0.12.0 includes native shells (owner request), staged behind the neutral
  model so that egui remains a working fallback. This overrides the reviewer's
  advice to defer them [R10].
- `optical-mmc` is deferred [R11]. Settings stay read-only [R13].
- Unsupported drives show Overview, plus Recovery when a backend identifies the
  receiver [R6].
