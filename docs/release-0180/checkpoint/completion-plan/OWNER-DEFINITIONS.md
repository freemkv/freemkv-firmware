# Exact filter ownership contract

Accepted definition design for the frozen SAT8/9/native REC and SAT1 domain. This defines what each owner must prove; it does not grant a correction or close a positive/excluded-domain gate. The current implementation is pinned at PO `f16f0e9e381df138aa8d6f3ab97b9ee42b58a73b`. Its observed values and the larger required contracts below are deliberately separate.

## Common typed boundary

An owner certificate contains `(architecture, source-authority, incoming-authority, native-programs, state-roles, physical-trace, logical-interface, imports, resources, lifetime)`. A native program is a complete instruction/table region with rooted entries, all local exits and explicit foreign calls; an address by itself is never a program identity. Source PCs and whole-image hashes bind evidence, not semantic equality. State roles distinguish ordinary RAM, MMIO, retained data, executable copies and incoming logical state. All native operand widths, signedness and instruction ordering remain part of the contract.

A physical trace records actual register transactions, sensor observations, deadlines, interrupt masks, storage operations and physical success/failure. It may retain A's physical driver while adapting its API to B. Logical output includes B's command/retry/error behavior and genuine completion. Logging bytes may differ; a physical failure may not become success. Equality of the old projected value proves only that observation, not equality of this certificate.

Every foreign edge must terminate at one typed import in JOINT-CONTRACT.md. Its disposition is either unchanged logical, exact installed physical, or an explicitly changed provider. A provider not yet proved remains a named blocking issue below. There is no recursive requirement to re-prove the entire application and no permission to assume a generic ROM ABI. One final Normal/Kernel resource ledger must own every allocation, timer slot, stack delta, code span and copied-code lifetime.

## Storage — observed geometry versus physical transactions

Current `src/filters/geometry.rs` observes marker/stride, native bank addresses, or a bound peripheral region. The complete owner is the native **capacity case, bank selector, erase/program transaction, marker/sequence publication, rollover, recovery and transfer footprint**. It owns command operands, polling/watchdog/service-write order, masks and real error continuations, including copied Kernel flash code. Layout owns the meaning of the payload, not these physical transactions.

`StorageRelation` exports: selected installed bank and bounds; read-only capacity-case witness; physical read/program/erase services with exact argument ranges; transaction result/fault; and recovery selection. It imports Controller bootstrap/transaction/watchdog services and Layout's payload/record contract. Selection and transfer geometry must describe the same final pair. No preparation step writes retained data.

Concrete bindings: SAT9 forward `host-geometry/geometry-owned-operands.json` (43 Normal + 4 Kernel) and `layout-startup/layout-storage-operands.json` (123 Normal), and reverse `host-geometry/reverse-exact-trace-manifest.json` (224-byte physical driver). Capacity's 118-byte query, 120-byte boot constructors and three native clients are separate roles in packet D. Their shared Controller service is blocked by **CT-PHYSICAL**, not assumed from prefix equality. Full Storage closure is **ST-CASE**.

## Controller — shared physical services

This required owner is absent from the current seven-filter hardware identity. It owns the remaining shared physical initialization and runtime services: ED00/ED04/ED06 and ED10..ED1F configuration, port/transaction modes, bounded native device/capacity queries, measurement acquisition, physical calibration policy, descriptor-dependent physical thresholds and their publishers. It does not own B's unrelated command implementation, the host protocol, mechanical loading policy, parameter schema or all code reachable from a service.

Its service boundary is the actual constructor/vtable/callback entries and their native callers. Each export binds arguments, mutable descriptor fields, MMIO effects, live registers/flags, errors, state publication and lifetime. The 110-byte ED table has 11 ten-byte entries; its 25-arm indexed dispatcher and secondary tables are bound separately. A physical descriptor's `+16` is its **kind discriminator**, not a capacity count. The source's 23 independent descriptor reads cannot become one cached read without an equivalence premise.

Calibration exports the seven stages in `loading-inputs/211m-controller-calibration-provider.json`: acquisition/admission; measured/valid state; descriptor/derived flags; physical coefficient selection; scale/normalization; physical adjustment; and result publication. Loading consumes these exports, not their internal register values. The native command-0 payload/retry protocol is incoming logical behavior. Shared GPIO/PWM effects have one provider, imported by Inputs/Loading.

Bindings are `controller-runtime-census/expanded-census.json`, `host-geometry/controller-port-contract.md`, `calibration-native-collection/` and `sat1-controller-verdict/controller-contract.md`. The observed form inventory **CT-CENSUS** is closed; runtime coverage remains with **CT-PHYSICAL**. Remaining live publication/ABI/resource relation **CT-PHYSICAL**, SAT1 retained Kernel/delay **CT-SAT1**, and physical calibration difference **LD-CAL** are explicit blocking rows. Forty-two structural layouts are not runtime equivalence classes.

## Layout — retained meaning and ordinary save lifecycle

Current `src/filters/layout.rs::value` serializes the observed primary-record projection. The full contract includes every logical index and mode, pointer/read/write interface, selected or absolute physical region, current-record width/header/count/encoding, raw/log/counter region, cache, queue, snapshot and recovery meaning. A different base address is only one coordinate in this relation.

`RecordRelation` maps B logical state to A's retained representation losslessly, preserving ordinary future OEM saves and recovery. It exports mapped reader, writer, snapshot and default/copy behavior to Startup and incoming logical callers. It imports the same `StorageRelation` used by Geometry. There is no independent half-adapter. It owns schema bounds and data meaning; Storage owns actual flash commands and bank transactions.

Bindings are packet E, `layout-startup/raw-lifecycle-contract.md`, `layout-storage-operands.json`, `old-to-modern-state-capacity.md`, `sat1-core-to-extended-state-capacity.md`, and `sat1-extended-preserver-contract.md`. Old 512→modern545 and SAT1 core384→extended894 current-word deficits are directional schema prohibitions, not reverse proofs. **LY-FAULT** is closed for the revised 468-byte preserver, including its 68-byte program-error wrapper. Remaining rows are **LY-RAM** (exclusive1024-byte save workspace), **LY-REVERSE** (history/log representation), and **LY-COUNTER** (journal/HRL semantics).

## Startup — installed accepted state and incoming continuation

Current `src/filters/startup.rs` observes a rooted fixed word-009F comparison, a bound conditional predicate, or a separate preservation contract. The complete owner is a predicate over the installed physical retained state and its actual lifecycle, plus B's accept/reject continuations. A recognizer miss is not absence of a predicate and never means FFFF.

`StartupRelation` consumes the final Layout reader/writer/cache/default relation. For every physical state in its domain, its acceptance result must equal A's acceptance result, and its logical continuation/error API must match B's. A fixed↔fixed representation codec may leave B's gate untouched only when the mapping proves that equality. Fixed↔conditional cases require the complete policy relation; neither an OR of gates nor blanket preservation of B's original gate is permitted.

Static code-entry, vector, callback and table declarations in packet A establish byte ownership only. They cannot satisfy runtime target identity, register preservation or startup acceptance. Protected opaque bytes remain opaque. Concrete bindings are `layout-startup/startup-class-ledger.json`, `startup-conditional-contract.md`, `boundary-closure/`, and `sat1-startup-boundary/`. Policy composition is **SU-POLICY**; complete94-class disposition is **SU-BOUNDARY**.

## Loading / IRQ — physical loading policy

Current `src/filters/loading.rs` keeps three distinct variants: FFC5 `(old & mask) | set`, a physical input term, or an installed tray-close vector route. Direct writes and masked updates differ. None of these alone describes the loading driver.

The full owner binds physical readiness/inhibition, loading state machine, installed IRQ/vector/callback route, polling and acknowledgement, hold/release deadlines, cancellation, genuine completion and physical fault policy. It exports the incoming logical loading API/status/error interface. It imports Inputs' physical sensing/actuation, Controller's seven-stage calibration provider and the precise resident timer/task/allocator services. Logical callers remain B callers. Private holds may use owned fixed state only while preserving the entire public16-slot timer interface, including its full/error/query and dispatch behavior.

Bindings: `loading-inputs/211m-private-hold-model-proof.json`, the native driver/relocation manifests and `211m-kernel-ABI-proof.json`. Native emission/execution budget is **LD-TIMER**; physical calibration is **LD-CAL**; remaining ROM/indirect boundaries and other native forms are **LD-ABI**. A passing finite timer model does not discharge native timing.

## Inputs — physical sensing, movement and completion

Current `src/filters/initialization.rs` observes role-bound closed/open conjunctions (address encoding, bit, active level), or a complete bounded initializer when that reader is absent. SAT1 E46B mask/value is a projected register observation. The full owner binds the physical sensor/configuration program, output/feedback movement, debounce/qualification clocks, reset/motion services and mechanical state meaning.

It exports B's request, abort, status, callback and error interface. Completion must arise from A's real physical observation; an observer may not synthesize arrival from B's departed predicate. Source physical arrival3 and target closed20 qualification are separate clocks in the single-input→dual-input construction. Callback registration/removal, task16 epoch invalidation, failed start, abort and re-registration belong to this owner. Generic scheduler/IRQ primitives remain typed imports; shared GPIO/PWM and reset services have one Controller provider.

Bindings are `inputs-verdict/` complete driver/observer manifests, `jm-reset-root-manifest.json`, current202-member input census and `xu-four-native/report.md`. Lifecycle is **IN-EPOCH**, exact reset provider **IN-RESET**, and remaining legacy/XU forms **IN-FAMILIES**. A BSS end address, absent literal reference or unused-looking RAM gap does not reserve memory.

## Host — physical transport and incoming protocol

Current `src/filters/host.rs` observes FE94 bit7 or a bound older initializer. This bit is not an established voltage or protocol meaning. The complete owner binds host physical initialization, FE94/FE95/FEAB/FF6C and other actual mode effects, reset/power/resume order, runtime masks, physical transfers, interrupt acknowledgement and completion/error publication in both components.

Its exported boundary is B's logical protocol/read-only preflight/retry/error API. Physical transfer and reset services are A services or proved equivalents. Storage supplies the final mapped physical transactions. Shared resident scheduler, allocators and IRQ services are imports with concrete caller/resource domains; the Host owner cannot assume their ABI or capacity. Logging need not match A's bytes, but real transport errors remain visible through B's API.

The authoritative selected candidate is indexed by `host-parent/driver-closure/current-contract-index.json`; historical candidates are not substitutes. Its installed physical capsule is9898bytes, with concrete reset/power/snapshot resources. Task20 needs116additional stack bytes; task2's actual outer-call delta must share the same arena budget. Complete native free-block and allocation/free lifetime safety is **HO-RESOURCES**, exported caller/IRQ relation **HO-CALLERS**, and remaining SAT1 physical/reset directions **HO-SAT1**.

## Phase — assignment within an output interface

Phase owns channel assignment only inside a bound native output interface. Current direct/swapped assignment does not make byte-output F908/F909 and split-word/control F910..F913 electrically interchangeable. The cross-interface case belongs to a complete Controller output service, with Phase consuming that service's bound assignment. **PH-SUPPORT** seals the implemented same-interface predicate; **PH-INTERFACE** disposes the remaining observed physical output cases. Neither moving a case to another owner nor a lack of merge benefit is an impossibility proof.

## Definition gate acceptance

This document closes definition gates8/14/20/26/32/38/44: the observed value, owned native behavior, exported logical/physical boundary, shared provider and exact blocking issue are now explicit for each owner. It closes **BND as a definition task only**. Every positive-solution and excluded-domain gate stays open until its named evidence meets the separate acceptance test. Future unknown firmware remains outside a detector's proved predicate; that implementation refusal is not a claim that its correction is physically impossible.
