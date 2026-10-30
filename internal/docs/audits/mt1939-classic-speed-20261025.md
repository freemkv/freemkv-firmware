# Classic native read-speed selector

One shared detector and emitter now cover all 24 published classic inputs. The
previous explanation that 0x1b854-style halfword clamps controlled read speed
was incorrect: tracing the called helper reaches an elapsed-counter comparison
and MMIO counter source. That code is unchanged.

The selected contract instead binds ARM RMAX and OPTM setters through their
actual byte stores, resolved SRAM literals, log strings and shared logger. A
real caller must consume the Thumb selector result into that same OPTM cell.
Every reachable selector path must remain a pure bounded leaf and converge on
the same byte-normalization tail. Calls, stores, unknown reads, loops, alternate
returns and entry into the middle of the replaced tail are rejected. Four
native policy/compiler forms use this one detector; source hashes are fixture
provenance, never selection rules.

The wide branch replaces the tail's LSL/LSR, preserving the caller LR. The stub
saves r1, selects the existing native RMAX only for Speed On and initialized
values 1..48, otherwise keeps the OEM result, restores r1, replays byte
normalization and returns to the original caller. OEM media/hardware maxima,
write-speed controls, thermal and recovery logic remain untouched. This is a
read-default selector change, not an override of every native safety limit.

Validation:

- All 24 full source images: 17,280 independent ARM CPU comparisons using the
  actual emitted stub and installed wide branch. OEM output/flags and live
  registers, LR and SP are checked against native execution; enabled output is
  checked against the bound native maximum. Zero/invalid maxima retain OEM.
- Four native excerpt fixtures: 2,880 execution comparisons run in CI and QA.
- Rust regression rejects a BL at the tail even after valid re-signing; the
  caller-preserving B.W is required. Existing real classic Create/Modify
  equivalence and structural audit tests pass with the new speed hook.
- Full 1,085-input audit builds all 196 supported results, matches preview/output
  hashes, preserves every source hash, and retains explicit Flash refusals.

All 24 classic published hashes move from 4/6 to 5/6 grouped features. This does
not establish MT1939 physical UHD capability. The native recognition, layer and
read path remain the outstanding Unrestricted investigation; no UHD support is
inferred from the presence of HRL, encryption or a successfully built stub.
