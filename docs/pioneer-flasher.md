# Pioneer flasher (`freemkv-flash`)

Reference for the Pioneer / Renesas path of the `freemkv-flash` CLI: the
commands, which one to use, and the policy that decides whether a flash is
allowed. For the MediaTek path see the top-level `README.md`. For the
modified-bundle proposal see
`crates/freemkv-flash/docs/pioneer-modified-profile-contract.md`.

> **Beta. A bad flash can permanently brick the drive.** Eject any disc first;
> the tray must be empty and closed. Do not power off or unplug during a write.

## Commands

| Command | Writes? | Summary |
|---|---|---|
| `list` | no | List optical drives and the selector to pass to the other commands. |
| `info` | no | Identify and classify a drive or a firmware file. Read-only. |
| `backup` | no | Capture a flashable OEM-format package (two `.enc` components in a tar). |
| `dump` | no | Raw read of the whole device, `0x000000..0x600000`, into one `.bin`. Diagnostics only. |
| `flash` | with `--execute` | Validate and plan; write only with all safety flags. Dry run by default. |

```sh
freemkv-flash list
freemkv-flash info /dev/sg0
freemkv-flash backup /dev/sg0 -o backup.tar
freemkv-flash dump /dev/sg0 -o drive.bin            # add --force for degraded drives
freemkv-flash flash /dev/sg0 -i update.tar          # dry run: prints plan, no writes
freemkv-flash flash /dev/sg0 -i update.tar \
    --backup preflash.tar --execute --i-understand-risk
freemkv-flash flash /dev/sg0 -i known-good.tar --recover \
    --execute --i-understand-risk
```

The device argument is a `list` number, a `/dev` path, or an `ioreg:` id. It
may be omitted when exactly one drive is connected.

## Which should I use?

**`backup` vs `dump`: you almost always want `backup`.**

- `backup` captures a flashable OEM-format package: two OEM `.enc` components
  (Kernel and Normal) in a tar. `flash -i` reads it back and can restore it.
  Use it for rollback, before any flash.
- `dump` is a raw snapshot of the device address space. It is **not a
  flashable artifact.** It includes drive RAM state that differs between runs;
  only the FLASH region is deterministic. Use it for diagnostics and forensics,
  or to salvage something from a degraded drive. `dump --force` stops trusting
  what the drive reports (identity/layout failures become warnings) and is
  still read-only.

**`flash` vs `flash --recover`:**

- Plain `flash` is for normal updates and rollbacks. All gates below apply.
- `flash --recover` is for a degraded or soft-bricked drive. It re-pushes
  known-good bytes. It bypasses the date/pair refusals and the mandatory
  pre-flash backup, but **keeps the family gate**. It still needs `--execute`
  and `--i-understand-risk`. Experimental and hardware-unvalidated.

## Flash policy

Three gates and one side-check decide what `flash` will do.

1. **Hardware family match.** The family of the installed (drive) Normal must
   equal the family of the bundle's Normal (`fw::get_family`). If the silicon
   differs, the flash is refused. `--force` bypasses this gate. It also waives
   one refusal of gate 2: an installed Kernel tag that could not be read. It
   bypasses nothing else.
2. **Kernel ID tag match (Normal-only bundles).** When the bundle contains only
   a Normal, the installed Kernel's tag must equal the Kernel tag the incoming
   Normal requires. This mirrors Pioneer's OEM updater
   (`memcmp(F1+0x18, file+0xD0, 8)`). On mismatch the flash is refused with a
   message to use a Kernel+Normal package instead.
3. **Bundle self-consistency.** The bundle is checked on its own: bad headers,
   SAT mismatch between Kernel and Normal, the Kernel's own tag differing from
   the tag the Normal requires, or an unrecovered envelope tail. Any of these
   is refused **unconditionally**. `--force` does not bypass it.
4. **Site-1 downgrade patch (side-check, not a refusal).** When writing a
   Kernel whose decoded marker is `FF` or `00` to a drive whose installed
   marker is `01`, the executor patches the Kernel body in flight
   (`[0xFE]` `FF`/`00` -> `01`, plus `0xFE00` mod 2^32 at `0x1020`), re-encodes
   it, and writes. A loud warning is printed. This is the section 15.3 patch.

Direction (up or down), SAT change (same or cross), and era (`FF` or `01`) do
not enter the gate decisions. The tag check decides. A separate "reflash" case
is not needed; it is covered by the same gates.

### Decision matrix

| Condition | Normal flash | `--force` | `--recover` |
|---|---|---|---|
| Family differs | refused | allowed | refused (unless `--force`) |
| Normal-only bundle, Kernel tag mismatch | refused | refused | see note |
| Normal-only bundle, installed Kernel tag unknown | refused | allowed (warning) | see note |
| Bundle fails self-consistency | refused | refused | refused |
| Kernel marker `FF`/`00` onto installed `01` | allowed, Kernel patched, warning | same | same |
| Everything matches | allowed | allowed | allowed |

Note: `--recover` waives the date/pair refusals and the pre-flash backup, not
the bundle self-consistency checks. Treat the Kernel-tag check as applying
unless you have verified otherwise for your build.

## Safety and what will not be done

- A live write requires all of: `--execute`, `--i-understand-risk`, and a
  pre-flash backup (`--backup <file>`). If the backup fails, the flash aborts
  before any write. (`--skip-backup` and `--recover` waive it; both are
  dangerous.)
- Without `--execute`, `flash` is a dry run: it prints the plan and issues no
  firmware writes.
- `--force` never bypasses bundle self-consistency. A malformed or inconsistent
  bundle is never written.
- `dump` and `backup` are read-only and do not write to the drive.
- Kernel mode is never needed for BD flashing, and the flasher never enters
  it. OEM BD updates use only `04/FF -> 07/FE -> 07/F0 -> 05/FF`. The F3/F2
  handshake exists only in the `pioneer-optical` crate, for the experimental
  DVR path.
- There is no `verify` command, and no safe abort once the write has begun.
