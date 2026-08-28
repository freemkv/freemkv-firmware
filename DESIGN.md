# freemkv-flash — agreed design (2026-08-28)

Standalone, multi-OS optical-drive **flasher/dumper**. No MakeMKV dependency. 100% Rust.
Binary name: `freemkv-flash` (crate renamed from `freemkv-firmware`; repo stays freemkv-firmware).
Phase-B firmware *authoring* tooling will be a second binary later (`freemkv-forge`).

## Commands — exactly three; `info` is the default
| Invocation | Writes? | Input | Behavior |
|---|---|---|---|
| `freemkv-flash <dev>`  (bare) | no | — | alias for `info` |
| `freemkv-flash info <dev>` | no | — | INQUIRY + boot banner + **classify family**; print to screen |
| `freemkv-flash dump <dev> [-o out.tar]` | no | — | read per-unit regions → interoperable tar |
| `freemkv-flash flash <dev> -i <file> [flags]` | **yes** | `.bin` or `.tar` | write; see below |

- **`restore` does not exist** — it is just `flash` with a `.tar` input. `flash` sniffs the
  input: `.bin` = full firmware image (main region); `.tar` = per-unit dump (restore regions).
- **`verify` does not exist as a command** — `flash` **always** read-back-verifies after writing
  (read the written ranges, compare to what was sent). Verify is integral to flash, flash only.
  `info`/`dump` never verify (dump is a read; there is nothing to compare against).

## flash = a DUMB flasher (decided 2026-08-28)
The flasher takes a file and writes it to the drive **verbatim**. It does NOT modify the image.
No DE byte, no downgrade magic, no per-unit splice, no CMAC resign — all of that is *firmware
modification* and belongs to a SEPARATE future tool (`freemkv-forge`: firmware X→Y — add
downgrade, remove speed lock, remove AACS host-cert). **Out of scope here; ignored for now.**

flash's entire job: (1) back up via a pre-flash dump, (2) write the given bytes to the drive,
(3) read-back verify. Nothing else touches the image.

## flash safety invariants
- Refuses without `--execute --i-understand-risk`. Without `--execute` it prints a dry-run plan.
- **Always attempts a pre-flash dump (backup only — NOT spliced into the image).** On success it
  is saved so the drive can be restored later. On dump failure, flash aborts unless
  `--rescue-no-dump` (the only skip, for a drive that can no longer be read).
- **Always read-back verifies** after write; mismatch is a hard error. flash only.
- Blocks cross-flash (model mismatch) unless `--allow-cross-flash`; blocks size mismatch.
- Never writes on unknown/unsupported silicon (see MTK-gate).
- The input is written verbatim: `.bin` = full 2 MB image (whole image streamed via WRITE_BUFFER
  0x3B mode 6); `.tar` = per-unit dump, restore exactly those regions verbatim.

## enc — DETECT whether the drive needs an encrypted image, then enc or not
Open question under active research (ENC_DETECT_RESEARCH.md). Working hypothesis (NOT yet proven):
the enc requirement lives in the **currently-running firmware's** flash-accept path — **stock
firmware demands the enc format; MakeMKV-patched firmware also accepts plaintext.** Detection
signal = is the drive currently stock vs MK (MK markers `MMkv`/`LbDr` via READ_BUFFER 3C).
Design: **enc is ALWAYS auto-detected and auto-chosen — the user never decides.**
`enc_needed(dev) -> bool` runs on every flash; if true, AES-128-ECB the whole image
(key 5e9e4f00..2324) before streaming; else plaintext. `--enc`/`--no-enc` exist ONLY as a
hidden expert override for debugging and are never required in normal use. Until the research
lands, `enc_needed` defaults to plaintext (returns false) but the auto-detect call site is wired.
(Supersedes the earlier "plaintext only, never enc" note — that read one image's drive-side
handler, not stock-vs-MK, and may be wrong.)

## Two independent plug-in layers
```
src/
  main.rs                 = freemkv-flash.rs: arg parse, classify, dispatch the 3 commands
  platform/               OS transport — SCSI passthrough (the ScsiDevice trait)
    mod.rs                trait ScsiDevice { inquiry, read_buffer, write_buffer, get_config };
                          open(dev) -> Box<dyn ScsiDevice>, compile-time OS selection
    linux.rs              #[cfg(target_os="linux")]   SG_IO ioctl   ← first hardware test (10.1.7.13)
    windows.rs            #[cfg(target_os="windows")] SPTI IOCTL_SCSI_PASS_THROUGH_DIRECT
    mac.rs                #[cfg(target_os="macos")]   IOKit SCSITaskDeviceInterface
  drive/                  chip family — flash/dump logic + classification
    mod.rs                trait DriveFamily { classify, dump, flash, verify, banner_offsets };
                          classify(&mut dyn ScsiDevice) -> Family
    mtk.rs                MediaTek MT1959/MT1939 — the only fully-implemented family
    renesas.rs            stub: classifies positive, dump/flash return Unsupported
    pioneer.rs            stub: classifies positive, dump/flash return Unsupported
  cmac.rs manifest.rs     (existing) CMAC verify/resign, manifest
```

## MTK-gate (this tool is MediaTek-only for now)
Every command classifies the drive before acting:
- **GET_CONFIG 0x46 feature 0x010C returns 01 0C** ⇒ MediaTek (MT19xx). Supported.
- **READ_BUFFER 0xF1 succeeds** ⇒ Pioneer / HL-DT-ST-Renesas. Classified, NOT supported.
- neither ⇒ Unknown.

`info` prints the detected family. `dump` and `flash` **abort** on anything but MediaTek:
> "This is a <Pioneer|Renesas|Unknown> drive. freemkv-flash currently supports MediaTek
>  MT19xx only. Aborting — no commands sent." (exit non-zero, nothing written.)

This makes running the tool on a Pioneer drive safe: it stops before issuing any dump/flash CDB.

## Device argument by OS
- Linux: `/dev/sgN` (SG_IO). May also accept `/dev/srN` and map to sg.
- Windows: `\\.\CdRomN`.
- macOS: IOKit service / BSD name.

## Reused work
`src/dump.rs` (landed): READ_BUFFER 3C-06 region reads, INQUIRY, GET_CONFIG 0x0108/0x010C for
serial/fw-date, interoperable tar writer/reader. Folds into `drive/mtk.rs`.
