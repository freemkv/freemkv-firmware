# Flash GUI hard-coded UI copy audit

Source snapshot from 2026-10-20, before the message-ID migration. Line references
describe that snapshot and will move as the migration proceeds.

This is a source-level inventory of literal text that can reach the flash GUI, including labels, help text, status messages, confirmation copy, analysis copy, and app-owned native menu items. It excludes tests, schema/event keys, protocol values, filenames, and toolkit identifiers. Text inside `{…}` is a format template; runtime values such as paths, drive names, firmware tags, and error details should remain data.

The scanner covered `crates/freemkv-flash-gui/src` runtime modules. Each entry gives the first source location where the literal occurs. This is an audit aid, not proof that every runtime-generated string was captured.

## Shared warnings, task names, and drive/status labels

| Source | UI text |
|---|---|
| `ui.rs:1967` | freemkv Firmware Utility {} |
| `ui.rs:1970` | Optical drive |
| `ui.rs:1980` | No optical drive found |
| `ui.rs:1981` | Refresh |
| `ui.rs:30` | Recovery skips backups and compatibility checks. Incompatible firmware can make the drive unusable. |
| `ui.rs:33` | Flashing can permanently disable the drive. Keep it connected and powered until completion. |
| `ui.rs:35` | I understand and want to update this drive |
| `ui.rs:37` | Keep the drive connected and powered until this finishes. |
| `ui.rs:40` | The pre-flash backup is saved. Cancel keeps it and writes nothing to the drive. |
| `ui.rs:42` | Cancelled at the confirmation: nothing was written; the pre-flash backup is kept. |
| `ui.rs:43` | Operation worker failed unexpectedly. If flashing was underway, the drive state is uncertain; keep the backup and inspect the drive before retrying. |
| `ui.rs:44` | The worker stopped before reporting a result. If a flash was underway, inspect the drive before retrying. |
| `ui.rs:45` | Diagnostic log |
| `ui.rs:73` | Drive info |
| `ui.rs:74` | Inspect |
| `ui.rs:75` | Compare |
| `ui.rs:76` | Backup |
| `ui.rs:77` | Dump |
| `ui.rs:78` | Flash |
| `ui.rs:79` | Recovery |
| `ui.rs:116` | probing… |
| `ui.rs:117` | Profile unavailable |
| `ui.rs:834` | Session history is not being saved: {error} |
| `ui.rs:871` | Ready |
| `ui.rs:879` | Ready. Select an optical drive and choose an action. |
| `ui.rs:1050` | No optical drive found |
| `ui.rs:1065` | Language changed for this session but could not be saved: {error} |
| `ui.rs:1113` | Drive information |
| `ui.rs:1117` | Check file |

## Status, progress, and operation messages

| Source | UI text |
|---|---|
| `ui.rs:1169` | Recovery plan |
| `ui.rs:1193` | Cancelling after the current operation returns… |
| `ui.rs:1210` | Report history is unavailable. |
| `ui.rs:1218` | Opening report approval in your browser… |
| `ui.rs:1227` | {error:#} |
| `ui.rs:1238` | Stopping report submission after the current request finishes… |
| `ui.rs:1246` | Could not read diagnostic log: {e} |
| `ui.rs:1329` | Diagnostic log exported: {} |
| `ui.rs:1330` | Could not export diagnostic log: {error} |
| `ui.rs:1344` | Saved {} |
| `ui.rs:1345` | Could not save report: {e} |
| `ui.rs:1350` | Check file |
| `ui.rs:1377` | Raw dump |
| `ui.rs:1379` | Backup |
| `ui.rs:1480` | Flash plan |
| `ui.rs:1495` | Firmware update |
| `ui.rs:1566` | {label}: not run by the GUI gate. |
| `ui.rs:1573` | No optical drive selected. |
| `ui.rs:1578` | {label}… |
| `ui.rs:1588` | {label}: {device} |
| `ui.rs:1629` | Could not submit report: {error} |
| `ui.rs:1680` | {} complete |
| `ui.rs:1682` | {} cancelled |
| `ui.rs:1700` | {message} {} |
| `ui.rs:1727` | ✓ done. |
| `ui.rs:1729` | ✗ {}: {e} |
| `ui.rs:1748` | Operation interrupted |
| `ui.rs:1750` | ✗ worker disconnected before reporting completion; operation outcome is unknown. |
| `ui.rs:1810` | File origin inspection stopped unexpectedly. |
| `ui.rs:1811` | {e:#} |
| `ui.rs:1855` | Matches known OEM firmware; drive compatibility is unverified. |
| `ui.rs:1862` | Could not inspect file origin: {error} |
| `ui.rs:1864` | Checking file origin… |
| `ui.rs:1905` | {label}... |
| `ui.rs:1913` | Diagnostic warning |
| `ui.rs:1938` | In-memory diagnostics; no diagnostic file was saved.<br>{}<br>{} |
| `ui.rs:1947` | No diagnostic log is available for this operation. |
| `ui.rs:1955` | Could not read diagnostic log: {error} |

## Task forms, confirmation, and diagnostics

| Source | UI text |
|---|---|
| `ui.rs:2034` | Read drive information |
| `ui.rs:2038` | Check file… |
| `ui.rs:2043` | Connect an optical drive, then select Refresh. |
| `ui.rs:2053` | Capture all accessible drive memory into a raw file. |
| `ui.rs:2055` | Save firmware backup files for restoration. |
| `ui.rs:2061` | Save raw dump… |
| `ui.rs:2067` | Save backup… |
| `ui.rs:2078` | Change file… |
| `ui.rs:2087` | Flash now |
| `ui.rs:2090` | Check file |
| `ui.rs:2099` | Choose firmware… |
| `ui.rs:2108` | Current firmware |
| `ui.rs:2111` | Read from drive |
| `ui.rs:2116` | Choose Current… |
| `ui.rs:2125` | Current firmware (optional receiver reference) |
| `ui.rs:2126` | Choose Current file or TAR… |
| `ui.rs:2127` | If live receiver code cannot be read, select the firmware currently running—not the firmware to install. For BH16NS40 INTM, select the TAR's intermediate.bin. |
| `ui.rs:2131` | Reads installed firmware for protocol analysis. No backup file is saved. |
| `ui.rs:2137` | Current firmware member |
| `ui.rs:2146` | Selected: |
| `ui.rs:2162` | Firmware to flash |
| `ui.rs:2164` | Firmware to flash (Kernel + Normal) |
| `ui.rs:2177` | Select exactly one image to recover. No second stage will run. |
| `ui.rs:2180` | Recovery image |
| `ui.rs:2208` | Recover |
| `ui.rs:2223` | Source |
| `ui.rs:2224` | Source A |
| `ui.rs:2225` | Source B |
| `ui.rs:2231` | Firmware file… |
| `ui.rs:2236` | Selected drive… |
| `ui.rs:2249` | {device} → capture {}{} |
| `ui.rs:2251` | (as a backup) |
| `ui.rs:2253` | Retained analysis: {} |
| `ui.rs:2254` | Choose a firmware file or drive. |
| `ui.rs:2259` | Save a drive capture as a backup |
| `ui.rs:2267` | Compare |
| `ui.rs:2267` | Inspect |
| `ui.rs:2282` | {} — {label} ({}%) |
| `ui.rs:2287` | {} — {label} |
| `ui.rs:2299` | Working… |
| `ui.rs:2312` | Cancel analysis |
| `ui.rs:2322` | Open results… |
| `ui.rs:2336` | Save diagnostic log… |
| `ui.rs:2342` | {warning}<br>{notice} |
| `ui.rs:2347` | View Log |
| `ui.rs:2353` | Cancel report |
| `ui.rs:2358` | Submit Report |
| `ui.rs:2365` | Drive: {} |
| `ui.rs:2366` | Image: {} |
| `ui.rs:2373` | Receiver detected directly; no Current firmware required |
| `ui.rs:2375` | Current: {} |
| `ui.rs:2376` | Current: read from drive |
| `ui.rs:2379` | Current member (receiver reference): {member} |
| `ui.rs:2382` | Target member (will be flashed): {member} |
| `ui.rs:2402` | File origin: {}. {} |
| `ui.rs:2408` | Confirm recovery |
| `ui.rs:2410` | Confirm flash |
| `ui.rs:2425` | Cancel |
| `ui.rs:2431` | Diagnostic log |
| `ui.rs:2433` | Copy diagnostic log |
| `ui.rs:2439` | Close |
| `ui.rs:2441` | Attach this log to your bug report. |

## Drive information and analysis results

| Source | UI text |
|---|---|
| `ui.rs:2543` | {e:#} |
| `ui.rs:2553` | Drive not detected after operation |
| `ui.rs:2611` | General information |
| `ui.rs:2612` | Additional information |
| `ui.rs:2613` | DVD region |
| `ui.rs:2614` | Device settings |
| `ui.rs:2615` | Media capabilities |
| `ui.rs:2616` | Firmware operations |
| `ui.rs:2627` | Read: |
| `ui.rs:2628` | Write: |
| `ui.rs:2629` | Yes |
| `ui.rs:2642` | -ROM |
| `ui.rs:2667` | CD- |
| `ui.rs:2667` | DVD- |
| `ui.rs:2667` | DVD+ |
| `ui.rs:2682` | Current settings · read only |
| `ui.rs:2695` | Codec |
| `ui.rs:2695` | Logical bytes |
| `ui.rs:2707` | Unchanged |
| `ui.rs:2709` | {bytes} bytes |
| `ui.rs:2711` | {:.1} KiB |
| `ui.rs:2716` | Unknown |
| `ui.rs:2725` | Role: |
| `ui.rs:2740` | {} @ {:#x}: {} |
| `ui.rs:2747` | {} — {} records |
| `ui.rs:2767` | Drive state captured at {} (Unix seconds) |
| `ui.rs:2774` | DVD region and change counters are available only from a live drive capture. |
| `ui.rs:2780` | {name}: |
| `ui.rs:2781` | Not included in this source. |
| `ui.rs:2786` | Hardware family: {} |
| `ui.rs:2793` | A: {} — {} |
| `ui.rs:2798` | B: {} — {} |
| `ui.rs:2803` | No unexpected differences. |
| `ui.rs:2804` | Unexpected differences in 1 region. |
| `ui.rs:2805` | Unexpected differences in {n} regions. |
| `ui.rs:2808` | Inspect A |
| `ui.rs:2809` | Inspect B |
| `ui.rs:2823` | Partially compared |
| `ui.rs:2827` | Not available |
| `ui.rs:2827` | {p:.2}% |
| `ui.rs:2830` | None |
| `ui.rs:2831` | Expected |
| `ui.rs:2832` | Unexpected |
| `ui.rs:2840` | Region |
| `ui.rs:2841` | Role |
| `ui.rs:2842` | Changed in A |
| `ui.rs:2843` | Changed in B |
| `ui.rs:2844` | Different |
| `ui.rs:2845` | Verdict |
| `ui.rs:2851` | Changes by region |
| `ui.rs:2852` | Percentages use decoded and expanded bytes across both sources. Metadata and verified address relocations do not count as differences. |
| `ui.rs:2855` | {} address-relocation or metadata changes excluded. |
| `ui.rs:2859` | Excluded changes |
| `ui.rs:2864` | Technical details |
| `ui.rs:2867` | Hardware family: {:?} |
| `ui.rs:2871` | Firmware analysis |
| `ui.rs:2873` | Copy report |
| `ui.rs:2874` | Save text… |
| `ui.rs:2875` | Save JSON… |

## Report workflow messages

| Source | UI text |
|---|---|
| `support.rs:136` | Session history is available only in memory |
| `support.rs:213` | A saved history event exceeds 64 KiB; archive the affected history file and retry. |
| `support.rs:215` | Saved event history exceeds the 32 MiB scan limit; archive old history and retry. |
| `support.rs:242` | There are more than {MAX_LOGS} logs. Choose this session or remove old logs. |
| `support.rs:250` | The selected logs exceed 50 MiB. Choose this session or remove old logs. |
| `support.rs:257` | freemkv-report-{}-{}.zip |
| `support.rs:274` | logs/{name} |
| `support.rs:286` | The selected logs grew beyond 50 MiB while creating the report. |
| `support.rs:315` | Could not finish report ZIP |
| `support.rs:322` | A report history event exceeds 64 KiB. |

## macOS menu labels

| Source | UI text |
|---|---|
| `mac.rs:1563` | freemkv Flash |
| `mac.rs:1564` | Quit freemkv Flash |
| `mac.rs:1567` | Edit |
| `mac.rs:1569` | Copy |
| `mac.rs:1570` | Select All |
| `mac.rs:1574` | Window |
| `mac.rs:1576` | Minimize |
| `mac.rs:1577` | Close |

## Windows menu labels

| Source | UI text |
|---|---|
| `windows.rs:611` | &Refresh drives	F5 |
| `windows.rs:616` | E&xit	Alt+F4 |
| `windows.rs:623` | &Copy	Ctrl+C |
| `windows.rs:627` | Select &All	Ctrl+A |
| `windows.rs:633` | &Diagnostic log\u{2026} |
| `windows.rs:649` | &File |
| `windows.rs:653` | &Edit |
| `windows.rs:657` | &View |

## Workflow messages passed into the UI

| Source | UI text |
|---|---|
| `ops.rs:38` | Unsupported |
| `ops.rs:74` | Recovery not offered: could not identify the receiver ({e}) |

**Inventory size:** 216 distinct literal candidates after deduplication within each section. Some copy repeats across sections or is assembled from runtime data.
