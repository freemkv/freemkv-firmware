# Hoard-backed drive Dump and OEM Backup coverage

## User flow

- **Dump** captures the drive's accessible firmware bytes as a raw, coverage-described artifact. It records the commands, ranges, short reads and failures. It does not claim completeness when ranges are missing.
- **Backup** captures every firmware component needed by the family's OEM update format, reconstructs the original envelope or image, and validates the result against the captured bytes and known OEM references. An unknown or unsupported format must not be presented as an OEM backup.
- **Submit Report** sends selected diagnostic history only. After a successful Dump or Backup, **Submit Dump** or **Submit Backup** sends that file plus the chosen history's events and diagnostic logs, subject to browser approval. The approval page names the firmware bytes.
- If Backup has no proven capture and OEM construction path, explain that before starting and offer **Dump for Review** when a real firmware dump path is available. A failed backup must never silently submit a diagnostic-only file as a dump.

## Evidence inventory, 2026-10-23

| Family | Held firmware | Current app | Next work |
| --- | --- | --- | --- |
| Pioneer SAT | 904 OEM envelopes: 343 Kernel, 520 Normal, 41 Plane | SAT H8 Kernel/Normal read and envelope builder. The refreshed Normal table has 491 authenticated, byte-exact decoded images; 32 SAT 8000 entries were added. | Verify live read coverage per SAT hardware; investigate Plane and the remaining excluded envelopes separately. |
| Pioneer ATA | 320 OEM envelopes: 81 Kernel, 190 Normal, 49 Plane, across 29 hardware IDs | F1 accepts ATA for classification, but Backup requires SAT and the existing H8 builder excludes all 81 ATA Kernels. | Derive ATA component read map, geometry, codec/envelope construction and authentication from OEM resources; implement a distinct ATA capture profile and validate on hardware. |
| Pioneer SCSI | 3 OEM envelopes: 1 Kernel, 2 Normal | F1 accepts SCSI for classification, but Backup requires SAT; the Kernel is outside the H8 builder. | Same protocol and envelope work, scoped to the held SCSI model. |
| Pioneer REC 8301/8800/8C00 | Report ZIPs contain INQUIRY/F1 identity, not firmware bytes. Main hoard index has L08SHB inquiry only, no package; no matching L11SH/L13SH entry. A SAT 8801/ID92 pair is a different hardware tag. | A dump-only fallback now accepts valid Pioneer F1 identities and invokes the existing raw capture routine; OEM Backup and Flash remain unavailable through that fallback. | Collect live dumps and inspect actual read coverage; use the captured components and exact OEM references to develop Backup. Successful routing does not establish which ranges these drives return. |
| MediaTek MT19xx | Current hoard yields 85 candidate builds under the catalog generator. | Complete 2 MiB read, OEM image reconstruction and dump already exist. The embedded catalog remains at 69 builds because the generated replacement failed existing provenance, default-byte and crossflash tests. | Reconcile the generator with the app's stricter OEM admission rules before adding any entries; verify live captures for newly admitted revisions. |
| Other held families | Hoard also has older MediaTek images, Pioneer legacy ROMs, and Renesas SH7200 payloads. | No live family-specific capture/restore contract in this app. | Inventory each controller's read route and OEM package shape; implement separate backends rather than applying MT19xx or SAT addresses. |

The image inventory is an offline file census. An OEM updater proves the bytes and wrapper for that release; it does not prove where a running drive exposes its installed firmware, which per-unit state is included, or whether an arbitrary live read is restorable. Backup reconstruction must validate the captured controller and component layout. SAT `8301` or `8800` is not evidence for REC `8301` or `8800`.

## Implementation gate per family

1. Preserve the existing Pioneer Dump commands, memory map and file format. A Pioneer vendor identity and a complete printable, nonblank F1 hardware field allow an attempt without an OEM-family allowlist. The existing OEM backend takes precedence; the fallback grants only Dump.
2. Use the capture directory's read records to determine actual coverage. Unavailable and unattempted zero-filled regions are not observed firmware bytes. A saved dump alone does not prove a complete firmware capture; no identity-only fallback replaces the memory-read attempt.
3. Derive component boundaries, header fields, encoding keys and signatures from held OEM firmware. Rebuild held envelopes byte-for-byte in offline tests before enabling OEM Backup.
4. Capture and validate each live component. Gate OEM Backup on complete reads and reconstruction; do not replace missing bytes with a catalog image and call it the drive's backup.
5. Test the live route on representative hardware, including a readback or independent consistency check. Classification and an offline envelope match alone are insufficient.

## Current implementation status

The report ZIP path can include a completed artifact with selected diagnostic logs. Pioneer SAT Normal metadata has been refreshed. The existing Pioneer Dump command and its B0 memory map are unchanged. A dump-only registry fallback admits REC and other valid Pioneer F1 hardware identities after existing OEM protocol probes decline them. Tests cover the three reported REC identities reaching memory capture, output bytes, GUI availability, continued Backup/Flash refusal, and Recovery behavior. Live REC memory-read success still needs hardware confirmation. The current report API limits uploads to 50 MiB, so larger future dumps require an increased or chunked upload path.
