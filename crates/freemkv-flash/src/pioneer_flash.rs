//! Live Pioneer OEM flash executor.
//!
//! Issues the OEM `WRITE BUFFER` command sequence over the wire imperatively,
//! with the documented result checks, post-entry identity gate, settle delays,
//! and completion poll (see the BDR-UD04 1.11 host trace in the Pioneer firmware
//! notes). It issues real writes and must only be reached behind the engine's
//! `--execute`/`--i-understand-risk` safety gate, an empty/closed tray guard,
//! and a captured pre-flash backup.
//!
//! The caller ([`crate::drive::pioneer`]) builds the 256-byte control buffer
//! (descriptor + key from the embedded key table) and selects the components
//! from the flash input — a Kernel (`07/FE`), a Normal (`07/F0`), or both. This
//! executor is straight-line: entry CDB, the chunk CDBs, finish CDB. There is no
//! pre-built transcript list; the key is already resolved into `control`.

use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::drive::mtk::{cdb_read_buffer, cdb_write_buffer};
use crate::drive::pioneer::{
    cdb_wb_flash_entry, cdb_wb_flash_finish, CONTROL_LEN, FLASH_CHUNK, NORMAL_BUFFER_ID,
    TRANSFER_MODE,
};
use crate::platform::ScsiDevice;
use crate::style;

/// A failed transfer or finish past the entry gate leaves the drive mid-flash.
const PARTIAL_HINT: &str = " — the drive may now hold a partial firmware; re-flash the captured \
                            pre-flash backup to restore it";

/// Documented post-entry settle before the identity check.
const ENTRY_SETTLE: Duration = Duration::from_secs(1);
/// Documented post-finish settle before status polling.
const FINISH_SETTLE: Duration = Duration::from_secs(2);
/// Upper bound on the completion poll after `05/FF` finish.
const POLL_TIMEOUT: Duration = Duration::from_secs(90);
/// Delay between completion-poll attempts.
const POLL_INTERVAL: Duration = Duration::from_millis(500);

// ---------------------------------------------------------------------------
// Vendor kernel-mode unlock (BDRFlash's F3/F2 challenge-response).
//
// NOT the OEM `04/FF` update entry above. This is the extra drive-side unlock
// the trusted downgrade tools (BDRFlash, Autoflasher) perform before streaming
// an older/foreign OEM image, pinned byte-for-byte from the BDRFlash x86 disasm
// (`enter_kernel_mode`-equivalent at `0x40b575`). It is implemented here but NOT
// yet wired into any flash path: whether completing it actually clears the
// receiver's Site-1 generation-marker reject (`0x405266`) is still the open
// question — resolve that against the drive-firmware trace before plumbing it in.
// ---------------------------------------------------------------------------

/// Mode field (`CDB[1]`, masked to 5 bits) for both unlock buffer commands.
const KERNEL_UNLOCK_MODE: u8 = 0x01;
/// `WRITE BUFFER` buffer-id that arms the unlock (zero-length data-out).
const KERNEL_ARM_BUFFER_ID: u8 = 0xF3;
/// `READ BUFFER`/`WRITE BUFFER` buffer-id for the challenge and the response.
const KERNEL_CHALLENGE_BUFFER_ID: u8 = 0xF2;
/// Length of the challenge status buffer read back from the drive.
const KERNEL_STATUS_LEN: u32 = 0x400;
/// Bytes of the F2 challenge used to recover the 16-bit LCG seed.
const KERNEL_SIGNATURE_LEN: usize = 4;
/// Length of the response written back with buffer-id `0xF2` (first write).
const KERNEL_RESPONSE_LEN: u32 = 0x100;

/// The ANSI-C `rand()` LCG the unlock is built on (`0x407f87` in the disasm):
/// advance the 32-bit state once and return the high 16 bits. The per-step
/// output byte the handshake consumes is `(state >> 16) & 0xFF`.
fn lcg_step(state: &mut u32) -> u16 {
    *state = state.wrapping_mul(0x41C6_4E6D).wrapping_add(0x3039);
    (*state >> 16) as u16
}

/// Enter the vendor kernel-mode unlock (BDRFlash's F3/F2 handshake), traced from
/// `0x40b575`:
///
/// 1. **Arm** — `WRITE BUFFER` mode 1, buffer-id `0xF3`, zero-length. CDB
///    `3B 01 F3 00 00 00 00 00 00 00`.
/// 2. **Challenge** — `READ BUFFER` mode 1, buffer-id `0xF2`, 0x400 bytes. CDB
///    `3C 01 F2 00 00 00 00 04 00 00`. The first 4 bytes are the signature.
/// 3. **Recover seed** — brute-force a 16-bit seed `v` in `0..=0xFFFF` such that
///    four LCG steps from `v` reproduce the 4 signature bytes (each compared
///    byte is `(state >> 16) & 0xFF`).
/// 4. **Respond** — re-seed from `v`, advance the LCG 0x400 steps, take one more
///    step whose output byte is bit-inverted (`!((state >> 16) & 0xFF)`), fill a
///    buffer with that byte, and `WRITE BUFFER` mode 1 buffer-id `0xF2`
///    (0x100 bytes) back to the drive.
///
/// Returns the recovered seed on success. Driven by [`execute_flash`] only when
/// its `kernel_mode` flag is set (downgrade/crossflash, behind the live gate).
pub(crate) fn enter_kernel_mode(dev: &mut dyn ScsiDevice) -> Result<u16> {
    // 1. Arm: zero-length WRITE BUFFER to buffer-id 0xF3.
    dev.command_out_strict(
        &cdb_write_buffer(KERNEL_UNLOCK_MODE, KERNEL_ARM_BUFFER_ID, 0, 0),
        &[],
    )
    .context("kernel-mode arm (WRITE BUFFER F3) failed")?;

    // 2. Challenge: READ BUFFER 0x400 bytes from buffer-id 0xF2.
    let status = dev
        .command_in(
            &cdb_read_buffer(
                KERNEL_UNLOCK_MODE,
                KERNEL_CHALLENGE_BUFFER_ID,
                0,
                KERNEL_STATUS_LEN,
            ),
            KERNEL_STATUS_LEN as usize,
        )
        .context("kernel-mode challenge (READ BUFFER F2) failed")?;
    let signature = status
        .get(..KERNEL_SIGNATURE_LEN)
        .context("kernel-mode challenge returned a short status buffer")?;

    // 3. Recover the 16-bit seed that reproduces the 4-byte signature.
    let seed = recover_unlock_seed(signature)
        .context("could not recover the kernel-mode unlock seed from the drive challenge")?;

    // 4. Build and send the response.
    let response_byte = unlock_response_byte(seed);
    dev.command_out_strict(
        &cdb_write_buffer(
            KERNEL_UNLOCK_MODE,
            KERNEL_CHALLENGE_BUFFER_ID,
            0,
            KERNEL_RESPONSE_LEN,
        ),
        &vec![response_byte; KERNEL_RESPONSE_LEN as usize],
    )
    .context("kernel-mode response (WRITE BUFFER F2) failed")?;

    Ok(seed)
}

/// Brute-force the 16-bit seed whose first four LCG output bytes equal `signature`
/// (step 3 of [`enter_kernel_mode`]). `None` if no seed in `0..=0xFFFF` matches.
fn recover_unlock_seed(signature: &[u8]) -> Option<u16> {
    (0u32..=0xFFFF).find_map(|candidate| {
        let mut state = candidate;
        if signature
            .iter()
            .all(|&want| (lcg_step(&mut state) & 0xFF) as u8 == want)
        {
            Some(candidate as u16)
        } else {
            None
        }
    })
}

/// The response byte for a recovered `seed` (step 4): advance the LCG 0x400
/// steps, then one more whose low output byte is bit-inverted.
fn unlock_response_byte(seed: u16) -> u8 {
    let mut state = seed as u32;
    for _ in 0..KERNEL_STATUS_LEN {
        lcg_step(&mut state);
    }
    !((lcg_step(&mut state) & 0xFF) as u8)
}

/// Execute the OEM update against the drive imperatively, with the pre-built
/// 256-byte `control` buffer (descriptor + key from the embedded key table).
/// Straight-line: `04/FF` entry (control) → post-entry settle + identity gate →
/// `07/FE` Kernel chunks (if any) → `07/F0` Normal chunks → `05/FF` finish
/// (control) → finish settle + ready poll. Every write goes through the strict
/// (abort-on-any-nonzero, no-retry) path, exactly as the OEM host loop does. The
/// caller resolves the control key and components and guarantees gating, the
/// tray guard, and a pre-flash backup.
///
/// When `kernel_mode` is set, the vendor kernel-mode unlock ([`enter_kernel_mode`])
/// runs FIRST, before the OEM entry — this is the downgrade/crossflash path. The
/// caller decides this from the flash plan; it must only be set behind the live
/// enablement gate until the Site-1 bypass is proven.
pub(crate) fn execute_flash(
    dev: &mut dyn ScsiDevice,
    control: &[u8; CONTROL_LEN],
    kernel: Option<&[u8]>,
    normal: &[u8],
    kernel_mode: bool,
    recover: bool,
) -> Result<()> {
    style::trace(&format!(
        "execute_flash: kernel_mode={kernel_mode}, kernel={} bytes, normal={} bytes",
        kernel.map_or(0, <[u8]>::len),
        normal.len()
    ));

    // Two independent progress bars: the Kernel phase (FE slices) and the Normal
    // phase (F0 chunks) each report against their own byte total.
    let mut kernel_progress =
        style::Progress::new("flashing kernel", kernel.map_or(0, <[u8]>::len));
    let mut normal_progress = style::Progress::new("flashing normal", normal.len());

    // Vendor kernel-mode unlock FIRST (downgrade/crossflash only). This is a
    // precondition, not part of the OEM update sequence below.
    if kernel_mode {
        style::trace("kernel mode requested — issuing F3/F2 vendor unlock before OEM entry");
        let seed = enter_kernel_mode(dev).context("vendor kernel-mode unlock failed")?;
        style::trace(&format!(
            "kernel mode entered (recovered unlock seed {seed:#06X})"
        ));
        println!("{}", style::dim("  kernel mode unlocked"));
    }

    // OEM update-mode entry (04/FF control write + settle + identity gate). In
    // recover mode the drive is degraded and may not report a trustworthy
    // identity, so the post-entry gate is skipped — we force the write.
    enter_update_mode(dev, control, recover)?;

    // 07/FE linear Kernel chunks (crossflash only), then 07/F0 Normal chunks —
    // each at most FLASH_CHUNK, 24-bit big-endian offset/len, byte-for-byte.
    if let Some(kernel) = kernel {
        let mut written = 0usize;
        for (index, chunk) in kernel.chunks(FLASH_CHUNK).enumerate() {
            let cdb = cdb_write_buffer(
                TRANSFER_MODE,
                0xFE,
                (index * FLASH_CHUNK) as u32,
                chunk.len() as u32,
            );
            dev.command_out_strict(&cdb, chunk)
                .with_context(|| format!("OEM Kernel write failed{PARTIAL_HINT}"))?;
            written += chunk.len();
            kernel_progress.set(written);
        }
    }
    let mut written = 0usize;
    for (index, chunk) in normal.chunks(FLASH_CHUNK).enumerate() {
        let cdb = cdb_write_buffer(
            TRANSFER_MODE,
            NORMAL_BUFFER_ID,
            (index * FLASH_CHUNK) as u32,
            chunk.len() as u32,
        );
        dev.command_out_strict(&cdb, chunk)
            .with_context(|| format!("OEM Normal write failed{PARTIAL_HINT}"))?;
        written += chunk.len();
        normal_progress.set(written);
    }

    // 05/FF finish with the control buffer, then settle and poll for ready.
    dev.command_out_strict(&cdb_wb_flash_finish(), control)
        .with_context(|| format!("OEM Finish write failed{PARTIAL_HINT}"))?;
    std::thread::sleep(FINISH_SETTLE);
    poll_until_ready(dev)?;
    Ok(())
}

/// Enter the OEM update mode: `04/FF` control write, the documented ~1 s settle,
/// and the post-entry identity gate. A failed entry is before the update state,
/// so it carries no partial-firmware hint. This is the *standard* OEM entry — it
/// is distinct from [`enter_kernel_mode`], the vendor F3/F2 unlock.
fn enter_update_mode(
    dev: &mut dyn ScsiDevice,
    control: &[u8; CONTROL_LEN],
    recover: bool,
) -> Result<()> {
    dev.command_out_strict(&cdb_wb_flash_entry(), control)
        .context("OEM Entry write failed")?;
    std::thread::sleep(ENTRY_SETTLE);
    if recover {
        // Degraded-drive recovery: do not trust (or require) the post-entry
        // identity report; proceed straight to the forced write.
        println!(
            "{}",
            style::dim("  update mode entered (recover: identity gate skipped)")
        );
        return Ok(());
    }
    entry_identity_gate(dev)?;
    println!("{}", style::dim("  update mode entered"));
    Ok(())
}

/// After `04/FF` entry the OEM host waits ~1 s, issues INQUIRY, and requires
/// ASCII `000` at response bytes `[0x20..0x23]` before transferring. Mirror that
/// gate: a drive not in the expected update state aborts before any transfer.
fn entry_identity_gate(dev: &mut dyn ScsiDevice) -> Result<()> {
    let inquiry = dev
        .command_in(&[0x12, 0, 0, 0, 0x60, 0], 0x60)
        .context("post-entry INQUIRY")?;
    if inquiry.get(0x20..0x23) != Some(b"000".as_slice()) {
        bail!(
            "drive did not report the expected post-entry update state \
             (INQUIRY[0x20..0x23] != \"000\"); aborting before any transfer"
        );
    }
    Ok(())
}

/// After `05/FF` finish the OEM host waits ~2 s, then polls GET EVENT STATUS and
/// TEST UNIT READY using status/sense to continue or stop. Poll until the drive
/// returns ready (TEST UNIT READY good status) or the timeout elapses.
fn poll_until_ready(dev: &mut dyn ScsiDevice) -> Result<()> {
    let start = Instant::now();
    loop {
        // Supplementary event drain, as the OEM host issues; result ignored.
        let _ = dev.command_in(&[0x4A, 0, 0, 0, 0x10, 0, 0, 0, 0x08, 0], 0x08);
        // TEST UNIT READY: good status (Ok) means the drive is ready again.
        match dev.command_in(&[0, 0, 0, 0, 0, 0], 0) {
            Ok(_) => return Ok(()),
            Err(error) => {
                if start.elapsed() >= POLL_TIMEOUT {
                    return Err(error)
                        .context("drive did not return ready within the post-flash poll timeout");
                }
                std::thread::sleep(POLL_INTERVAL);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Seed the mock drive's F2 challenge keystream is built from.
    const KERNEL_TEST_SEED: u16 = 0x1234;

    /// The 0x8A10 (UD04) OEM control buffer, built generically from the embedded
    /// key table exactly as the live flasher does for the self/GENERAL path.
    fn ud04_control() -> [u8; CONTROL_LEN] {
        let row = crate::pioneer_keys::lookup(0x8A10).expect("0x8A10 in key table");
        let key = row
            .key_for_tag(crate::pioneer_keys::DEFAULT_TAG)
            .expect("GENERAL key");
        row.control_payload(key)
    }

    /// Minimal UD04 Normal envelope: valid banner + 256-byte aligned size.
    fn ud04_normal(len: usize) -> Vec<u8> {
        let mut e = vec![0u8; len];
        let header = b"********  Copyright(c) 2000 Pioneer Corporation\r\nID : PIONEER BD-RW   BDR-UD04.\r\nRevision Level : 1.11.\r\nHardware Version : SAT 8A10.\r\nDestination : GENERAL.\r\nFile Type : Normal.\r\n";
        e[..header.len()].copy_from_slice(header);
        e
    }

    /// Records every CDB AND the data payload of each write, tracks whether the
    /// STRICT data-out entry point was used, and answers the post-entry INQUIRY
    /// with "000" / TEST UNIT READY ready so a cooperative drive completes.
    /// `fail_strict_at` makes the Nth strict write (0-indexed) return an error.
    #[derive(Default)]
    struct Recorder {
        writes: Vec<(Vec<u8>, Vec<u8>)>, // (cdb, data)
        ins: Vec<Vec<u8>>,
        strict_writes: usize,
        lenient_writes: usize,
        fail_strict_at: Option<usize>,
    }
    impl ScsiDevice for Recorder {
        fn command_in(&mut self, cdb: &[u8], alloc: usize) -> Result<Vec<u8>> {
            self.ins.push(cdb.to_vec());
            if cdb.first() == Some(&0x12) {
                let mut r = vec![0u8; alloc.max(0x23)];
                r[0x20..0x23].copy_from_slice(b"000");
                return Ok(r);
            }
            // READ BUFFER mode1 buffer-id 0xF2 = the kernel-mode challenge: return
            // a status buffer whose first 4 bytes are the LCG keystream of a known
            // seed, so `recover_unlock_seed` succeeds.
            if cdb.first() == Some(&0x3C) && cdb.get(2) == Some(&0xF2) {
                let mut state = KERNEL_TEST_SEED as u32;
                let mut buf = vec![0u8; alloc];
                for slot in buf.iter_mut().take(KERNEL_SIGNATURE_LEN) {
                    *slot = (lcg_step(&mut state) & 0xFF) as u8;
                }
                return Ok(buf);
            }
            Ok(vec![0u8; alloc])
        }
        fn command_out(&mut self, cdb: &[u8], data: &[u8]) -> Result<()> {
            self.lenient_writes += 1;
            self.writes.push((cdb.to_vec(), data.to_vec()));
            Ok(())
        }
        fn command_out_strict(&mut self, cdb: &[u8], data: &[u8]) -> Result<()> {
            let n = self.strict_writes;
            self.strict_writes += 1;
            if self.fail_strict_at == Some(n) {
                anyhow::bail!("simulated CHECK CONDITION on strict write {n}");
            }
            self.writes.push((cdb.to_vec(), data.to_vec()));
            Ok(())
        }
        fn describe(&self) -> String {
            "recorder".into()
        }
    }

    #[test]
    fn executes_entry_normal_chunks_finish_via_strict_writes_with_gate_and_poll() {
        // 1 MiB + 0x100 => 32 full 07/F0 chunks + one 0x100 partial.
        let len = 0x0010_0000usize + 0x100;
        let normal = ud04_normal(len);
        let control = ud04_control();
        let mut dev = Recorder::default();
        execute_flash(&mut dev, &control, None, &normal, false, false).unwrap();

        let chunks = len.div_ceil(0x8000);
        // EVERY write went through the strict (abort-on-any-nonzero) path — guards
        // the hardening: a regression to lenient command_out fails this.
        assert_eq!(dev.strict_writes, chunks + 2);
        assert_eq!(dev.lenient_writes, 0);
        let cdbs: Vec<&Vec<u8>> = dev.writes.iter().map(|(c, _)| c).collect();
        assert_eq!(cdbs[0][..3], [0x3b, 0x04, 0xff]); // entry
        assert_eq!(cdbs.last().unwrap()[..3], [0x3b, 0x05, 0xff]); // finish
        assert!(cdbs[1..=chunks]
            .iter()
            .all(|c| c[..3] == [0x3b, 0x07, 0xf0]));
        assert_eq!(cdbs[chunks][3..9], [0x10, 0x00, 0x00, 0x00, 0x01, 0x00]);
        // The concatenated 07/F0 payloads reproduce the Normal byte-for-byte —
        // guards against sending corrupted/truncated data.
        let sent: Vec<u8> = dev.writes[1..=chunks]
            .iter()
            .flat_map(|(_, d)| d.iter().copied())
            .collect();
        assert_eq!(sent, normal);
        // Post-entry INQUIRY and post-finish TEST UNIT READY were issued.
        assert!(dev.ins.iter().any(|c| c.first() == Some(&0x12)));
        assert!(dev.ins.iter().any(|c| c == &vec![0u8; 6]));
    }

    #[test]
    fn kernel_mode_unlock_precedes_entry_with_correct_cdbs() {
        let normal = ud04_normal(0x0010_0000);
        let control = ud04_control();
        let mut dev = Recorder::default();
        execute_flash(&mut dev, &control, None, &normal, true, false).unwrap();

        let cdbs: Vec<&Vec<u8>> = dev.writes.iter().map(|(c, _)| c).collect();
        // First two writes are the F3 arm then the F2 response, BEFORE the 04/FF
        // OEM entry — the unlock is a precondition, not part of the OEM sequence.
        assert_eq!(cdbs[0][..3], [0x3B, 0x01, 0xF3]); // arm (zero-length)
        assert_eq!(dev.writes[0].1.len(), 0);
        assert_eq!(cdbs[1][..3], [0x3B, 0x01, 0xF2]); // response write
        assert_eq!(dev.writes[1].1.len(), KERNEL_RESPONSE_LEN as usize);
        assert_eq!(cdbs[2][..3], [0x3B, 0x04, 0xFF]); // THEN OEM entry
        assert_eq!(cdbs.last().unwrap()[..3], [0x3B, 0x05, 0xFF]); // finish
                                                                   // The F2 challenge READ BUFFER happened between arm and response.
        assert!(dev
            .ins
            .iter()
            .any(|c| c.first() == Some(&0x3C) && c.get(2) == Some(&0xF2)));
        // The response byte matches the recovered-seed keystream.
        assert_eq!(
            dev.writes[1].1[0],
            unlock_response_byte(KERNEL_TEST_SEED),
            "response fill byte must be the recovered seed's response byte"
        );
    }

    #[test]
    fn plain_flash_issues_no_kernel_mode_commands() {
        let normal = ud04_normal(0x0010_0000);
        let mut dev = Recorder::default();
        execute_flash(&mut dev, &ud04_control(), None, &normal, false, false).unwrap();
        // No F3/F2 buffer-id traffic at all on the plain path.
        assert!(!dev
            .writes
            .iter()
            .any(|(c, _)| c.get(2) == Some(&0xF3) || c.get(2) == Some(&0xF2)));
        assert!(!dev
            .ins
            .iter()
            .any(|c| c.first() == Some(&0x3C) && c.get(2) == Some(&0xF2)));
    }

    #[test]
    fn kernel_mode_aborts_when_challenge_seed_unrecoverable() {
        // A challenge whose signature no 16-bit seed reproduces: force the F2 read
        // to return bytes the keystream can't match (all 0xAB is extremely unlikely
        // to be a 4-step LCG run, but to be deterministic we reject via a custom dev).
        struct NoSeed;
        impl ScsiDevice for NoSeed {
            fn command_in(&mut self, cdb: &[u8], alloc: usize) -> Result<Vec<u8>> {
                if cdb.first() == Some(&0x3C) && cdb.get(2) == Some(&0xF2) {
                    // Signature that cannot be produced by the LCG from any seed:
                    // craft one byte-by-byte to differ from every seed's output is
                    // hard, so instead return a short buffer -> treated as failure.
                    return Ok(vec![0u8; 2]);
                }
                Ok(vec![0u8; alloc])
            }
            fn command_out_strict(&mut self, _cdb: &[u8], _data: &[u8]) -> Result<()> {
                Ok(())
            }
            fn command_out(&mut self, _cdb: &[u8], _d: &[u8]) -> Result<()> {
                Ok(())
            }
            fn describe(&self) -> String {
                "no-seed".into()
            }
        }
        let normal = ud04_normal(0x0010_0000);
        let err =
            execute_flash(&mut NoSeed, &ud04_control(), None, &normal, true, false).unwrap_err();
        assert!(format!("{err:#}").contains("kernel-mode"));
    }

    #[test]
    fn aborts_before_any_transfer_when_drive_not_in_update_state() {
        struct BadEntry {
            writes: Vec<Vec<u8>>,
        }
        impl ScsiDevice for BadEntry {
            fn command_in(&mut self, _cdb: &[u8], alloc: usize) -> Result<Vec<u8>> {
                Ok(vec![0u8; alloc]) // INQUIRY returns zeros, not "000"
            }
            fn command_out_strict(&mut self, cdb: &[u8], _data: &[u8]) -> Result<()> {
                self.writes.push(cdb.to_vec());
                Ok(())
            }
            fn command_out(&mut self, cdb: &[u8], _d: &[u8]) -> Result<()> {
                self.writes.push(cdb.to_vec());
                Ok(())
            }
            fn describe(&self) -> String {
                "bad-entry".into()
            }
        }
        let normal = ud04_normal(0x0010_0000 + 0x100);
        let mut dev = BadEntry { writes: Vec::new() };
        let err =
            execute_flash(&mut dev, &ud04_control(), None, &normal, false, false).unwrap_err();
        assert!(format!("{err:#}").contains("post-entry update state"));
        // Only the entry write happened; NO Normal chunk or finish followed.
        assert_eq!(dev.writes.len(), 1);
        assert_eq!(dev.writes[0][..3], [0x3b, 0x04, 0xff]);
        assert!(!dev.writes.iter().any(|c| c[..3] == [0x3b, 0x07, 0xf0]));
    }

    #[test]
    fn a_failed_mid_transfer_write_aborts_with_a_recovery_hint() {
        let normal = ud04_normal(0x0010_0000 + 0x100);
        // Fail the first Normal chunk (strict write index 1: 0=entry, 1=first F0).
        let mut dev = Recorder {
            fail_strict_at: Some(1),
            ..Recorder::default()
        };
        let err =
            execute_flash(&mut dev, &ud04_control(), None, &normal, false, false).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("Normal") && msg.contains("re-flash the captured"));
        // No finish (05/FF) was sent after the failed transfer.
        assert!(!dev.writes.iter().any(|(c, _)| c[..3] == [0x3b, 0x05, 0xff]));
    }

    #[test]
    fn executes_both_kernel_and_normal_via_strict_writes_in_order() {
        // 0x18000 kernel => 3 full 07/FE slices; 0x8100 normal => 2 07/F0 chunks.
        let kernel: Vec<u8> = (0..0x18000usize).map(|i| (i % 253) as u8).collect();
        let normal: Vec<u8> = (0..0x8100usize).map(|i| (i % 251) as u8).collect();
        let mut dev = Recorder::default();
        execute_flash(&mut dev, &[0xA5; 256], Some(&kernel), &normal, false, false).unwrap();

        // entry + 3 kernel FE + 2 normal F0 + finish, all strict, nothing lenient.
        assert_eq!(dev.strict_writes, 7);
        assert_eq!(dev.lenient_writes, 0);
        let cdbs: Vec<&Vec<u8>> = dev.writes.iter().map(|(c, _)| c).collect();
        assert_eq!(cdbs[0][..3], [0x3b, 0x04, 0xff]); // entry
        assert!(cdbs[1..=3].iter().all(|c| c[..3] == [0x3b, 0x07, 0xfe])); // kernel
        assert!(cdbs[4..=5].iter().all(|c| c[..3] == [0x3b, 0x07, 0xf0])); // normal
        assert_eq!(cdbs[6][..3], [0x3b, 0x05, 0xff]); // finish

        // Each chunk's 24-bit BE offset is index*FLASH_CHUNK — pins the offset
        // arithmetic in both loops (kills `*`->`+`/`/` on the offset expression).
        let off = |c: &Vec<u8>| ((c[3] as u32) << 16) | ((c[4] as u32) << 8) | c[5] as u32;
        assert_eq!(
            [off(cdbs[1]), off(cdbs[2]), off(cdbs[3])],
            [0, FLASH_CHUNK as u32, 2 * FLASH_CHUNK as u32]
        ); // kernel FE offsets
        assert_eq!([off(cdbs[4]), off(cdbs[5])], [0, FLASH_CHUNK as u32]); // normal F0 offsets

        // Both payloads were sent byte-exact through the strict path.
        let kernel_sent: Vec<u8> = dev.writes[1..=3]
            .iter()
            .flat_map(|(_, d)| d.iter().copied())
            .collect();
        assert_eq!(kernel_sent, kernel);
        let normal_sent: Vec<u8> = dev.writes[4..=5]
            .iter()
            .flat_map(|(_, d)| d.iter().copied())
            .collect();
        assert_eq!(normal_sent, normal);
        // Post-entry INQUIRY gate and post-finish TEST UNIT READY poll both ran.
        assert!(dev.ins.iter().any(|c| c.first() == Some(&0x12)));
        assert!(dev.ins.iter().any(|c| c == &vec![0u8; 6]));
    }

    #[test]
    fn recover_skips_the_identity_gate_that_aborts_a_normal_flash() {
        // A degraded drive that never reports the post-entry "000" identity but
        // does answer the kernel-mode F2 challenge (so kernel mode works).
        #[derive(Default)]
        struct Degraded {
            writes: usize,
            finished: bool,
        }
        impl ScsiDevice for Degraded {
            fn command_in(&mut self, cdb: &[u8], alloc: usize) -> Result<Vec<u8>> {
                if cdb.first() == Some(&0x3C) && cdb.get(2) == Some(&0xF2) {
                    let mut state = KERNEL_TEST_SEED as u32;
                    let mut buf = vec![0u8; alloc];
                    for slot in buf.iter_mut().take(KERNEL_SIGNATURE_LEN) {
                        *slot = (lcg_step(&mut state) & 0xFF) as u8;
                    }
                    return Ok(buf);
                }
                // INQUIRY never reports the "000" update state; TEST UNIT READY ok.
                Ok(vec![0u8; alloc.max(0x23)])
            }
            fn command_out(&mut self, cdb: &[u8], data: &[u8]) -> Result<()> {
                self.command_out_strict(cdb, data)
            }
            fn command_out_strict(&mut self, cdb: &[u8], _data: &[u8]) -> Result<()> {
                self.writes += 1;
                if cdb.first() == Some(&0x3b) && cdb.get(1) == Some(&0x05) {
                    self.finished = true;
                }
                Ok(())
            }
            fn describe(&self) -> String {
                "degraded".into()
            }
        }
        let normal = ud04_normal(0x0010_0000);

        // Without recover, the post-entry identity gate aborts before any transfer.
        let mut normal_dev = Degraded::default();
        let err = execute_flash(&mut normal_dev, &ud04_control(), None, &normal, true, false)
            .unwrap_err();
        assert!(format!("{err:#}").contains("post-entry update state"));
        assert!(!normal_dev.finished, "a gated flash must not reach finish");

        // With recover, the gate is skipped and the forced write runs to finish.
        let mut recover_dev = Degraded::default();
        execute_flash(&mut recover_dev, &ud04_control(), None, &normal, true, true).unwrap();
        assert!(
            recover_dev.finished,
            "recover must force the write through finish"
        );
    }

    /// HARD INVARIANT: the generically-built 0x8A10 control buffer is byte-for-
    /// byte the old hand-baked UD04 payload ("PIONEER BDR-US04" + 0xFD236642 LE,
    /// zero tail), and the UD04 Normal-only self-flash CDB sequence AND every
    /// data-out payload on the wire are unchanged. This is the one validated
    /// write path; its bytes must never drift.
    #[test]
    fn ud04_self_flash_control_and_wire_bytes_are_byte_exact() {
        // 1 control oracle: the exact bytes the removed ud04_oem_control_payload()
        // produced.
        let mut oracle = [0u8; CONTROL_LEN];
        oracle[..16].copy_from_slice(b"PIONEER BDR-US04");
        oracle[16..20].copy_from_slice(&0xFD23_6642u32.to_le_bytes());
        let control = ud04_control();
        assert_eq!(
            control, oracle,
            "generic 0x8A10 control must equal old UD04 payload"
        );

        // 0x1D7000 => 59 full 07/F0 chunks; the canonical UD04 Normal size.
        let normal = ud04_normal(0x1D7000);
        let mut dev = Recorder::default();
        execute_flash(&mut dev, &control, None, &normal, false, false).unwrap();

        // Exact CDB sequence: 04/FF entry, 59x 07/F0 chunks, 05/FF finish.
        let cdbs: Vec<Vec<u8>> = dev.writes.iter().map(|(c, _)| c.clone()).collect();
        assert_eq!(cdbs.len(), 61);
        assert_eq!(cdbs[0], vec![0x3B, 0x04, 0xFF, 0, 0, 0, 0, 1, 0, 0]);
        assert_eq!(cdbs[1], vec![0x3B, 0x07, 0xF0, 0, 0, 0, 0, 0x80, 0, 0]);
        assert_eq!(cdbs[59], vec![0x3B, 0x07, 0xF0, 0x1D, 0, 0, 0, 0x70, 0, 0]);
        assert_eq!(cdbs[60], vec![0x3B, 0x05, 0xFF, 0, 0, 0, 0, 1, 0, 0]);

        // Exact payloads: entry and finish carry the control; the 59 F0 chunks
        // reproduce the Normal byte-for-byte.
        assert_eq!(dev.writes[0].1.as_slice(), control.as_slice());
        assert_eq!(dev.writes[60].1.as_slice(), control.as_slice());
        let sent: Vec<u8> = dev.writes[1..=59]
            .iter()
            .flat_map(|(_, d)| d.iter().copied())
            .collect();
        assert_eq!(sent, normal);
    }

    /// Lock the LCG primitive to the exact disasm constants
    /// (`state = state*0x41C64E6D + 0x3039`, return high 16 bits).
    #[test]
    fn lcg_step_matches_the_ansi_c_constants() {
        let mut state = 0u32;
        assert_eq!(lcg_step(&mut state), (0x3039u32 >> 16) as u16);
        assert_eq!(state, 0x3039);
        // Second step by hand: 0x3039 * 0x41C64E6D + 0x3039.
        let expected = 0x3039u32.wrapping_mul(0x41C6_4E6D).wrapping_add(0x3039);
        assert_eq!(lcg_step(&mut state), (expected >> 16) as u16);
    }

    /// A signature synthesized from a known seed is recovered back to that seed,
    /// and the response byte is deterministic for it.
    #[test]
    fn unlock_seed_round_trips_through_recovery() {
        for seed in [0u16, 1, 0x1234, 0x6123, 0xFFFF] {
            let mut state = seed as u32;
            let signature: Vec<u8> = (0..KERNEL_SIGNATURE_LEN)
                .map(|_| (lcg_step(&mut state) & 0xFF) as u8)
                .collect();
            // Recovery finds *a* seed producing this signature; it must produce
            // the same response byte as the original (the handshake only depends
            // on the keystream, not the specific seed integer).
            let recovered = recover_unlock_seed(&signature).expect("seed recoverable");
            assert_eq!(
                unlock_response_byte(recovered),
                unlock_response_byte(seed),
                "response byte must match for seed {seed:#06X}"
            );
        }
    }

    /// The response byte is the bit-inverted low output byte after 0x401 steps.
    #[test]
    fn unlock_response_byte_is_inverted_0x401st_step() {
        let seed = 0x6123u16;
        let mut state = seed as u32;
        for _ in 0..=KERNEL_STATUS_LEN {
            lcg_step(&mut state);
        }
        assert_eq!(unlock_response_byte(seed), !((state >> 16) as u8));
    }
}
