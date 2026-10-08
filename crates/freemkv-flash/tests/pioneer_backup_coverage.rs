//! Opt-in offline census of the public backup path. Never opens a device.
use anyhow::{bail, Context, Result};
use freemkv_flash::{
    drive, engine, pioneer_backup,
    pioneer_bundle::{Bundle, Role},
    platform::{ScsiDevice, ScsiSenseError},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

const KERNEL_BASE: usize = 0x400000;
const NORMAL_BASE: usize = 0x410000;
const READ_CHUNK: usize = 0x8000;

struct Replay {
    inquiry: Vec<u8>,
    hardware: Vec<u8>,
    kernel: Vec<u8>,
    normal: Vec<u8>,
    locked: bool,
    knocks: usize,
    kernel_bytes: usize,
    normal_bytes: usize,
}
impl ScsiDevice for Replay {
    fn command_in(&mut self, c: &[u8], len: usize) -> Result<Vec<u8>> {
        if c.first() == Some(&0x12) {
            let mut b = self.inquiry.clone();
            b.resize(len, 0);
            return Ok(b);
        }
        if c.first() == Some(&0x46) {
            return Err(ScsiSenseError::new(5, 0x20, 0, "not MTK").into());
        }
        if c == [0x3c, 2, 0xf1, 0, 0, 0, 0, 0, 48, 0] {
            let mut b = vec![b' '; 48];
            b[16..24].copy_from_slice(&self.hardware);
            return Ok(b);
        }
        if c.len() != 10 || c[..3] != [0x3c, 2, 0xb0] {
            bail!("unexpected command {c:02x?}");
        }
        if self.locked {
            return Err(ScsiSenseError::new(5, 0x24, 0, "receiver read gate").into());
        }
        let off = ((c[3] as usize) << 16) | ((c[4] as usize) << 8) | c[5] as usize;
        let declared = ((c[6] as usize) << 16) | ((c[7] as usize) << 8) | c[8] as usize;
        if declared != len || len > READ_CHUNK || c[9] != 0 {
            bail!("invalid read framing");
        }
        let end = off.checked_add(len).context("read address overflow")?;
        if end > NORMAL_BASE + self.normal.len() {
            return Err(ScsiSenseError::new(5, 0x24, 0, "read ceiling").into());
        }
        // Map probing reads RAM and the complete firmware span, including
        // chunks crossing component boundaries. Unused simulated RAM is zero.
        let mut bytes = vec![0; len];
        for (base, image, count) in [
            (KERNEL_BASE, self.kernel.as_slice(), &mut self.kernel_bytes),
            (NORMAL_BASE, self.normal.as_slice(), &mut self.normal_bytes),
        ] {
            let start = off.max(base);
            let stop = end.min(base + image.len());
            if start < stop {
                bytes[start - off..stop - off].copy_from_slice(&image[start - base..stop - base]);
                *count += stop - start;
            }
        }
        Ok(bytes)
    }
    fn command_out(&mut self, c: &[u8], data: &[u8]) -> Result<()> {
        if c != [0x3b, 2, 0x41, 0xa5, 0xaa, 0xaa, 0, 0, 0, 0]
            || !data.is_empty()
            || self.knocks != 0
        {
            bail!("unexpected write {c:02x?}");
        }
        self.knocks += 1;
        self.locked = false;
        Ok(())
    }
    fn describe(&self) -> String {
        "offline corpus replay".into()
    }
}
fn files(root: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for e in fs::read_dir(root)? {
        let p = e?.path();
        if p.is_dir() {
            files(&p, out)?;
        } else if p.to_string_lossy().ends_with(".installer.tar") {
            out.push(p)
        }
    }
    Ok(())
}
fn run_pair(bundle: &Bundle, evidence: &BTreeMap<String, Value>, output: &Path) -> Result<Value> {
    let k = bundle
        .components
        .iter()
        .find(|c| c.role == Role::Kernel)
        .context("missing Kernel fixture")?;
    let n = bundle
        .components
        .iter()
        .find(|c| c.role == Role::Main)
        .context("missing Normal fixture")?;
    let kh = pioneer_optical::envelope::header_info(&k.bytes).context("Kernel header")?;
    let nh = pioneer_optical::envelope::header_info(&n.bytes).context("Normal header")?;
    let kd =
        pioneer_optical::envelope::decode_envelope(&k.bytes).context("Kernel codec unresolved")?;
    let nd = pioneer_optical::envelope::decode_envelope_with_kernel(&n.bytes, &kd)
        .context("Normal receiver codec unresolved")?;
    if !kh.hardware_version.starts_with("SAT ") {
        bail!("non-SAT read map unresolved");
    }
    let hash = format!("{:x}", Sha256::digest(&n.bytes));
    let e = evidence
        .get(&hash)
        .context("read/entry receiver evidence missing")?;
    let locked = e["evidence"]["shared_state_candidate"]
        .as_bool()
        .unwrap_or(false);
    if !locked && kh.hardware_version != "SAT 1003" {
        bail!("read permission evidence unresolved");
    }
    let tokens: Vec<_> = nh.id.split_whitespace().collect();
    if tokens.len() < 3 {
        bail!("INQUIRY identity missing");
    }
    let product = tokens[1..].join(" ");
    if tokens[0].len() > 8
        || product.len() > 16
        || nh.revision.len() > 4
        || kh.hardware_version.len() != 8
    {
        bail!("INQUIRY fields unrepresentable");
    }
    let mut inquiry = vec![b' '; 96];
    inquiry[0] = 5;
    inquiry[8..8 + tokens[0].len()].copy_from_slice(tokens[0].as_bytes());
    inquiry[16..16 + product.len()].copy_from_slice(product.as_bytes());
    inquiry[32..32 + nh.revision.len()].copy_from_slice(nh.revision.as_bytes());
    let mut r = Replay {
        inquiry,
        hardware: kh.hardware_version.into_bytes(),
        kernel: kd.image.clone(),
        normal: nd.image.clone(),
        locked,
        knocks: 0,
        kernel_bytes: 0,
        normal_bytes: 0,
    };
    let found = drive::resolve_backend(&mut r)?.context("backend not recognized")?;
    if found.evidence.family != drive::Family::Pioneer {
        bail!("wrong backend");
    }
    let backend = drive::pioneer::Pioneer::new();
    let result = engine::backup(&mut r, &backend, output, false, false);
    if let Err(e) = result {
        assert!(!output.exists(), "failed backup left output");
        return Err(e);
    }
    let bytes = fs::read(output)?;
    fs::remove_file(output)?;
    pioneer_backup::validate_envelope_package(&bytes, &product)?;
    let rebuilt = Bundle::from_tar_bytes(&bytes)?;
    let rk = rebuilt
        .components
        .iter()
        .find(|c| c.role == Role::Kernel)
        .context("output Kernel missing")?;
    let rn = rebuilt
        .components
        .iter()
        .find(|c| c.role == Role::Main)
        .context("output Normal missing")?;
    let rk =
        pioneer_optical::envelope::decode_envelope(&rk.bytes).context("output Kernel decode")?;
    let rn = pioneer_optical::envelope::decode_envelope_with_kernel(&rn.bytes, &rk)
        .context("output Normal decode")?;
    if rk.image != kd.image || rn.image != nd.image {
        bail!("captured images differ");
    }
    if r.kernel_bytes < 2 * kd.image.len() || r.normal_bytes < 2 * nd.image.len() {
        bail!("double read missing");
    }
    if r.knocks != 1 {
        bail!("wrong service-entry count");
    }
    Ok(json!({"status":"supported_offline","knocks":r.knocks,"hardware":nh.hardware_version}))
}
#[test]
fn model_backup_coverage_when_configured() -> Result<()> {
    let Ok(root) = std::env::var("PIONEER_BACKUP_CENSUS_ROOT") else {
        return Ok(());
    };
    let report = PathBuf::from(std::env::var("PIONEER_BACKUP_CENSUS_REPORT")?);
    let source: Vec<Value> =
        serde_json::from_slice(&fs::read(std::env::var("PIONEER_BACKUP_READ_EVIDENCE")?)?)?;
    let evidence = source
        .into_iter()
        .map(|v| (v["envelope_sha256"].as_str().unwrap().to_owned(), v))
        .collect();
    let root = PathBuf::from(root);
    let mut paths = vec![];
    files(&root, &mut paths)?;
    paths.sort();
    let temp =
        std::env::temp_dir().join(format!("pioneer-backup-census-{}.tar", std::process::id()));
    assert!(!temp.exists());
    let mut cache = BTreeMap::<String, Value>::new();
    let mut rows = vec![];
    for path in paths {
        let relative = path.strip_prefix(&root)?;
        let model = relative
            .components()
            .next()
            .unwrap()
            .as_os_str()
            .to_string_lossy()
            .into_owned();
        let raw = fs::read(&path)?;
        // Cache only byte-identical packages, preserving every model row.
        // Avoid repeating expensive envelope parsing for OEM alias copies.
        let key = format!("{:x}", Sha256::digest(&raw));
        let value = if let Some(v) = cache.get(&key) {
            v.clone()
        } else {
            let result = match Bundle::from_tar_bytes(&raw) {
                Ok(b) => run_pair(&b, &evidence, &temp),
                Err(e) => Err(e),
            };
            let v = result.unwrap_or_else(|e| json!({"status":"tbd","reason":format!("{e:#}")}));
            cache.insert(key, v.clone());
            eprintln!("coverage pair {}: {}", cache.len(), v);
            v
        };
        rows.push(json!({"model":model,"path":relative,"result":value}));
    }
    let mut models = BTreeMap::<String, Vec<Value>>::new();
    for r in &rows {
        models
            .entry(r["model"].as_str().unwrap().into())
            .or_default()
            .push(r.clone());
    }
    let models: Vec<Value> = models
        .into_iter()
        .map(|(model, packages)| {
            let passed = packages
                .iter()
                .filter(|p| p["result"]["status"] == "supported_offline")
                .count();
            let status = if passed == packages.len() {
                "supported_offline"
            } else if passed > 0 {
                "partial"
            } else {
                "tbd"
            };
            json!({"model":model,"status":status,"passing_packages":passed,"packages":packages})
        })
        .collect();
    let count = |status: &str| models.iter().filter(|m| m["status"] == status).count();
    assert!(
        count("supported_offline") > 0,
        "no complete model passed the public backup path"
    );
    let summary = json!({"models":models.len(),"supported_offline":count("supported_offline"),"partial":count("partial"),"tbd":count("tbd"),"unique_input_packages":cache.len(),"physical_restore_tested":false});
    eprintln!("MODEL COVERAGE {summary}");
    fs::write(
        report,
        serde_json::to_vec_pretty(&json!({"summary":summary,"models":models}))?,
    )?;
    assert!(!rows.is_empty());
    Ok(())
}

#[test]
fn replay_serves_map_probe_and_boundary_reads_with_real_ceiling_sense() -> Result<()> {
    let mut replay = Replay {
        inquiry: vec![],
        hardware: vec![],
        kernel: vec![0xa5; NORMAL_BASE - KERNEL_BASE],
        normal: vec![0x5a; READ_CHUNK],
        locked: true,
        knocks: 0,
        kernel_bytes: 0,
        normal_bytes: 0,
    };
    let read = |offset: usize, length: usize| {
        pioneer_optical::cdb::read_memory(offset as u32, length as u32)
    };
    let error = replay.command_in(&read(KERNEL_BASE, 4), 4).unwrap_err();
    assert_eq!(
        freemkv_flash::platform::sense_triplet(&error),
        Some((5, 0x24, 0))
    );
    replay.command_out(&pioneer_optical::cdb::knock(), &[])?;
    assert_eq!(
        replay.command_in(&read(0, READ_CHUNK), READ_CHUNK)?,
        vec![0; READ_CHUNK]
    );
    assert_eq!(
        replay.command_in(&read(KERNEL_BASE, READ_CHUNK), READ_CHUNK)?,
        vec![0xa5; READ_CHUNK]
    );
    assert_eq!(
        replay.command_in(&read(NORMAL_BASE - 2, 4), 4)?,
        [0xa5, 0xa5, 0x5a, 0x5a]
    );
    let ceiling = NORMAL_BASE + READ_CHUNK;
    assert_eq!(replay.command_in(&read(ceiling - 1, 1), 1)?, [0x5a]);
    let error = replay.command_in(&read(ceiling, 1), 1).unwrap_err();
    assert_eq!(
        freemkv_flash::platform::sense_triplet(&error),
        Some((5, 0x24, 0))
    );
    assert_eq!(replay.kernel_bytes, READ_CHUNK + 2);
    assert_eq!(replay.normal_bytes, 3);
    assert_eq!(replay.knocks, 1);
    Ok(())
}
