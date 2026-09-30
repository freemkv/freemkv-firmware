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
        if declared != len || len > 164 || c[9] != 0 {
            bail!("invalid read framing");
        }
        if (0x400000..0x410000).contains(&off) {
            self.kernel_bytes += len;
            return self
                .kernel
                .get(off - 0x400000..off - 0x400000 + len)
                .map(|b| b.to_vec())
                .context("Kernel read outside fixture");
        }
        if off >= 0x410000 {
            self.normal_bytes += len;
            return self
                .normal
                .get(off - 0x410000..off - 0x410000 + len)
                .map(|b| b.to_vec())
                .context("Normal read outside fixture");
        }
        bail!("read outside proven replay map")
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
    let kh = pioneer_codec::header_info(&k.bytes).context("Kernel header")?;
    let nh = pioneer_codec::header_info(&n.bytes).context("Normal header")?;
    let kd = pioneer_codec::decode_envelope(&k.bytes).context("Kernel codec unresolved")?;
    let nd = pioneer_codec::decode_envelope_with_kernel(&n.bytes, &kd)
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
    let result = engine::backup(&mut r, &backend, output);
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
    let rk = pioneer_codec::decode_envelope(&rk.bytes).context("output Kernel decode")?;
    let rn = pioneer_codec::decode_envelope_with_kernel(&rn.bytes, &rk)
        .context("output Normal decode")?;
    if rk.image != kd.image || rn.image != nd.image {
        bail!("captured images differ");
    }
    if r.kernel_bytes < 2 * kd.image.len() || r.normal_bytes < 2 * nd.image.len() {
        bail!("double read missing");
    }
    if r.knocks != usize::from(locked) {
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
