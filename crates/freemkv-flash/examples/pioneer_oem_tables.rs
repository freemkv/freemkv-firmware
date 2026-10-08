//! Refresh backup reconstruction metadata from a current directory of OEM .enc files.
//! Usage: cargo run -p freemkv-flash --example pioneer_oem_tables -- <images> <existing-tables> <output>
//! No device I/O. Existing historical rows are preserved; every new candidate
//! must reconstruct its source envelope byte-for-byte before being admitted.
use anyhow::{bail, Context, Result};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use pioneer_optical::{
    envelope::{self, builder::*, DecodedEnvelope, HeaderInfo, Layout},
    ComponentKind,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::Write,
    path::{Path, PathBuf},
};

type Table = BTreeMap<String, Value>;
struct Kernel {
    decoded: DecodedEnvelope,
    header: HeaderInfo,
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn files(root: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            files(&entry.path(), out)?;
        } else if ty.is_file() && entry.path().extension().is_some_and(|x| x == "enc") {
            out.push(entry.path());
        }
    }
    Ok(())
}
fn read_table(dir: &Path, name: &str) -> Result<Table> {
    Ok(serde_json::from_reader(GzDecoder::new(
        std::fs::File::open(dir.join(name))?,
    ))?)
}
fn write_table(dir: &Path, name: &str, table: &Table) -> Result<()> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(&serde_json::to_vec(table)?)?;
    std::fs::write(dir.join(name), encoder.finish()?)?;
    Ok(())
}
fn date_key(date: &str) -> (u32, u32, u32) {
    let parts: Vec<_> = date.split('/').collect();
    if parts.len() == 3 {
        return (
            2000 + parts[0].parse::<u32>().unwrap_or(9999),
            parts[1].parse().unwrap_or(99),
            parts[2].parse().unwrap_or(99),
        );
    }
    if let Some((md, year)) = date.split_once(',') {
        if let (Some(month), Some(day)) = (md.get(..3), md.get(3..)) {
            let months = [
                "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
            ];
            return (
                year.parse().unwrap_or(9999),
                months
                    .iter()
                    .position(|m| *m == month)
                    .map_or(99, |i| i as u32 + 1),
                day.trim().parse().unwrap_or(99),
            );
        }
    }
    (9999, 99, 99)
}
fn admit(table: &mut Table, image_hash: String, row: Value) {
    // Stable canonical choice for bodies distributed under multiple OEM headers.
    let rank = |v: &Value| {
        (
            date_key(v["date"].as_str().unwrap()),
            v["version"].as_str().unwrap().to_owned(),
            v.to_string(),
        )
    };
    if table
        .get(&image_hash)
        .is_none_or(|old| rank(&row) < rank(old))
    {
        table.insert(image_hash, row);
    }
}
fn sum_zero(image: &[u8]) -> bool {
    let (words, tail) = image.as_chunks::<4>();
    tail.is_empty()
        && words
            .iter()
            .fold(0u32, |s, w| s.wrapping_add(u32::from_be_bytes(*w)))
            == 0
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 3 {
        bail!("usage: pioneer_oem_tables <OEM-images-directory> <existing-tables-directory> <output-directory>");
    }
    let root = Path::new(&args[0]);
    let existing = Path::new(&args[1]);
    let output = Path::new(&args[2]);
    let mut paths = Vec::new();
    files(root, &mut paths)?;
    paths.sort();
    if paths.is_empty() {
        bail!("no .enc files found; refusing an empty refresh");
    }
    let mut kernels: Vec<Kernel> = Vec::new();
    let mut kt = Table::new();
    let mut nt = Table::new();
    let mut report = Vec::new();
    for path in &paths {
        let bytes = std::fs::read(path)?;
        let Some(header) = envelope::header_info(&bytes) else {
            report.push(json!({"path":path,"status":"invalid_header"}));
            continue;
        };
        if header.kind != Some(ComponentKind::Kernel) {
            continue;
        }
        let Some(decoded) = envelope::decode_envelope(&bytes) else {
            report.push(json!({"path":path,"status":"kernel_decode_unsupported"}));
            continue;
        };
        if !matches!(
            decoded.info().layout,
            Layout::KernelFront | Layout::KernelDerived
        ) || !sum_zero(&decoded.image)
        {
            report.push(json!({"path":path,"status":"outside_H8_backup_builder"}));
            continue;
        }
        let mut row = json!({"version":header.revision,"date":header.generated_date});
        let key = if let Some(seed) = decoded.encoding_seed() {
            row["seed"] = json!(format!("0x{seed:06X}"));
            KernelKeySource::Seed(seed)
        } else if decoded.info().layout == Layout::KernelFront {
            let key = decoded.encoding_key();
            row["key_hex"] = json!(hex(key));
            KernelKeySource::RawKey(key)
        } else {
            report.push(json!({"path":path,"status":"unrecoverable_kernel_key"}));
            continue;
        };
        let rebuilt = encode_kernel_envelope(
            &decoded.image,
            &header.id,
            &KernelBuild {
                revision: &header.revision,
                date: &header.generated_date,
                key,
            },
        );
        let image_hash = hash(&decoded.image);
        // Captures can be indexed alongside OEM sources. Never promote our
        // explicit unknown-capture placeholder into OEM reconstruction metadata.
        let placeholder = decoded.reconstruction_placeholder().is_some();
        let exact = !placeholder && rebuilt.as_ref().is_ok_and(|b| *b == bytes);
        report.push(json!({"path":path,"image_sha256":image_hash,"envelope_sha256":hash(&bytes),"status":if placeholder {"kernel_placeholder"} else if exact {"kernel_byte_exact"} else {"kernel_not_byte_exact"}}));
        if exact {
            admit(&mut kt, image_hash, row);
        }
        kernels.push(Kernel { decoded, header });
    }
    for path in &paths {
        let bytes = std::fs::read(path)?;
        let Some(header) = envelope::header_info(&bytes) else {
            continue;
        };
        if header.kind != Some(ComponentKind::Normal) {
            continue;
        }
        let mut status = "no_matching_H8_kernel";
        let mut matched_hash = None;
        for kernel in kernels.iter().filter(|k| {
            k.header.hardware_version == header.hardware_version
                && k.header.kernel_version == header.kernel_version
                && k.header.kernel_version2 == header.kernel_version2
                && k.header.destination == header.destination
        }) {
            status = "normal_decode_unsupported";
            let Some(normal) = envelope::decode_envelope_with_kernel(&bytes, &kernel.decoded)
            else {
                continue;
            };
            if !sum_zero(&normal.image) {
                status = "invalid_normal_checksum";
                continue;
            }
            matched_hash = Some(hash(&normal.image));
            let Some(seed) = normal.encoding_seed() else {
                status = "unrecoverable_normal_seed";
                continue;
            };
            let signature = bytes
                .get(NORMAL_SIGNATURE_RANGE)
                .context("short signature")?;
            if normal.reconstruction_placeholder().is_some() {
                status = "normal_placeholder";
                continue;
            }
            if !normal_authentication_valid(&bytes, &kernel.decoded.image) {
                status = "normal_authentication_failed";
                continue;
            }
            let input = BuildInputs {
                kernel_image: &kernel.decoded.image,
                normal_image: &normal.image,
                envelope_id: &header.id,
                normal_revision: &header.revision,
                normal_date: &header.generated_date,
                kernel: KernelBuild::from_seed(0),
                normal_key_seed: seed,
            };
            let Ok(pair) = encode_encrypted_pair(&input, NormalSignature::Oem(signature)) else {
                status = "normal_build_unsupported";
                continue;
            };
            if pair.normal != bytes {
                status = "normal_not_byte_exact";
                continue;
            }
            admit(
                &mut nt,
                matched_hash.clone().unwrap(),
                json!({"version":header.revision,"date":header.generated_date,"seed":format!("0x{seed:06X}"),"sig_hex":hex(signature)}),
            );
            status = "normal_byte_exact";
            break;
        }
        report.push(json!({"path":path,"image_sha256":matched_hash,"envelope_sha256":hash(&bytes),"status":status}));
    }
    let old_k = read_table(existing, "pioneer_k.bin")?;
    let old_n = read_table(existing, "pioneer_n.bin")?;
    // Do not delete historical OEM metadata just because its source is absent
    // from today's corpus. Preserve existing canonical choices for shared bodies.
    let verified_k = kt.len();
    let verified_n = nt.len();
    let historical_k = old_k.keys().filter(|h| !kt.contains_key(*h)).count();
    let historical_n = old_n.keys().filter(|h| !nt.contains_key(*h)).count();
    for (hash, row) in old_k {
        kt.insert(hash, row);
    }
    for (hash, row) in old_n {
        nt.insert(hash, row);
    }
    let mut counts = BTreeMap::<String, usize>::new();
    for r in &report {
        *counts
            .entry(r["status"].as_str().unwrap().to_owned())
            .or_default() += 1;
    }
    let summary = json!({"envelopes":paths.len(),"verified_kernel_images":verified_k,"verified_normal_images":verified_n,"retained_historical_kernel_rows":historical_k,"retained_historical_normal_rows":historical_n,"kernel_rows":kt.len(),"normal_rows":nt.len(),"statuses":counts});
    std::fs::create_dir_all(output)?;
    write_table(output, "pioneer_k.bin", &kt)?;
    write_table(output, "pioneer_n.bin", &nt)?;
    std::fs::write(
        output.join("report.json"),
        serde_json::to_vec_pretty(&json!({"summary":summary,"files":report}))?,
    )?;
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}
