//! Read-only capture for the exact BH16NS48 detection experiment.
//! No flag changes, media resets, firmware writes or sector reads are issued.
use anyhow::{bail, Context, Result};
use clap::Parser;
use freemkv_flash::platform::{self, ScsiDevice};
use freemkv_fw::abi;
use serde_json::{json, Value};
use std::path::PathBuf;

const SOURCE: &str = "8a7ffc47910f7fef6abdac612f94f7d76d8f81149c704ae54e490a9aec1ff800";
const HOOK: &[u8] = &[0xa0, 0xf0, 0xa3, 0xf9, 0xc0, 0x46, 0xc0, 0x46];
const STUB: &[u8] = &[
    0x6b, 0x46, 0x2f, 0xb5, 0x01, 0xd6, 0x00, 0x25, 0x00, 0xe0, 0x01, 0x25, 0x1f, 0x48, 0x00, 0x78,
    0x01, 0x28, 0x2b, 0xd1, 0x1e, 0x48, 0x84, 0x42, 0x28, 0xd1, 0x18, 0x7b, 0x42, 0x28, 0x25, 0xd1,
];
const BINDINGS: &[u8] = &[
    0x13, 0x12, 0x00, 0x02, 0xd3, 0x9d, 0xff, 0x01, 0x35, 0xa9, 0x10, 0x00, 0x00, 0x00, 0x00, 0x40,
    0x7f, 0xa8, 0x10, 0x00,
];
const BU40N_SOURCE: &str = "011ecbea0f9d8bb20ec7aa68d07fbe6fabfd1d3279ff720d9affdb5d4f137410";
const BU40N_HOOK: &[u8] = &[0xa1, 0xf0, 0xc5, 0xfd, 0xc0, 0x46, 0xc0, 0x46];
const BU40N_STUB: &[u8] = &[
    0x6b, 0x46, 0x2f, 0xb5, 0x01, 0xd6, 0x00, 0x25, 0x00, 0xe0, 0x01, 0x25, 0x29, 0x48, 0x00, 0x78,
    0x01, 0x28, 0x3f, 0xd1, 0x28, 0x48, 0x84, 0x42, 0x3c, 0xd1, 0x18, 0x7b, 0x42, 0x28, 0x39, 0xd1,
];

#[derive(Parser)]
struct Args {
    /// Optional device path. Otherwise select the sole BH16NS48 automatically.
    #[arg(long)]
    device: Option<String>,
    /// Destination JSON. Default: a timestamped file beside the executable.
    #[arg(long)]
    out: Option<PathBuf>,
}

fn read(dev: &mut dyn ScsiDevice, name: &str, cdb: &[u8], length: usize) -> Value {
    match dev.diagnostic_in(cdb, length, 1500) {
        Ok(data) => json!({"name":name,"cdb":cdb,"requested":length,
            "ok":true,"received":data.len(),"data":data}),
        Err(error) => json!({"name":name,"cdb":cdb,"requested":length,
            "ok":false,"error":format!("{error:#}"),"sense":platform::sense_triplet(&error)}),
    }
}

fn mem(dev: &mut dyn ScsiDevice, address: u32) -> Value {
    let mut result = read(
        dev,
        "memory",
        &abi::build_memread_cdb(address),
        abi::MEMREAD_LEN,
    );
    result["address"] = json!(address);
    result
}

fn matches(sample: &Value, expected: &[u8]) -> bool {
    sample["ok"] == true
        && sample["data"].as_array().is_some_and(|data| {
            data.len() >= expected.len()
                && data
                    .iter()
                    .zip(expected)
                    .all(|(a, b)| a.as_u64() == Some(u64::from(*b)))
        })
}

fn byte(memory: &[Value], address: u32) -> Option<u8> {
    memory.iter().find_map(|sample| {
        if sample["ok"] != true {
            return None;
        }
        let base = sample["address"].as_u64()?;
        let offset = u64::from(address).checked_sub(base)? as usize;
        sample["data"]
            .as_array()?
            .get(offset)?
            .as_u64()?
            .try_into()
            .ok()
    })
}

fn word(memory: &[Value], address: u32) -> Option<u32> {
    Some(u32::from_le_bytes([
        byte(memory, address)?,
        byte(memory, address + 1)?,
        byte(memory, address + 2)?,
        byte(memory, address + 3)?,
    ]))
}

fn capture(dev: &mut dyn ScsiDevice) -> Value {
    let inquiry = read(dev, "INQUIRY", &[0x12, 0, 0, 0, 36, 0], 36);
    let product: Option<String> = inquiry["data"].as_array().and_then(|data| {
        let bytes: Option<Vec<u8>> = data
            .get(16..32)?
            .iter()
            .map(|v| v.as_u64()?.try_into().ok())
            .collect();
        Some(String::from_utf8_lossy(&bytes?).trim().to_owned())
    });
    let mut result = json!({"policy":"read-only snapshot; native status may change between reads",
        "full_image_hash_verified":false,
        "inquiry":inquiry,"product":product});
    if !product.is_some_and(|p| p.contains("BH16NS48")) {
        result["status"] = json!("wrong_drive_or_inquiry_failed");
        return result;
    }
    let hook = mem(dev, 0x10a876);
    // Select addresses only from a recognized installed hook. Both experiments
    // bind the same native RAM map; never dereference firmware-supplied pointers.
    let (stub_at, bindings_at, expected_stub, expected_hash) = if matches(&hook, BU40N_HOOK) {
        (0x1ac404, 0x1ac4b8, BU40N_STUB, BU40N_SOURCE)
    } else {
        (0x1aabc0, 0x1aac4c, STUB, SOURCE)
    };
    let stub = mem(dev, stub_at);
    let bindings = mem(dev, bindings_at);
    let supported = (matches(&hook, HOOK) || matches(&hook, BU40N_HOOK))
        && matches(&stub, expected_stub)
        && matches(&bindings, BINDINGS);
    result["expected_image_sha256"] = json!(expected_hash);
    result["firmware_samples"] = json!([hook, stub, bindings]);
    result["firmware_samples_match"] = json!(supported);
    if !supported {
        result["status"] = json!("firmware_sample_mismatch_or_read_failed");
        return result;
    }
    // Capture native RAM before capacity/configuration commands can alter state.
    let memory: Vec<_> = [
        0x01ff9b20, 0x01ff9d80, 0x01ff9dc0, 0x01ff9e00, 0x01ffa200, 0x02000b00, 0x02000b40,
        0x02000dc0, 0x02000e00, 0x02001210, 0x01ffafc0, 0x01ffb080, 0x01ffb200,
    ]
    .into_iter()
    .map(|address| mem(dev, address))
    .collect();
    let ready = byte(&memory, 0x02000b14);
    result["decoded"] = json!({
        "media_state":byte(&memory, 0x01ff9dd3),
        "native_status":byte(&memory, 0x01ff9b29),
        "read_blocked":byte(&memory, 0x01ff9b2b),
        "native_init_status":byte(&memory, 0x02000b00),
        "abort_status":byte(&memory, 0x02000b05),
        "abort_a":byte(&memory, 0x01ffafc6),
        "abort_override":byte(&memory, 0x01ffb0ac),
        "di_reader_abort":byte(&memory, 0x01ffb20e),
        "di_status":ready,"di_ready":ready.map(|v| v & 2 != 0),
        "mode":byte(&memory, 0x01ffa20d),
        "di_offset":word(&memory, 0x01ffa204),
        "di_buffer_base":word(&memory, 0x02000df0),
        "availability":byte(&memory, 0x02000ddc),
        "capacity_end":word(&memory, 0x02000e18),
        "unrestricted":byte(&memory, 0x02001213),
    });
    let errors = memory.iter().filter(|sample| sample["ok"] != true).count();
    result["memory"] = json!(memory);
    result["identity"] = read(dev, "freemkv identity", &abi::build_identity_cdb(64), 64);
    result["capacity"] = read(dev, "READ CAPACITY", &[0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0], 8);
    result["configuration"] = read(
        dev,
        "GET CONFIGURATION",
        &[0x46, 0, 0, 0, 0, 0, 0, 0, 64, 0],
        64,
    );
    result["memory_errors"] = json!(errors);
    result["status"] = json!(if errors == 0 {
        "captured"
    } else {
        "partial_capture"
    });
    result
}

fn selected(args: &Args) -> Result<String> {
    if let Some(path) = &args.device {
        return Ok(path.clone());
    }
    let drives: Vec<_> = platform::list_drives()
        .into_iter()
        .filter(|d| d.model.contains("BH16NS48"))
        .collect();
    if drives.len() != 1 {
        bail!(
            "Expected one BH16NS48; found {}. Supply --device if necessary.",
            drives.len()
        );
    }
    Ok(drives[0].path.clone())
}

fn main() -> Result<()> {
    let args = Args::parse();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis();
    let output = args.out.clone().unwrap_or(
        std::env::current_exe()?.with_file_name(format!("BH16NS48-disc-state-{now}.json")),
    );
    let result = (|| -> Result<Value> {
        let path = selected(&args)?;
        println!("Reading diagnostic state from {path} ...");
        let mut dev = platform::open(&path, false)
            .context("opening the drive (administrator access may be needed)")?;
        let mut captured = capture(dev.as_mut());
        captured["device"] = json!(path);
        Ok(captured)
    })();
    let mut report = match result {
        Ok(value) => value,
        Err(error) => json!({"status":"capture_failed","error":format!("{error:#}")}),
    };
    report["time_ms"] = json!(now);
    report["tool_version"] = json!(env!("CARGO_PKG_VERSION"));
    report["os"] = json!(std::env::consts::OS);
    std::fs::write(&output, serde_json::to_vec_pretty(&report)?)?;
    println!(
        "Saved {}\nSend this JSON file back for diagnosis.",
        output.display()
    );
    if report["status"] != "captured" {
        bail!("Capture incomplete; the JSON records the error.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Device {
        fail: bool,
        wrong: bool,
        bu40n: bool,
        ram_reads: usize,
    }
    impl ScsiDevice for Device {
        fn describe(&self) -> String {
            "test".into()
        }
        fn command_out(&mut self, _: &[u8], _: &[u8]) -> Result<()> {
            panic!("writes forbidden")
        }
        fn command_in(&mut self, cdb: &[u8], len: usize) -> Result<Vec<u8>> {
            let mut data = vec![0; len];
            match cdb[0] {
                0x12 => data[16..32].copy_from_slice(b"BD-RE  BH16NS48 "),
                0x3c => {
                    assert!([1, 9].contains(&cdb[4]), "only Identity and DumpAll");
                    if cdb[4] == 9 {
                        let at = u32::from_be_bytes(cdb[5..9].try_into().unwrap());
                        match at {
                            0x10a876 => {
                                if !self.wrong {
                                    let hook = if self.bu40n { BU40N_HOOK } else { HOOK };
                                    data[..hook.len()].copy_from_slice(hook);
                                }
                            }
                            0x1aabc0 => data[..STUB.len()].copy_from_slice(STUB),
                            0x1aac4c => data[..BINDINGS.len()].copy_from_slice(BINDINGS),
                            0x1ac404 => data[..BU40N_STUB.len()].copy_from_slice(BU40N_STUB),
                            0x1ac4b8 => data[..BINDINGS.len()].copy_from_slice(BINDINGS),
                            _ => {
                                self.ram_reads += 1;
                                if self.fail {
                                    return Err(platform::ScsiSenseError::new(
                                        2,
                                        0x30,
                                        0,
                                        "test failure",
                                    )
                                    .into());
                                }
                            }
                        }
                    }
                }
                0x25 | 0x46 => (),
                _ => panic!("unexpected command"),
            }
            Ok(data)
        }
    }
    #[test]
    fn matching_candidate_captures_without_writes() {
        let mut dev = Device {
            fail: false,
            wrong: false,
            bu40n: false,
            ram_reads: 0,
        };
        let report = capture(&mut dev);
        assert_eq!(report["status"], "captured");
        assert_eq!(report["decoded"]["di_ready"], false);
        assert_eq!(dev.ram_reads, 13);
    }
    #[test]
    fn command_errors_are_not_decoded_as_zero() {
        let mut dev = Device {
            fail: true,
            wrong: false,
            bu40n: false,
            ram_reads: 0,
        };
        let report = capture(&mut dev);
        assert!(report["decoded"]["di_ready"].is_null());
        assert_eq!(report["status"], "partial_capture");
        assert!(report["decoded"]["media_state"].is_null());
        assert_eq!(report["memory"][0]["sense"], json!([2, 0x30, 0]));
    }
    #[test]
    fn mismatching_firmware_never_reads_bound_ram() {
        let mut dev = Device {
            fail: false,
            wrong: true,
            bu40n: false,
            ram_reads: 0,
        };
        assert_eq!(
            capture(&mut dev)["status"],
            "firmware_sample_mismatch_or_read_failed"
        );
        assert_eq!(dev.ram_reads, 0);
    }
    #[test]
    fn bu40n_port_uses_its_own_flash_samples_and_same_native_ram_map() {
        let mut dev = Device {
            fail: false,
            wrong: false,
            bu40n: true,
            ram_reads: 0,
        };
        let report = capture(&mut dev);
        assert_eq!(report["status"], "captured");
        assert_eq!(report["expected_image_sha256"], BU40N_SOURCE);
        assert_eq!(report["full_image_hash_verified"], false);
        assert_eq!(dev.ram_reads, 13);
    }
}
