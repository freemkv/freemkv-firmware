//! Read-only inventory of retained classic UHD contracts against full sources.
use anyhow::{Context, Result};
pub use freemkv_fw::abi;
#[allow(dead_code)]
use freemkv_fw::engine::mt1939_uhd as research;
use mediatek_optical::image::analysis::{
    ClassicCalibration, ClassicConsumer, ClassicConsumerKind as K, ClassicDi, ClassicParameter,
    ClassicPosition, ClassicPositionSetup, ClassicReadCompletion, ClassicReadPosition,
    LegacyStackDi, NativeSpeedPolicy, UhdAreas,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
fn binding<T: std::fmt::Debug>(
    value: Result<T, mediatek_optical::image::analysis::Error>,
) -> serde_json::Value {
    match value {
        Ok(v) => json!({"bound":true,"native_contract":format!("{v:?}")}),
        Err(e) => json!({"error":e.to_string()}),
    }
}
fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let inventory: serde_json::Value =
        serde_json::from_slice(&std::fs::read(args.next().context("inventory")?)?)?;
    let hoard = PathBuf::from(args.next().context("hoard")?);
    let output = PathBuf::from(args.next().context("output")?);
    let mut results = Vec::new();
    for row in inventory["images"].as_array().context("images")? {
        let bytes = std::fs::read(hoard.join(row["path"].as_str().context("source path")?))?;
        anyhow::ensure!(
            format!("{:x}", Sha256::digest(&bytes))
                == row["sha256"].as_str().context("source hash")?,
            "source hash mismatch"
        );
        let plan = research::UhdConversionPlan::inspect(&bytes);
        let di = ClassicDi::detect(&bytes);
        let downstream = UhdAreas::inspect(&bytes)
            .media_state_address()
            .map(|state| {
                json!({
                    "stack_di":binding(LegacyStackDi::detect(&bytes)),
                    "position":binding(ClassicPosition::detect(&bytes,state)),
                    "position_setup":binding(ClassicPositionSetup::detect(&bytes,state)),
                    "read_position":binding(ClassicReadPosition::detect(&bytes,state)),
                    "parameter":binding(ClassicParameter::detect(&bytes,state)),
                    "calibration":binding(ClassicCalibration::detect(&bytes,state)),
                    "completion":binding(ClassicReadCompletion::inspect(&bytes,state)),
                    "speed":binding(NativeSpeedPolicy::detect(&bytes)),
                })
            });
        let auxiliary = UhdAreas::inspect(&bytes).media_state_address().map(|state| {
            [K::Control18, K::DiMode, K::ReadBoundary, K::ReadControl, K::MediaDefaults,
                K::Mode23, K::ParameterClass, K::RequestArgument, K::ReadValue,
                K::ReadStatus, K::InitializationBypass].map(|kind| {
                json!({"role":format!("{kind:?}"),"contract":match ClassicConsumer::inspect_kind(&bytes,state,kind) {
                    Ok(c)=>json!({"region":c.region,"site":c.selection.site(),"accept":c.selection.accept(),"reject":c.selection.reject()}),
                    Err(e)=>json!({"error":e.to_string()})}})
            })
        });
        results.push(json!({"sha256":row["sha256"],"family":row["identified_family"],
            "auxiliary":match auxiliary {Ok(v)=>json!(v),Err(e)=>json!({"error":e.to_string()})},
            "downstream":match downstream {Ok(v)=>v,Err(e)=>json!({"error":e.to_string()})},
            "classic_di":match di {Ok(_) => json!({"recognized":true}),Err(e)=>json!({"error":e.to_string()})},
            "classic_group":match plan {Ok(p)=>json!({"state":p.state_address(),"missing":p.remaining_contracts(),
                "prepared":match p.prepared_patches(&bytes,0x02000e40) {Ok(v)=>json!({"count":v.len(),"sites":v.iter().map(|c|json!({"role":c.role,"site":c.site,"original":c.original,"bytes":c.bytes})).collect::<Vec<_>>()}),Err(e)=>json!({"error":format!("{e:#}")})}}),Err(e)=>json!({"error":format!("{e:#}")})}}));
    }
    std::fs::write(output, serde_json::to_vec_pretty(&results)?)?;
    Ok(())
}
