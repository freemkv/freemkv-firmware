use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fs};
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
macro_rules! version {
    ($name:ident, $lib:ident) => {
        mod $name {
            use super::*;
            use $lib::{envelope::Update,receiver::Receiver};
            pub fn snapshot(source: &Value, target: &Value) -> Result<Value,String> {
                let pair = |row: &Value| -> Result<Update,String> {
                    Update::load(&fs::read(row["kernel"].as_str().unwrap()).unwrap(), &fs::read(row["normal"].as_str().unwrap()).unwrap()).map_err(|e|e.to_string())
                };
                let source = pair(source)?;
                let receiver = Receiver::from_installed(&source).map_err(|e|e.to_string())?;
                let target = pair(target)?;
                let descriptor = target.normal().image[..16].to_vec();
                let plan = receiver.prepare(target).map_err(|e|e.to_string())?;
                Ok(json!({
                    "initial_kernel":hash(plan.kernel_transfer()),
                    "initial_normal":hash(plan.normal_transfer()),
                    "first_kernel_image":hash(plan.first_kernel_image()),
                    "final_kernel_image":hash(plan.final_kernel_image()),
                    "restoration":plan.restoration_kernel_transfer().map(hash),
                    "startup":format!("{:?}",plan.startup_setting()),
                    "settings":format!("{:?}",plan.settings()),
                    "initial_control":hash(&receiver.entry_control(&source.normal().image[..16]).unwrap()),
                    "final_control":plan.restoration_receiver().map(|r|hash(&r.entry_control(&descriptor).or_else(|_|r.entry_control(&source.normal().image[..16])).unwrap())),
                }))
            }
        }
    }
}
version!(old, baseline);
version!(new, candidate);
fn main() {
    let list: Vec<Value> =
        serde_json::from_slice(&fs::read(std::env::args().nth(1).unwrap()).unwrap()).unwrap();
    let mut cases = BTreeSet::new();
    for i in 0..list.len() {
        cases.insert((i, i));
    }
    for (i, a) in list.iter().enumerate() {
        for (j, b) in list.iter().enumerate() {
            if ["1014", "1030", "1031"].contains(&a["group"].as_str().unwrap())
                && ["1014", "1030", "1031"].contains(&b["group"].as_str().unwrap())
            {
                cases.insert((i, j));
            }
        }
    }
    let mut identical = 0;
    let mut refused = 0;
    let mut bridges = 0;
    let mut failures = vec![];
    for (n, (i, j)) in cases.iter().enumerate() {
        let before = old::snapshot(&list[*i], &list[*j]);
        let after = new::snapshot(&list[*i], &list[*j]);
        match (before,after) {
            (Ok(a),Ok(b)) if a==b=>identical+=1,
            (Err(_),Err(_))=>refused+=1,
            (Err(a),Ok(_)) if a.contains("Kernel handoff mismatch")=>bridges+=1,
            (a,b)=>failures.push(json!({"source":list[*i]["package"],"target":list[*j]["package"],"baseline":a,"candidate":b})),
        }
        if n % 50 == 0 {
            eprintln!(
                "{}/{}: {} identical, {} new bridges, {} failures",
                n + 1,
                cases.len(),
                identical,
                bridges,
                failures.len()
            );
        }
    }
    println!("{}",serde_json::to_string_pretty(&json!({"baseline":"d7ae773da92d37f05fa2740be98cdb6e0281e486","packages":list.len(),"cases":cases.len(),"identical":identical,"refused":refused,"new_bridges":bridges,"failures":failures})).unwrap());
    if !failures.is_empty() || bridges == 0 {
        std::process::exit(1)
    }
}
