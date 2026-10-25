// Offline production-library contract audit. Input: sha<TAB>old-family<TAB>path.
// Run from a temporary crate depending on the companion optical worktree.
use std::{fs, io::{self, BufRead}, collections::BTreeMap};
use pioneer_optical::{envelope, image, startup, settings::update::Contract, CodedError};
fn main() {
    let mut entries = Vec::new();
    let mut errors = Vec::new();
    for line in io::stdin().lock().lines() {
        let line = line.unwrap(); let f: Vec<_> = line.split('\t').collect();
        let raw = match fs::read(f[2]) { Ok(raw) => raw, Err(error) => { errors.push(format!("{}: read: {}", f[0], error)); continue } };
        let body = if f[2].ends_with(".enc") {
            match envelope::decode_envelope(&raw) {Some(d) => d.image, None => {errors.push(f[0].to_string()); continue}}
        } else {raw};
        let family = image::family(&body).map(|f| f.to_string());
        let setting = startup::setting(&body).ok().map(|s| format!("{:04x}:{:04x}:{}",s.parameter,s.value,s.explicit));
        entries.push((f[0].to_string(), f[1].to_string(), family, Contract::discover(&body), setting));
    }
    let mut old_to_new = BTreeMap::<String,Vec<String>>::new();
    let mut counts = BTreeMap::<String,usize>::new();
    let mut changes = Vec::new();
    let mut old_same_settings_refusals = Vec::new();
    for (sha, old, new, _, _) in &entries {
        if let Some(new) = new { old_to_new.entry(old.clone()).or_default().push(new.clone()); }
        for (other_sha, other_old, other_new, contract, _) in &entries {
            if new.is_none() || other_new.is_none() { continue }
            if new != other_new { *counts.entry("hardware_different".into()).or_default() += 1; continue }
            let own = &entries.iter().find(|e| &e.0 == sha).unwrap().3;
            let decision = match own.check(contract) {Ok(()) => "compatible", Err(ref e) => e.code()};
            *counts.entry(format!("same_hardware:{decision}")).or_default() += 1;
            if old != other_old { changes.push(serde_json::json!({"source":sha,"target":other_sha,"decision":decision})); }
            else if decision != "compatible" { old_same_settings_refusals.push(serde_json::json!({"source":sha,"target":other_sha,"decision":decision})); }
        }
    }
    for values in old_to_new.values_mut() {values.sort();values.dedup();}
    let result = serde_json::json!({"scheme":image::FAMILY_SCHEME,"attempted":entries.len()+errors.len(),"decoded":entries.len(),"decode_failures":errors,"counts":counts,"old_to_new":old_to_new,"newly_equal_directed_pairs":changes,"existing_same_family_settings_refusals":old_same_settings_refusals,"startup_policies":entries.iter().map(|(sha,_,_,_,s)|(sha,s)).collect::<BTreeMap<_,_>>(),"scope":"Actual production hardware and settings contract functions; no transport or live device; full receiver/authentication admission remains a separate audit."});
    println!("{}",serde_json::to_string_pretty(&result).unwrap());
}
