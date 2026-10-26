//! Exact-input capability queries run the real modifier and structural audit.
//! A valid query returns a record even when the firmware cannot be modified.

use sha2::{Digest, Sha256};

use crate::engine::lever::jstr;
use crate::{api, boot::BootSettings, engine, family};

/// Build the normal preview without saving output, and bind its result to the
/// input digest. Consumers must inspect `status`; query success is not build success.
pub fn report_json(image: &[u8]) -> String {
    let digest = Sha256::digest(image)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let identity = family::detect_chip(image)
        .ok()
        .map(|i| {
            format!(
                "{{\"chip\":{},\"vendor\":{},\"model\":{},\"revision\":{},\"variant\":{}}}",
                jstr(i.family.label()),
                jstr(&i.vendor),
                jstr(&i.model),
                jstr(&i.rev),
                jstr(&i.vendor_specific)
            )
        })
        .unwrap_or_else(|| "null".into());
    let defaults = BootSettings::standard();
    let result = api::modify_with_defaults(image, &defaults).and_then(|(report, support)| {
        let audit = engine::audit::audit_image(image, &report);
        anyhow::ensure!(audit.ok(), "generated preview failed structural audit");
        Ok((report, support))
    });
    let (status, report, reason, detail, output) = match result {
        Ok((report, support)) => (
            if report.applied_count() > 0 {
                "supported"
            } else {
                "unchanged"
            },
            defaults.report_json(&support, &report.to_json()),
            "null".to_string(),
            "null".to_string(),
            jstr(
                &Sha256::digest(&report.image)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>(),
            ),
        ),
        Err(error) => {
            let issue = freemkv_flash::workflow::user_error(&error);
            (
                "unsupported",
                "null".to_string(),
                jstr(issue.id),
                jstr(&format!("{error:#}")),
                "null".to_string(),
            )
        }
    };
    format!("{{\"schema\":1,\"input_sha256\":{},\"producer_version\":{},\"status\":{},\"identity\":{},\"report\":{},\"reason\":{},\"detail\":{},\"output_sha256\":{}}}",
        jstr(&digest),jstr(env!("CARGO_PKG_VERSION")),jstr(status),identity,report,reason,detail,output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wh_capabilities_bind_real_emission_choices_and_missing_hooks_to_the_input() {
        let image = include_bytes!("../tests/fixtures/WH16NS58_OEM_1.V9.bin");
        let before = image.to_vec();
        let result: serde_json::Value = serde_json::from_str(&report_json(image)).unwrap();
        assert_eq!(
            result["input_sha256"],
            "97b287072e20c9527de6f34f6d564c8edcc6afb3ecf5675c11b8262c11663061"
        );
        assert_eq!(result["status"], "supported");
        assert_eq!(result["identity"]["chip"], "MT1959");
        assert_eq!(
            result["report"]["boot_settings"]["unrestricted"]["choices"],
            serde_json::json!(["oem", "on"])
        );
        let raw = result["report"]["levers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|l| l["id"] == "RawRead")
            .unwrap();
        let hooks = raw["hooks"].as_array().unwrap();
        assert!(hooks.iter().any(|h| h["id"] == "auth-cell"
            && h["status"] == "applied"
            && h["variant"] == "R1StateR1"));
        assert!(hooks.iter().any(|h| h["id"] == "uhd-native"
            && h["status"] == "unavailable"
            && h["reason"].is_string()));
        assert_eq!(image.as_slice(), before);
    }

    #[test]
    fn unsupported_input_is_an_explicit_capability_record_not_a_missing_row() {
        let image = vec![0u8; 1024];
        let result: serde_json::Value = serde_json::from_str(&report_json(&image)).unwrap();
        assert_eq!(result["schema"], 1);
        assert_eq!(result["status"], "unsupported");
        assert!(result["report"].is_null());
        assert!(result["reason"].is_string());
        assert_eq!(image, vec![0u8; 1024]);
    }
}
