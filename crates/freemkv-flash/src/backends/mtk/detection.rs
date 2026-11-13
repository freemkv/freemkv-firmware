//! Bounded vendor protocol probe used by shared discovery arbitration.
use crate::backend::{
    detection::{read, Detection, Unavailable},
    ReadDevice,
};

pub(crate) fn probe(
    dev: &mut ReadDevice<'_>,
    inquiry: &[u8],
    result: &mut Detection,
    failures: &mut Vec<anyhow::Error>,
) -> Option<mediatek_optical::drive::Evidence> {
    let mediatek_response = read(
        dev,
        "MediaTek boot banner",
        &mediatek_optical::cdb::read_memory(0x3000, 32),
        32,
        &mut result.observations,
    );
    match mediatek_response {
        Ok(bytes) => bytes,
        Err(error) => {
            result.observations.push(format!("{error:#}"));
            failures.push(error);
            None
        }
    }
    .and_then(
        |b| match mediatek_optical::drive::Evidence::parse(inquiry, &b) {
            Ok(e) => e,
            Err(source) => {
                result
                    .observations
                    .push("MediaTek boot banner: incomplete structure".into());
                failures.push(
                    Unavailable {
                        command: "MediaTek boot banner",
                        source: source.into(),
                    }
                    .into(),
                );
                None
            }
        },
    )
}

/// BOOT evidence identifies the protocol but only Recovery can bind its loader.
pub(crate) fn normal_operations_available(evidence: &mediatek_optical::drive::Evidence) -> bool {
    evidence.identity().revision() != "BOOT"
}
