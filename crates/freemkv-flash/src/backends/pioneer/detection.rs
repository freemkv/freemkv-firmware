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
) -> Option<pioneer_optical::drive::Evidence> {
    let pioneer_response = read(
        dev,
        "Pioneer F1 identity",
        &pioneer_optical::cdb::vendor_identity(),
        48,
        &mut result.observations,
    );
    match pioneer_response {
        Ok(bytes) => bytes,
        Err(error) => {
            result.observations.push(format!("{error:#}"));
            failures.push(error);
            None
        }
    }
    .and_then(
        |b| match pioneer_optical::drive::Response::parse(inquiry, &b) {
            Ok(response) => {
                result.pioneer_identity = Some(response.identity().clone());
                response.into_evidence()
            }
            Err(source) => {
                result
                    .observations
                    .push("Pioneer F1 identity: incomplete structure".into());
                failures.push(
                    Unavailable {
                        command: "Pioneer F1 identity",
                        source: source.into(),
                    }
                    .into(),
                );
                None
            }
        },
    )
}
