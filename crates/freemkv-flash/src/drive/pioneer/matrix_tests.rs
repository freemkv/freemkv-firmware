use super::*;
use crate::drive::pioneer::flash_plan::{self as plan, FlashPlan, Installed};
use pioneer_optical::{envelope, image, receiver::Receiver};

// Private fixtures are supplied explicitly; synthetic regression tests run in CI.
#[test]
fn every_prepared_package_in_both_directions_within_its_family() {
    let Some(manifest) = std::env::var_os("PIONEER_PACKAGE_MATRIX") else {
        return;
    };
    let mut packages = Vec::new();
    for line in std::fs::read_to_string(manifest).unwrap().lines() {
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 4);
        let kernel = std::fs::read(fields[1]).unwrap();
        let normal = std::fs::read(fields[2]).unwrap();
        let update = envelope::Update::load(&kernel, &normal)
            .unwrap_or_else(|e| panic!("{}: {e}", fields[0]));
        assert_eq!(update.family().unwrap().to_string(), fields[3]);
        let required = update.normal().required_abi().unwrap();
        assert!(required.is_satisfied_by(&update.kernel().provided_abi().unwrap()));
        let policy = image::kernel_marker_policy(&update.kernel().image).unwrap();
        let target = plan::target_from_components(Some(&kernel), Some(&normal)).unwrap();
        let installed = Installed {
            controller_id: target.controller_id,
            receiver_new_gen: Some(policy == image::KernelMarkerPolicy::RejectZeroAndErased),
            normal_date: target.normal.unwrap().date,
            family: target.family.clone(),
            kernel_tag: target.required_kernel_tag.clone(),
        };
        let steps = offline_pair_data_out(&kernel, &normal)
            .unwrap_or_else(|e| panic!("{}: {e:#}", fields[0]));
        let kernel_wire: Vec<_> = steps
            .iter()
            .filter(|s| s.stage == TransferStage::KernelFe)
            .flat_map(|s| s.data.iter().copied())
            .collect();
        assert_eq!(receive_kernel(&kernel_wire), update.kernel().image);
        let normal_wire: Vec<_> = steps
            .iter()
            .filter(|s| s.stage == TransferStage::Normal)
            .flat_map(|s| s.data.iter().copied())
            .collect();
        assert_eq!(normal_wire, update.normal_transfer());
        assert!(envelope::builder::normal_authentication_valid(
            &normal_wire,
            &update.kernel().image
        ));
        let receiver = Receiver::from_installed(&update).unwrap();
        packages.push((fields[0].to_owned(), installed, target, update, receiver));
    }
    assert!(packages.len() >= 2, "matrix must contain multiple packages");
    let mut same_family = 0;
    let mut different_family = 0;
    let mut restore_passes = 0;
    for (source_id, installed, _, _, receiver) in &packages {
        for (target_id, _, target, update, _) in &packages {
            let selected = plan::decide_flash_plan(installed, target, false);
            if installed.family != target.family {
                assert!(matches!(selected, FlashPlan::Refused(_)));
                assert!(matches!(
                    receiver.check_family(update.normal()),
                    Err(pioneer_optical::receiver::Error::FamilyMismatch { .. })
                ));
                different_family += 1;
                continue;
            }
            assert!(
                !matches!(selected, FlashPlan::Refused(_)),
                "{source_id} -> {target_id}: {selected:?}"
            );
            let prepared = receiver
                .prepare(update.clone())
                .unwrap_or_else(|error| panic!("{source_id} -> {target_id}: {error}"));
            assert_eq!(prepared.normal_transfer(), update.normal_transfer());
            assert_eq!(prepared.final_kernel_image(), update.kernel().image);
            same_family += 1;
            if installed.receiver_new_gen == Some(true)
                && matches!(update.kernel().image[0xfe], 0 | 0xff)
            {
                let patched = prepared.first_kernel_image();
                assert_eq!(patched[0xfe], 1);
                assert_eq!(receive_kernel(prepared.kernel_transfer()), patched);
                assert_eq!(
                    prepared.restoration_kernel_transfer().unwrap(),
                    update.kernel_transfer()
                );
                let restoration = prepared.restoration_receiver().unwrap();
                assert!(restoration
                    .entry_control(&update.normal().image[..16])
                    .is_ok());
                assert_eq!(
                    image::kernel_marker_policy(patched),
                    Some(image::KernelMarkerPolicy::NoMarkerCheck)
                );
                // The second pass's receiver accepts the pristine marker.
                assert_eq!(
                    image::kernel_marker_policy(&update.kernel().image),
                    Some(image::KernelMarkerPolicy::NoMarkerCheck)
                );
                restore_passes += 1;
            } else {
                assert_eq!(prepared.kernel_transfer(), update.kernel_transfer());
                assert!(prepared.restoration_kernel_transfer().is_none());
                assert!(prepared.restoration_receiver().is_none());
            }
        }
    }
    eprintln!("{} packages: {same_family} same-family directions, {different_family} cross-family refusals, {restore_passes} restore paths", packages.len());
}

fn receive_kernel(wire: &[u8]) -> Vec<u8> {
    assert_eq!(wire.len(), 0x11200);
    let key = &wire[0x200..0x1200];
    wire[0x1200..]
        .as_chunks::<4>()
        .0
        .iter()
        .enumerate()
        .flat_map(|(i, w)| {
            let k = u32::from_le_bytes(key[(i * 4) % key.len()..][..4].try_into().unwrap());
            (u32::from_le_bytes(*w) ^ k)
                .rotate_right(k & 31)
                .to_le_bytes()
        })
        .collect()
}
