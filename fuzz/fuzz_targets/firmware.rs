#![no_main]
use freemkv_flash::{
    imageid,
    platform::{medium_status_from_sense, MediumStatus},
};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if data.len() > 5 * 1024 * 1024 {
        return;
    }
    let identity = imageid::identify(data);
    assert_eq!(identity, imageid::identify(data));
    let _ = identity.family.label();
    let _ = identity.family.flash_summary();
    if data.len() >= 3 {
        let (key, asc, ascq) = (data[0], data[1], data[2]);
        let status = medium_status_from_sense(key, asc, ascq);
        // SPC no-medium sense: only NOT READY / MEDIUM NOT PRESENT is empty.
        if key != 2 || asc != 0x3a {
            assert!(status.is_none());
        } else if ascq == 2 {
            assert_eq!(status, Some(MediumStatus::TrayOpen));
        } else {
            assert_eq!(status, Some(MediumStatus::ClosedEmpty));
        }
    }
});
