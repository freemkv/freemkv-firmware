//! Synthetic Thumb evidence for a receiver that decrypts the whole upload.

fn word(image: &mut [u8], at: usize, value: u16) {
    image[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn literal(image: &mut [u8], at: usize, register: u16, pool: usize, value: u32) {
    let displacement = pool - ((at + 4) & !3);
    assert_eq!(displacement % 4, 0);
    assert!(displacement / 4 < 256);
    word(
        image,
        at,
        0x4800 | register << 8 | (displacement / 4) as u16,
    );
    image[pool..pool + 4].copy_from_slice(&value.to_le_bytes());
}

fn call(image: &mut [u8], at: usize, target: usize) {
    let delta = target - at - 4;
    word(image, at, 0xf000 | ((delta >> 12) as u16 & 2047));
    word(image, at + 2, 0xf800 | ((delta >> 1) as u16 & 2047));
}

/// Add independently traced header and body AES arguments to a signed BU3
/// fixture. Callers must re-sign afterwards if they cover this code range.
pub(crate) fn stamp(image: &mut [u8]) {
    super::fixture::encrypted_receiver(image);
    image[0x9a324..0x9a520].fill(0);
    // The existing header setup loads [r5 + 28]; establish that RAM cell.
    literal(image, 0x9a312, 5, 0x9a500, 0x02000c18);

    // Both update-bit branches select start/offset zero or 0x10000 and
    // length total-start. These are assembled instructions, not vendor code.
    let selection = 0x9a360;
    for (index, op) in [
        (1, 0x6980),
        (2, 0x07c0),
        (3, 0xd006),
        (5, 0x2000),
        (6, 0x6008),
        (8, 0x6008),
        (9, 0x6820),
        (10, 0xe007),
        (12, 0x2101),
        (13, 0x0409),
        (14, 0x6001),
        (16, 0x6001),
        (17, 0x6820),
        (18, 0x1a40),
        (20, 0x6030),
    ] {
        word(image, selection + index * 2, op);
    }
    for (index, register, pool, value) in [
        (0, 0, 0x9a504, 0x04002040),
        (4, 1, 0x9a508, 0x02000c60),
        (7, 1, 0x9a50c, 0x02000c68),
        (11, 0, 0x9a508, 0x02000c60),
        (15, 0, 0x9a50c, 0x02000c68),
        (19, 6, 0x9a510, 0x02000c6c),
    ] {
        literal(image, selection + index * 2, register, pool, value);
    }

    // AES(staging + selected_start, staging + selected_start, 0x200000).
    let body = selection + 42;
    literal(image, body, 0, 0x9a50c, 0x02000c68);
    word(image, body + 2, 0x6800);
    literal(image, body + 4, 1, 0x9a514, 0x02000c34);
    for (offset, op) in [
        (6, 0x6809),
        (8, 0x1840),
        (10, 0x0001),
        (12, 0x2202),
        (14, 0x0512),
    ] {
        word(image, body + offset, op);
    }
    call(image, body + 16, 0x9b024);
}

#[test]
fn prepared_receiver_proves_and_encodes_both_header_and_body() {
    use mediatek_optical::{
        envelope::Envelope,
        receiver::{Encoding, Receiver},
        update::InstalledFirmware,
    };
    let mut image = super::fixture::image(&super::fixture::BU3, "BD-RE BU40N", 2);
    image[0x1ec000..0x1ec008].copy_from_slice(b"HL-DT-ST");
    image[0x1ec018..0x1ec01c].copy_from_slice(b"INTM");
    stamp(&mut image);
    let image = mediatek_optical::image::cmac::resign(&image).unwrap();
    let envelope = Envelope::load(&image).unwrap();
    let receiver = Receiver::from_firmware(&envelope).unwrap();
    let analysis = receiver.application_analysis().unwrap();
    assert_eq!(analysis.bulk_decoders().len(), 1);
    assert!(analysis.scratch_decoders().is_empty());
    let installed = InstalledFirmware::new(super::fixture::identity(&image), &image).unwrap();
    let prepared = receiver.prepare(&envelope, &installed).unwrap();
    assert_eq!(prepared.plan().encoding().header, Encoding::Encrypted);
    assert_eq!(prepared.plan().encoding().body, Encoding::Encrypted);
    let mut wire = prepared.plan().transfer().to_vec();
    assert_ne!(wire, image);
    mediatek_optical::enc::decrypt(&mut wire).unwrap();
    assert_eq!(wire, image);
}
