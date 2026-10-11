//! Test fixtures: the hardware configuration a synthetic MediaTek image
//! needs for `mediatek_optical::image::family` to name its board. Built in
//! code from the documented record layout; no vendor bytes.

/// A board a synthetic image is built for.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Board {
    /// Descriptor and record tag, e.g. `MTEKMT1959`.
    pub tag: &'static str,
    /// Boot banner, e.g. `MT1959 Boot BU5`.
    pub banner: &'static str,
    /// Record and descriptor platform code.
    pub platform: &'static str,
    /// Feature 0x0003 current profile.
    pub medium: u8,
    /// BD writing profiles enabled.
    pub bd_write: bool,
}

/// The BU40N board line (`309829e6c3c8f31d`).
pub(crate) const BU3: Board = Board {
    tag: "MTEKMT1959",
    banner: "MT1959 Boot BU5",
    platform: "BU3",
    medium: 0x2B,
    bd_write: true,
};

/// The JB7 MT1939 board line, e.g. BH16NS40 1.00 to 1.03 (`11e7527216405467`).
pub(crate) const JB7: Board = Board {
    tag: "MTEKMT1939",
    banner: "MT1939 Boot Code",
    platform: "JB7",
    medium: 0x39,
    bd_write: true,
};

/// The JB8 MT1939 board line, e.g. BH16NS40 1.02 to 1.05 (NS50) (`70f72c46f9603141`).
pub(crate) const JB8: Board = Board {
    tag: "MTEKMT1939",
    banner: "MT1959 Boot JB8 ",
    platform: "JB8",
    medium: 0x39,
    bd_write: true,
};

/// Where [`stamp`] writes the feature template and record: inside the
/// fixtures' signed range.
pub(crate) const RECORD_AREA: usize = 0x1_1000;

/// Offset of the platform code in the identity descriptor.
const DESCRIPTOR_PLATFORM: usize = 0x1E_C046;

fn padded(text: &str, len: usize) -> Vec<u8> {
    let mut out = vec![b' '; len];
    out[..text.len()].copy_from_slice(text.as_bytes());
    out
}

/// The MMC feature template, then the hardware record.
pub(crate) fn hardware(board: &Board) -> Vec<u8> {
    let mut profiles = Vec::new();
    for (number, bd_write) in [
        (0x43, true),
        (0x42, true),
        (0x41, true),
        (0x40, false),
        (0x2B, false),
        (0x10, false),
        (0x08, false),
    ] {
        let disabled = bd_write && !board.bd_write;
        profiles.extend_from_slice(&[if disabled { 0xFE } else { 0 }, number, 0, 0]);
    }
    let mut out = Vec::new();
    let mut feature = |code: u16, version: u8, data: &[u8]| {
        out.extend_from_slice(&code.to_be_bytes());
        out.push(version);
        out.push(data.len() as u8);
        out.extend_from_slice(data);
    };
    feature(0x0000, 3, &profiles);
    feature(0x0001, 11, &[0, 0, 0, 7, 1, 0, 0, 0]);
    feature(0x0003, 11, &[board.medium, 0, 0, 0]);
    out.extend_from_slice(&[0x55, 0xAA]);
    out.extend_from_slice(b"UNIQUE1712061658");
    out.extend_from_slice(board.tag.as_bytes());
    out.extend_from_slice(b"      \0\0");
    out.extend_from_slice(&padded(board.platform, 6));
    out
}

/// Give `img` `board`'s boot banner, descriptor platform code and hardware
/// record. The caller signs the image afterwards.
pub(crate) fn stamp(img: &mut [u8], board: &Board) {
    let banner = mediatek_optical::layout::BANNER;
    img[banner.start..banner.end()].fill(0);
    img[banner.start..banner.start + board.banner.len()].copy_from_slice(board.banner.as_bytes());
    img[DESCRIPTOR_PLATFORM..DESCRIPTOR_PLATFORM + 6].copy_from_slice(&padded(board.platform, 6));
    let record = hardware(board);
    img[RECORD_AREA..RECORD_AREA + record.len()].copy_from_slice(&record);
}
