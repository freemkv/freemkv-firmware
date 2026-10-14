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

/// A signed update image for `board` and `model` with the catalog's stored
/// boot page and one active integrity range, `0x11000..=0x1FFFF`.
pub(crate) fn image(board: &Board, model: &str, code: u8) -> Vec<u8> {
    use mediatek_optical::image::cmac;
    use mediatek_optical::layout;
    let mut img: Vec<u8> = (0..layout::IMAGE_SIZE)
        .map(|i| (i % 251) as u8 ^ code)
        .collect();
    let boot = super::oem::catalog()
        .default_for(mediatek_optical::Chip::Mt1959)
        .expect("a stored boot page")
        .boot_page()
        .to_vec();
    img[..layout::BOOT_PAGE.len].copy_from_slice(&boot);
    let d = layout::DESCRIPTOR.start;
    img[d + 0x08..d + 0x18].fill(b' ');
    img[d + 0x08..d + 0x08 + model.len()].copy_from_slice(model.as_bytes());
    img[d + 0x34..d + 0x3E].copy_from_slice(board.tag.as_bytes());
    stamp(&mut img, board);
    let t = cmac::TABLE_OFFSET;
    img[t..t + cmac::ENTRY_COUNT * cmac::ENTRY_SIZE].fill(0xFF);
    img[t..t + 4].copy_from_slice(&cmac::ENABLED.to_le_bytes());
    img[t + 4..t + 8].copy_from_slice(&0x1_1000u32.to_le_bytes());
    img[t + 8..t + 12].copy_from_slice(&0x1_FFFFu32.to_le_bytes());
    cmac::resign(&img).expect("a well-formed integrity table")
}

/// `img` with its hardware record's marker cleared, re-signed: an image that
/// names its chip but no hardware family.
pub(crate) fn without_record(img: &[u8]) -> Vec<u8> {
    let mut img = img.to_vec();
    let at = RECORD_AREA
        + img[RECORD_AREA..RECORD_AREA + 0x100]
            .windows(8)
            .position(|w| w == b"\x55\xAAUNIQUE")
            .expect("a stamped record");
    img[at] = 0;
    mediatek_optical::image::cmac::resign(&img).expect("a well-formed integrity table")
}

/// The live identity of a drive running `image`, as the plan reads it.
pub(crate) fn identity(image: &[u8]) -> mediatek_optical::Identity {
    use mediatek_optical::layout;
    mediatek_optical::Identity::parse(
        &[0; mediatek_optical::INQUIRY_LEN],
        layout::BANNER.of(image).unwrap(),
        layout::DESCRIPTOR.of(image).unwrap(),
    )
    .unwrap()
}

/// One build of the embedded OEM catalog, as `oem.bin` records it.
pub(crate) struct CatalogBuild {
    pub model: String,
    pub revision: String,
    pub family: String,
    pub hardware: String,
    pub boot: Vec<u8>,
    pub regions: Vec<Vec<u8>>,
}

impl CatalogBuild {
    /// The descriptor vendor; see [`vendor_of`].
    pub(crate) fn vendor(&self) -> &'static str {
        vendor_of(&self.model)
    }
}

/// The descriptor vendor of a catalog model. `oem.bin` records none; the
/// real-image test checks this against every catalog build in the corpus.
pub(crate) fn vendor_of(model: &str) -> &'static str {
    if model.starts_with("BW-") || model.starts_with("BC-") {
        "ASUS"
    } else if model.starts_with("BDRE ") {
        "hp HLDS"
    } else {
        "HL-DT-ST"
    }
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

/// Every build of the embedded OEM catalog.
pub(crate) fn catalog_builds() -> Vec<CatalogBuild> {
    use std::io::Read;
    let gz = include_bytes!("oem.bin");
    let mut json = String::new();
    flate2::read::GzDecoder::new(&gz[..])
        .read_to_string(&mut json)
        .unwrap();
    let table: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(table["family_scheme"], "mediatek.hardware.v1");
    let blob = |digest: &serde_json::Value| {
        unhex(table["blobs"][digest.as_str().unwrap()].as_str().unwrap())
    };
    table["builds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| CatalogBuild {
            model: b["model"].as_str().unwrap().into(),
            revision: b["revision"].as_str().unwrap().into(),
            family: b["family"].as_str().unwrap().into(),
            hardware: b["hardware"].as_str().unwrap().into(),
            boot: blob(&b["boot"]),
            regions: b["regions"].as_array().unwrap().iter().map(blob).collect(),
        })
        .collect()
}

/// The board a catalog hardware key describes.
pub(crate) fn board(key: &str) -> Board {
    let field = |name: &str| {
        key.split('\x1f')
            .find_map(|f| f.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("{name} in {key:?}"))
    };
    assert_eq!(field("iface"), "00000007", "{key:?}");
    let leak = |s: String| -> &'static str { Box::leak(s.into_boxed_str()) };
    let digits = &field("chip")[4..];
    Board {
        tag: leak(format!("MTEKMT19{digits}")),
        banner: leak(format!("MT19{digits} Boot {}", field("loader"))),
        platform: leak(field("platform").to_string()),
        medium: u8::from_str_radix(field("medium"), 16).unwrap(),
        bd_write: field("bdwrite") == "1",
    }
}

/// A signed image carrying `build`'s vendor, model, revision, hardware record
/// and factory contents (the catalog holds no code bytes).
pub(crate) fn stand_in(build: &CatalogBuild, seed: u8) -> Vec<u8> {
    let mut img = image(&board(&build.hardware), &build.model, seed);
    let d = mediatek_optical::layout::DESCRIPTOR.start;
    img[d..d + 0x08].copy_from_slice(&padded(build.vendor(), 8));
    img[d + 0x18..d + 0x1C].copy_from_slice(&format!("{:<4}", build.revision).as_bytes()[..4]);
    img[..0x400].copy_from_slice(&build.boot);
    for (range, contents) in mediatek_optical::layout::DRIVE_WRITTEN
        .iter()
        .zip(&build.regions)
    {
        img[range.start..range.end()].copy_from_slice(contents);
    }
    crate::cmac::resign(&img).unwrap()
}

/// Every catalog build with its stand-in image, whose family is the one the
/// catalog records.
pub(crate) fn stand_ins() -> Vec<(CatalogBuild, Vec<u8>)> {
    let builds = catalog_builds();
    assert_eq!(builds.len(), 69, "catalog size");
    builds
        .into_iter()
        .enumerate()
        .map(|(i, b)| {
            let image = stand_in(&b, i as u8);
            let family = mediatek_optical::image::family(&image).map(|f| f.to_string());
            assert_eq!(family.as_deref(), Some(b.family.as_str()), "{}", b.model);
            (b, image)
        })
        .collect()
}

#[test]
fn stamped_boards_have_their_families() {
    for (board, family) in [
        (BU3, "309829e6c3c8f31d"),
        (JB7, "11e7527216405467"),
        // JB8's banner is "MT1959 Boot JB8", so it is now MT1959 (the tag is the
        // stale MTEKMT1939 label) and its family hash flips accordingly.
        (JB8, "336e449ab6a827e3"),
    ] {
        let mut img = vec![0x11u8; mediatek_optical::layout::IMAGE_SIZE];
        let d = mediatek_optical::layout::DESCRIPTOR.start;
        img[d + 0x34..d + 0x3E].copy_from_slice(board.tag.as_bytes());
        stamp(&mut img, &board);
        assert_eq!(
            mediatek_optical::image::family(&img).map(|f| f.to_string()),
            Some(family.to_string()),
            "{board:?}"
        );
    }
}
