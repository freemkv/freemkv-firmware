//! Best-effort identification of the installed firmware.
//!
//! A live drive exposes, via `READ_BUFFER`, two firmware-code windows that vary
//! by build but not by physical unit: `rom_003000` (32 B) and `rom_1EC000`
//! (256 B, an ASCII descriptor carrying vendor/model/version/build-date). We
//! fingerprint them as `sha256(rom_003000 ++ rom_1EC000)` and match a built-in
//! catalog. (The per-unit calibration window `rom_1F0000` is deliberately NOT
//! part of the fingerprint — it differs between drives of the same firmware.)
//!
//! Cleanroom / legal note: this catalog holds only **hashes and descriptions**
//! (and, later, external download links). It never contains firmware binaries —
//! those are copyrighted OEM/MK images and are not redistributed here.

use sha2::{Digest, Sha256};

/// One known firmware build.
pub struct FwEntry {
    /// `sha256(rom_003000 ++ rom_1EC000)`, lowercase hex — the readable fingerprint.
    pub fp: &'static str,
    /// Human description, e.g. `"BU40N 1.03 (MK)"`.
    pub desc: &'static str,
    /// sha256 of the full 2 MiB image, to verify a downloaded original
    /// (`""` when not yet recorded).
    pub image_sha256: &'static str,
    /// Where to obtain the original image — a URL or note (`""` when none yet).
    /// Populated over time / by community contribution; binaries are never
    /// stored in this repo.
    pub source: &'static str,
}

/// Compute the firmware fingerprint from the two readable code windows.
pub fn fingerprint(rom_003000: &[u8], rom_1ec000: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(rom_003000);
    h.update(rom_1ec000);
    let digest = h.finalize();
    let mut s = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Look a fingerprint up in `catalog`.
pub fn identify_in<'a>(fp: &str, catalog: &'a [FwEntry]) -> Option<&'a FwEntry> {
    catalog.iter().find(|e| e.fp == fp)
}

/// Look a fingerprint up in the built-in [`CATALOG`].
pub fn identify(fp: &str) -> Option<&'static FwEntry> {
    identify_in(fp, CATALOG)
}

/// Extract the human-readable ASCII descriptor embedded at the start of the
/// `rom_1EC000` window (e.g. `"HL-DT-ST BD-RE BU40N 1.03 ... MT1959 ..."`), so a
/// drive whose fingerprint is not in the catalog can still show a version. Keeps
/// the leading run of printable ASCII, collapses repeated whitespace, trims.
pub fn descriptor(rom_1ec000: &[u8]) -> Option<String> {
    let ascii: String = rom_1ec000
        .iter()
        .take_while(|&&b| (0x20..=0x7e).contains(&b))
        .map(|&b| b as char)
        .collect();
    let cleaned = ascii.split_whitespace().collect::<Vec<_>>().join(" ");
    if cleaned.len() >= 4 {
        Some(cleaned)
    } else {
        None
    }
}

/// The result of identifying an installed firmware: the descriptor read
/// straight from the drive (works even for uncataloged firmware), the
/// fingerprint, and the catalog match (if any).
pub struct FwReport {
    /// ASCII descriptor read directly from `rom_1EC000` (vendor/model/version/…).
    pub descriptor: Option<String>,
    /// `sha256(rom_003000 ++ rom_1EC000)`, lowercase hex.
    pub fingerprint: String,
    /// The matching catalog entry, if the fingerprint is known.
    pub matched: Option<&'static FwEntry>,
}

/// Build a [`FwReport`] from the two readable regions.
pub fn report(rom_003000: &[u8], rom_1ec000: &[u8]) -> FwReport {
    let fingerprint = fingerprint(rom_003000, rom_1ec000);
    FwReport {
        descriptor: descriptor(rom_1ec000),
        matched: identify(&fingerprint),
        fingerprint,
    }
}

/// Built-in firmware catalog (hash -> description). Grows by contribution; the
/// fingerprint scheme and this table cover MediaTek MT19xx optical drives.
///
/// `image_sha256` / `source` are populated as they are recorded — an empty
/// string means "not yet known", not "none exists".
pub const CATALOG: &[FwEntry] = &[
    // ---- OEM builds of the embedded MediaTek catalog (oem.bin) ----
    FwEntry {
        fp: "576eeff21845aeb644f5428d9065dcc00e7ebaa336c51ede3b074543188ddf81",
        desc: "BC-12D2HT 3.01 (OEM)",
        image_sha256: "93ea068da225140d9628c105d88d13088982c61024bf6cca03e0fe456d53a721",
        source: "",
    },
    FwEntry {
        fp: "815989ae0f0fcf0d6f6c1e25a96de4172ce9c6e856d23b55ab942d7f918f454c",
        desc: "BE14NU40 1.00 (OEM)",
        image_sha256: "01c6a76a4d16c0c6b9aafa60ececccd331b73ac1a7f8b899b3f05e558c92c07c",
        source: "",
    },
    FwEntry {
        fp: "039716e5184c7ab02d8713d60b7fc9219b5ad8788f50b5b3971e328737431916",
        desc: "BE14NU40 1.01 (OEM)",
        image_sha256: "2f02308413c86c180ec863ada97fec3f594ebd7bf144e3159e91439518e57847",
        source: "",
    },
    FwEntry {
        fp: "5059cac4bb44a1d17ebea625d68d94ffef1f14fa53a233bc69fb0ed145b9545c",
        desc: "BE14NU40 1.01 (OEM)",
        image_sha256: "7ff91816c192f4c0ba492b507c8119fafb71df7a25118d0e456682bb34e2e567",
        source: "",
    },
    FwEntry {
        fp: "2a3eee2bc1e94657b7384a38915c986dfd55c0fb68e9352ddf6ad0316edb54fb",
        desc: "BE16NU50 1.02 (OEM)",
        image_sha256: "2b3ea41f87764ccc497059c9e362657df545fb169d6eeb2e78ccfbd7fafee533",
        source: "",
    },
    FwEntry {
        fp: "99f5d3e3d88150d2bb9e89d37e561677281e773e1e4d9ec1995a304273228734",
        desc: "BH14NS40 1.00 (OEM)",
        image_sha256: "d8ab861b6fefa847223a1a95b53241c9838953ac298ff068d9243fc31587df87",
        source: "",
    },
    FwEntry {
        fp: "7b4109fc142ed65bc27c1e424e057095a82fd8504a760ead0d17fe391060ef37",
        desc: "BH14NS40 1.01 (OEM)",
        image_sha256: "007ac6bfe4ea432c7d8e5b4bd1142a636abe452516e3cc36f67e4e13520fe40d",
        source: "",
    },
    FwEntry {
        fp: "619084959e9c043f5db691d0012bb48b3f961f872c352fb21a9887d6921fe6d1",
        desc: "BH14NS40 1.02 (OEM)",
        image_sha256: "6a96f7267ba605eb85ead6999944069eaa5fc19bd57dca5becd79aa1525aba6e",
        source: "",
    },
    FwEntry {
        fp: "b968f6b0c40f14c11233acf601b6521cdc597303371b7f82c7799245fb34981b",
        desc: "BH14NS48 1.00 (OEM)",
        image_sha256: "f1141a3295076c0d1a558e7ed396fee7709dc47f3ae277faed7068cd7ba66ce8",
        source: "",
    },
    FwEntry {
        fp: "4a076f76858f6ab1239c8df5046d04ccf10bf26ab0594e5e62f1cb6fb1f9a163",
        desc: "BH14NS48 1.01 (OEM)",
        image_sha256: "adfd807cde847ae75315b9083be29d287f56d8a628d171eaf59d6023ee266d1c",
        source: "",
    },
    FwEntry {
        fp: "491511d07eafead570d241a6e733dcb1a007bdeed09616a7295c9715b54a6515",
        desc: "BH14NS48 1.03 (OEM)",
        image_sha256: "3b8faae231f30afbdd3257d9cd2b7791a005a4616391ee0f8367dfa0db51abc3",
        source: "",
    },
    FwEntry {
        fp: "2a29e7062175244c74b68cac3947661b99f02e51e3a8fc209a22effa7567434f",
        desc: "BH14NS50 1.01 (OEM)",
        image_sha256: "4ef56002dd392733d15378e4535115f24ba891d3266a7c87420df14df0a7089d",
        source: "",
    },
    FwEntry {
        fp: "2b4d2e4c07582f581a7e4d5a3c4329782f3adfb371474fd7447de0ee367e04ea",
        desc: "BH14NS58 1.00 (OEM)",
        image_sha256: "53d2cdc32a2ae99864ec8fc4ea98a3a5218220aea990481f560112adaa871624",
        source: "",
    },
    FwEntry {
        fp: "02a410116a033fe6ce6feba9d823ca4312efcd2c48c5be15da73f6eac72ca452",
        desc: "BH14NS58 1.01 (OEM)",
        image_sha256: "eb0e2e7275448919aa72bec63ed0cd24ca360fcb0a8347601e85c2750f0d173a",
        source: "",
    },
    FwEntry {
        fp: "83ad13395ee7235f08820ebf33c74e6245a3843c1175f9e29258e8a0c3e4b8eb",
        desc: "BH16NS40 1.02 (OEM)",
        image_sha256: "acbe782ebc3c4850a24f852b8dc2ec42059f6b131e29d96157b09505628c415b",
        source: "",
    },
    FwEntry {
        fp: "59f4d9113af13e2aa8e1299a89cdd4bd4ab9cb4beb03bda23e6052cab8e67d65",
        desc: "BH16NS40 1.03 (OEM)",
        image_sha256: "b093a73656e58ee2a4367b5d92324fd7da3889f632a22b2f1be8802607cd3de4",
        source: "",
    },
    FwEntry {
        fp: "e988565c7565ffe50ee95e661696ace654c7f511a13657beec80a37fa595b422",
        desc: "BH16NS40 1.03 (OEM)",
        image_sha256: "a5bb75b8dbec1684e596f473aa53905f9f723b2b2f9c448550cb523145f90dd3",
        source: "",
    },
    FwEntry {
        fp: "9a3bce7415fdf71b28daf7d08f9f6fc8a8bdf4ae74d4e3c8e40624c4d0aa4d67",
        desc: "BH16NS48 1.01 (OEM)",
        image_sha256: "163fb6e0057d74f38e046cf9042981c137ec70c1aaa2d7b1c3ee1a62324aa146",
        source: "",
    },
    FwEntry {
        fp: "f1a17f87e06f1f8d9f403aba5827ee51c75fb0c4d4e3b59ceb02b341e20647ec",
        desc: "BH16NS48 1.02 (OEM)",
        image_sha256: "43c484dccc37ccb36183e970c5a4f28e90d6ccb530c0efd3bd8f96943ba7dfe3",
        source: "",
    },
    FwEntry {
        fp: "86b62cb0936dce24b843c8567d902f402d3af00af6cc9984373e5f951e9b2c86",
        desc: "BH16NS50 1.01 (OEM)",
        image_sha256: "b7a368da0fcbe905e45a09c6523bdd6f80557ce455272238c73868aa4ae4bd41",
        source: "",
    },
    FwEntry {
        fp: "7d000be12b81099f609f978a9e41e596865efe3f48b5f36376292f7688f3c1b2",
        desc: "BH16NS55 1.03 (OEM)",
        image_sha256: "0bfdd3009ed1bc246f81aae50cfd9a5e4919c5295263e488c2a900500fe48728",
        source: "",
    },
    FwEntry {
        fp: "bf66b9e62ff8535a32256d03070f9feeaf50b42fc97e41fb06beaa28d71b608f",
        desc: "BH16NS58 1.00 (OEM)",
        image_sha256: "6d9fdb2bd658165a073e6144c8938057e08d8cba7ca108274b120dd30c55328f",
        source: "",
    },
    FwEntry {
        fp: "bfa7812aa8b78f157f6638514e7f93e7f7716f1e88597c0cc2acb8cd332d42a5",
        desc: "BH16NS58 1.01 (OEM)",
        image_sha256: "ccc97e4f92e47b6fc1fab1e9baa1860020c7f104efa9ffb649321a173523adfb",
        source: "",
    },
    FwEntry {
        fp: "785270842397d2d0e0c74ced8b3334ff5853f5a5321c6330bc097644d055b07e",
        desc: "BH16NS58 1.02 (OEM)",
        image_sha256: "4f4e63cd5988f68f5729af21fe4033d0da2eeeec8f7576772f0f3a197f8eda21",
        source: "",
    },
    FwEntry {
        fp: "6215e7260aaadc0d84c104596ed8176644381e90b8bdf269a77b048caa05d5ca",
        desc: "BH40N B7C6 (OEM)",
        image_sha256: "0b2cdb82ff520589d4c750fae726571798901bf41e433de0a7164f7d74927d5f",
        source: "",
    },
    FwEntry {
        fp: "0e51a92e403eb6255beb4f4ccda26c133430372adffa897b3a2afc6a942b4377",
        desc: "BP50NB40 1.00 (OEM)",
        image_sha256: "c88a69013d557b9c4cf1a4d603c314585f51a258b9747c345184e866eef36306",
        source: "",
    },
    FwEntry {
        fp: "d9a6152a9a43b269b8481a4633cd97df606e1525884528be6fe0c3747bb2f6fb",
        desc: "BW-16D1H-U A203 (OEM)",
        image_sha256: "e9d8bcddf85aab6627c90623efcb7a39ee97681a68b729ef58fea391bc99b33a",
        source: "",
    },
    FwEntry {
        fp: "ac48ad00da8a2498b882549b3ba178b1605263a3baf28862f900890895666056",
        desc: "BW-16D1HT 3.01 (OEM)",
        image_sha256: "2e243a167739d4e46ad7095db7cb5452c2980579a0cb359208945a0bbe0f3f29",
        source: "",
    },
    FwEntry {
        fp: "e7d47927afe53b946a848742c03408b0516cd0c54592ac5ac3ae77430b7796f6",
        desc: "BW-16D1HT 3.03 (OEM)",
        image_sha256: "1d57260bf091dc89b6ab5b3e2cc7aa1b843d89227a3a4811e6244eaba353b764",
        source: "",
    },
    FwEntry {
        fp: "b14cde46956e90c6fed16bcc0e1dd5c56c90980053377bd4b54741d9e71a4834",
        desc: "BW-16D1HT 3.10 (OEM)",
        image_sha256: "37a32bfd708b86c825877364d7e52c943d0a856ec3e5457953b61b7fa1c9a23f",
        source: "",
    },
    FwEntry {
        fp: "e3159083ea755d3965a84c933c45f8c8f31b070db1787fe2479c2ab1a1d371f5",
        desc: "CH12NS40 1.01 (OEM)",
        image_sha256: "731bcf7aa48dacbcb5729f97576cf24b90d7a795a330c2ab8a801c57eb738f0e",
        source: "",
    },
    FwEntry {
        fp: "6b78278f35c9a7d96637ea98ae836512da485fd271981d9bf61facdd527da1e2",
        desc: "UH12NS30 1.01 (OEM)",
        image_sha256: "84fecc2930d63cd4da8aa4759f63550d1eb1a642343d29adf1e370a2a861347e",
        source: "",
    },
    FwEntry {
        fp: "4561b79e2a2e6712004f3f0b41c74838f08ff46f3e568fdc9106d29e5fe3bb7c",
        desc: "UH12NS30 1.02 (OEM)",
        image_sha256: "d98c2e11f400cf54133289369f19064ccabc72c69ef189f9129fc19b2d700cc8",
        source: "",
    },
    FwEntry {
        fp: "6dd823c0d3719efa78e937993937100c620cd35ef8ecbf6c977fc2b1d11d8609",
        desc: "UH12NS40 1.01 (OEM)",
        image_sha256: "fbe641e5e808e8127c0196e28bc8a10ba9d8ae61bd8645affff9f259b4a6b25c",
        source: "",
    },
    FwEntry {
        fp: "409b09a6020bcf4e3fff1ce85442b6ab2c8d932cc3c927d43e1fdc2c50c84f69",
        desc: "WH16NS40 1.01 (OEM)",
        image_sha256: "7af021b026f8aef225b2211183885be211a66c1a4d64c9dad5c84661586144c7",
        source: "",
    },
    FwEntry {
        fp: "040de4a2cf04dd429e13ee70f54791e163dc05540a1cdcaea6a1be2cbc3b4683",
        desc: "WH16NS40 1.02 (OEM)",
        image_sha256: "1368766f8d384d0c86d4803d057b7aa1ca205542b9b6b0580e875aaa8bd015b3",
        source: "",
    },
    FwEntry {
        fp: "e8bcc7a46c2909d2b93bc79066f19cce06e7b85e4f462b61e2426332ed72ba83",
        desc: "WH16NS40 1.03 (OEM)",
        image_sha256: "3e3b227e1338b5bc601ad6b2ce02fd1d375b7ea6179b055412ea0702ce54615c",
        source: "",
    },
    FwEntry {
        fp: "68a08b026f85e0feb639fc3a816287c273123f743941cefabf189515b9ec0e77",
        desc: "WH16NS48 1.D3 (OEM)",
        image_sha256: "46b41f15e053b66daccb024cba4380c45f791c2d0c2b8258cd23253fc5f0b22a",
        source: "",
    },
    FwEntry {
        fp: "17664e2c1453b9cbaf52f0f21c8518fec7f241545676328c7f0b502403fe666d",
        desc: "WH16NS58 1.V1 (OEM)",
        image_sha256: "4041c0f122a902288ca8439888f68f7760616a0a37c366b825d6497b51157e46",
        source: "",
    },
    FwEntry {
        fp: "2a3ab353f2855787305b954b35fc38e723996a073e29d936c1b3ba4ccc510f22",
        desc: "WH16NS58 1.V2 (OEM)",
        image_sha256: "3018997b63cc9a2f31618fd9b6b5c6bfe0cc921b891f4a80ac08ae3ef2b16504",
        source: "",
    },
    FwEntry {
        fp: "7afb5b9179dd2b48cadea8c8bdff0ebbba0c0ec4ef1ad44b6dcd88d3e686fdf5",
        desc: "WH16NS58 1.V5 (OEM)",
        image_sha256: "e24060184915a9860a84ea7d0ad23fee478e6eb31af86da589f5723c8e29a1cd",
        source: "",
    },
    FwEntry {
        fp: "a7c3f30e41a30d659e29d9354b52dfcad88c39fa12de4a522e0e94e26529b7ff",
        desc: "WH16NS60 1.01 (OEM)",
        image_sha256: "aea98763cad71e8cfbd8d32963a63adf429e889bd13b749e7c4a792cc5b076a2",
        source: "",
    },
    // ---- ASUS / TSSTcorp (MediaTek MT19xx) ----
    e(
        "001cb2b2299cf9b8e47bead095f7cf5074ff15843e86dbfb1b6d2d7ee8c4966d",
        "BC-12B1ST 3.01 (OEM)",
    ),
    e(
        "603592c11281f2a33db39b1752f48a52f156a2f77ecdf99d087e32dec02e1a59",
        "BC-12B1ST 3.11 (OEM)",
    ),
    e(
        "9923d279c7c254a2079bbc044b21c95bae5eaa12ffbf84cc0626b0004ba7e1ce",
        "BC-12D2HT 3.11 (OEM)",
    ),
    e(
        "ed7af8710842372edc4d810fb767e840b3a40997f6906bb9e74d0f705bad9e1d",
        "BW-16D1HT 3.02 (OEM)",
    ),
    e(
        "b75b2958999a547adc58f4d6072035f067a57a1810deca36383a8619039b45d9",
        "BC-12B1ST 3.01 (MK)",
    ),
    e(
        "9c6c98824cd012d7f4c5e847593947db6a98599d9e0f0d96ffa19e99684f0fbf",
        "BC-12B1ST 3.11 (MK)",
    ),
    e(
        "97c380003421100329a3cf40d8510d4dba09874b854bfbaf7d80cfaedfab35aa",
        "BC-12D2HT 3.01 (MK)",
    ),
    e(
        "c4d5d7f94363c0af4ce0275a6458d78d1d029861176a6ddb663827550e443183",
        "BC-12D2HT 3.11 (MK)",
    ),
    e(
        "ff527882bcb481f77ab99cf5595560828f3d234b3393133800b5eca81cc35971",
        "BW-16D1H-U A203 (MK)",
    ),
    e(
        "d97544be073eb9460a9750bdb8eef53813f44661b962b83d4f4dfe848975f5af",
        "BW-16D1H-U A204 (MK)",
    ),
    e(
        "93353dc63908739ea22908f75de5fed7e74a1be7a78fdf69cc617d6f4b92dd79",
        "BW-16D1HT 3.03 (MK)",
    ),
    e(
        "0837d9c0591f2be504afa3a5df8f894b1daeead8a7fc294f456260174fa7bdb0",
        "BW-16D1HT 3.10 (MK)",
    ),
    e(
        "b9adb37a560d11be91c2f92b27d62eedf80fb3080be6a092f5e2f2787b3c1fe8",
        "BC-12D2HT 3.00 (DE-patched)",
    ),
    e(
        "d88e939f89a78b0e3f4b514b1758a60e66e6f873c6765cefa9665d7150159b30",
        "BW-16D1HT 3.02 (DE-patched)",
    ),
    e(
        "d36c2cf1157c957870def87aa0c84dc07a6e2459b5c326727e37ff9d8c539a19",
        "BW-16D1HT 3.01 (OEM)",
    ),
    e(
        "03143f9d2259efac874f5d0bc8a08245308449782ef5ec3230cb251873f4ad45",
        "TS-LB23L 0600 (OEM)",
    ),
    // ---- LG / HL-DT-ST (MediaTek MT19xx). BU40N 1.03 (MK) is the flash-tested reference. ----
    e(
        "00ef88eea527316b240addada947e791555f6d182fbe84fc246ede076fb37e82",
        "BU40N 1.03 (MK)",
    ),
    e(
        "0bab74123cab0e69ec1b41f4b948cc81059a4a3a1440ed7da603b0d6412d6422",
        "WH14NS40-NS50 1.03 (MK)",
    ),
    e(
        "10a0512420d5c326d7132d2ba23719e17f59bdf12a5954df1d1c647d871a9c46",
        "WP50NB40-NB50 1.01 (MK)",
    ),
    e(
        "1198a0b27e2a69b8a2779c7e0c751483d543a37a8df6a0c6311ebb1e1365bd2e",
        "BP55EB40-NB50 1.01 (MK)",
    ),
    e(
        "16f00db68518726017751c2c31da5c075bd6f17b62d93ae790352f8435e0c480",
        "WH14NS40 1.01 (OEM)",
    ),
    e(
        "186c2f33b16f8029d380369e1cec6e0d3f30373f56a0e451a491e60146cc70ef",
        "BH16NS60 1.00 (MK)",
    ),
    e(
        "1bb595f75a966f2e3fc65077f9df21f9c6dce368c7dd51c8f6b9c8e03544e008",
        "BU40N U100 (MK)",
    ),
    e(
        "1c76d6e7c5c1835335653fd0996b6ca40b57f2d74c8ba83d71fbe17965b831d9",
        "WH16NS60 1.03 (MK)",
    ),
    e(
        "2171f74f6c40116e3a3c6ab437160c2ebebbaf042db037e7ac16bc8596d7ca7f",
        "BU40N BN12 (MK)",
    ),
    e(
        "226c4c5ad785e7f6c72b4592c428acb98107adbdc038b0e5a696f7ac1afa995f",
        "BU50N BW51 (OEM)",
    ),
    e(
        "277779c0834f0881e95ac78dbb05d57cc8cb61b87966abc5328866be7f2e42a0",
        "WH16NS40-NS50 1.03 (MK)",
    ),
    e(
        "2c80543a03e3f7700092bad51ce6b6c46e9c91310b3b11263ba33587f9e05927",
        "BH16NS40-NS50 1.05 (OEM)",
    ),
    e(
        "2ea58d0f0bd594f7d6243753610e8dbeab2c468fb7549bf2eab999ec02d2ec5b",
        "BH14NS58 1.01 (MK)",
    ),
    e(
        "30244f0bba5102f2bb2f1915ba336eda86e106d96f53c9645a3666a9ede671a1",
        "BH16NS40 1.00 (OEM)",
    ),
    e(
        "303b60a551c7e6b533fc738f2ec540ce76e5ccfc24c0e126032c00c8ff1c9155",
        "BH16NS50 1.03 (MK)",
    ),
    e(
        "33103a054031024734580c251a109d87e2427611c35eb3c727f1961dc17239e6",
        "WH14NS40 1.03 (OEM)",
    ),
    e(
        "3e05d733d37435921dc4400c7d1a65641e0c693bed6fef8bf3e6156fb67d3492",
        "BH16NS40-NS50 1.02 (DE-patched)",
    ),
    e(
        "3f0276d36cab2a12ea6d10cee3cff943a171b2e2c0abca4786bbaa255c7004b0",
        "WH16NS60 1.00 (OEM)",
    ),
    e(
        "3fa4a653c60b2851932df3730481cac8d5abfb9f9b640838e79be2d99f0e7461",
        "BU40N BW41 (OEM)",
    ),
    e(
        "4085730ec3a30c94b15864b6595a142f000096f0288129b58726ffe29f2b814e",
        "BH16NS60 1.02 (MK)",
    ),
    e(
        "41baece3ed4245b30ab08d1fe8743f5af999817821aa127939d4b4c6b6934f6b",
        "BU40N 1.00 (DE-patched)",
    ),
    e(
        "420e357a39b26abbceb5937b8b2a6679920f85d43d8e2afda5b27b1eaa6bb8a3",
        "BH16NS58 1.01 (MK)",
    ),
    e(
        "429b889ec927c28553016d8cd5b0909da67a9b0f4eeae424dcac2da19056c0eb",
        "BH16NS40-NS50 1.04 (MK)",
    ),
    e(
        "4f6b0f0e1b220b6c5cb63a2acf12ea6db2413960293e58a7b7c1d6a1465679ee",
        "BH16NS50 1.01 (MK)",
    ),
    e(
        "4f9d05e048454bc06bd23d265b77b7dd2daf45034fdbad5b79aed05605ef1d2e",
        "BH16NS40-NS50 1.05 (MK)",
    ),
    e(
        "500836fb82f0e7b253dbb18984c96a351b734f5b0e78793a8d18f8f1d822dbb8",
        "BU40N 1.01 RM01801 (MK)",
    ),
    e(
        "502efb3b530635048216af742f2ea1eef9bcac6ffeaa5cdd58f5fc9c1b41b27c",
        "BE16NU50 1.04 (MK)",
    ),
    e(
        "56fa9b33425cf60b1180cf11d16db49b2ebab35928c404bc1bd930e0e8b19d48",
        "BP60NB10 1.02 (MK)",
    ),
    e(
        "5965bf6ce555c3bec210f0c9f4e15d286a262f2222e856a21035dd2a673fcc61",
        "BP50NB40 1.03 (OEM)",
    ),
    e(
        "59d4fb0d5ed20b4a9c15a78e1b67bfc824b9febb6bc8b4fe7b873c48c1390209",
        "BU40N 1.04 (OEM)",
    ),
    e(
        "6039f036648e36c7b0770072095e178f6d13084651191d1b034d6eaffff2b4f4",
        "BU40N BW42 (OEM)",
    ),
    e(
        "605692def84a83af64d4bf38c49493ef9c12cb0333e899dfeee0fd8c0a01ed18",
        "BH16NS55 1.03 (MK)",
    ),
    e(
        "60ecbf4cf82adde5ef545ff7aa580c510e081510eaefb77caa7b62d562a6512a",
        "BU40N 1.02 (MK)",
    ),
    e(
        "6237b5e02478bff07b01e424b0942dd52cfb75e75f227a092a052498b0008a1d",
        "BU40N 1.02 (OEM)",
    ),
    e(
        "64a047c27de418f7744e7cd4981c60034e6b1ef231f1c80e46fabc8accf1dfd1",
        "WH16NS58 1.V5 (MK)",
    ),
    e(
        "6991612bc0ac9dedd968f1a48dbdaf5a6c7e8cd65908cbeb51a8bd67af81b6c6",
        "BP60NB10 1.01 (MK)",
    ),
    e(
        "6e9f7454054fe598f4ae99a4a8c920dfa6fa6c095c71a33e893ea960c11d24e1",
        "BU40N R1.01 (OEM)",
    ),
    e(
        "748e0ed15d4e3a626c5d944300e4b0d0399f8b4df60c50be4d20fa9665d9ccb1",
        "BU40N U101 (MK)",
    ),
    e(
        "75c0d7757a80082568080c9e1fe153ccb7c49a2e8e6ef615f7f6650c5c2f5b1e",
        "BE16NU50 1.04 (OEM)",
    ),
    e(
        "83dcde76835425ef8402b15f2f640350c7fc44109ae4d33e7bbfb546822c4367",
        "BU40N BN11 (MK)",
    ),
    e(
        "8426fdf3c007b28f017c175c751c4ed999cdb6ba206105e021d6973b43e57b39",
        "BH16NS40-NS50 1.03 (MK)",
    ),
    e(
        "858c401a01297ff13434c467fc3ad7ee5e41436fcade7000daf7af5e7dd75b05",
        "BH16NS40 1.02 (OEM)",
    ),
    e(
        "8a147bab2a80c1e9512cf687da40bbb164e55e2b4861a4433b6d3916465e16a7",
        "BH16NS40 1.01 (OEM)",
    ),
    e(
        "8d61a5f00692f9e1a4e5461d7cb411997e711448fdf875e8a51157033be9b534",
        "CH12NS40 1.03 (MK)",
    ),
    e(
        "8d9555bcd92ee694761ba4e973512df0ac7adc2f713caa5f9ecf8f28a793f9d5",
        "WH16NS60 1.02 (MK)",
    ),
    e(
        "90a568378c2bc0d0fa856a9612d30180839f649d0e2deca73999947f7401060e",
        "WP50NB40 1.01 (OEM)",
    ),
    e(
        "92a77c37896bc72144b8189f3b549398d25023470a0304ba29d9d767b3d90e56",
        "WH14NS40 1.02 (OEM)",
    ),
    e(
        "94c8edfadb46606733b7d1d1823159cd912dfa2b6dc1ac221ddaf0342ecd7ed4",
        "BH16NS60 INTM (OEM, WH16NS60 1.03 flasher)",
    ),
    e(
        "960b32ddc0b3f596854b6caeb94f99944e4fcb9fcf8a9f861c3499b9c918ecff",
        "BH14NS50 1.01 (MK)",
    ),
    e(
        "9691ea80fe4d387abaa8dc7b1b2645f01fd5971e180e3fea0249c7100b034ca8",
        "WH16NS40-NS50 1.05 (MK)",
    ),
    e(
        "99c2bbe1396d753ab305d49c2ab2cdae834d7b10c92fb7321ceece06d62255d5",
        "BU50N 1.00 (MK)",
    ),
    e(
        "9cb7289b62a7db77d894689d065c9aea1b211c3f7c6b0fb1e818a601441680df",
        "WH14NS40-NS50 1.05 (MK)",
    ),
    e(
        "9dfed35aa4d0d5686fc13e3b0fa7bd7dc01f9597ccd3359b99d0ffcab21b9869",
        "BH16NS40 1.03 (OEM)",
    ),
    e(
        "a203f6c8afc9f707b8ca346de0592c52600547c5aee93c6d4118cf960baf8a98",
        "BH14NS50 1.03 (MK)",
    ),
    e(
        "a2a6c18e5ead18113afb8feb8417f801dbc603066a0581c6c95029df1cc5db42",
        "BP50NB40-NB50 1.01 (MK)",
    ),
    e(
        "a7d6e0730efa4b78a1ae68da1b43478b2d256c61b55ca3dd79a658c860dbc9b1",
        "WH14NS40-NS50 1.04 (MK)",
    ),
    e(
        "ac2366cc8ae8e8eda23c7cd7b91ff9401571e1fc092f286ee0b9e2475b80dafd",
        "BU40N FR07 (MK)",
    ),
    e(
        "b456a320e38cb5b5f7776b8b668a22d07472fa77acd29adc2fca80e034fda857",
        "WP50NB40-NB50 1.03 (MK)",
    ),
    e(
        "b6ff13a99b65e5fa5646dc72162a1ba2e1b086a5b92eb69d99918d1582e083d6",
        "WH14NS40 1.00 (OEM)",
    ),
    e(
        "b89b57c8bde176bfa5713633c9c5100093f885769aca6e3bef6df56993fe1ca1",
        "UH12NS40 1.03 (MK)",
    ),
    e(
        "bfb933167bcc6e125e52fdd4707a00d1b7d6722f6d740fc1873a2f3350c0f041",
        "BU40N BU12 (MK)",
    ),
    e(
        "c1868b770aa8d1223d1163648e08d04e91058f4b4084273dec8060b5cfe9179c",
        "UH12NS40 1.01 (MK)",
    ),
    e(
        "c45795ee4592b1ed7e837ece59e05fc439a55fc5b9569eb4988c318ead0fb52d",
        "CH12NS40 INTM (OEM)",
    ),
    e(
        "c8876a74685a425995f5c43c26145b623557124666df93b451e336cd3930e00a",
        "BP50NB40 1.01 (OEM)",
    ),
    e(
        "c8a8c8161f30c7cafceac01f4a227af46b90d84f5835dcd2b2ae24f6fbeb6ec7",
        "CH12NS40 1.01 (MK)",
    ),
    e(
        "c991f5e70112cbdbab6302fa4e836b52ed403b2490a1fee5919ae4ca8de6d0ee",
        "BP55EB40-NB50 1.03 (MK)",
    ),
    e(
        "d3399c861751ac3113130ba46a682d206e3a64a12e897c90cb9d4393d9db24f9",
        "BE16NU50 1.01 (OEM)",
    ),
    e(
        "d3c8e06ff8419ffd9bff07a01f8915c5e731cf59ca9c3980a818d70cd63bbc0f",
        "WH16NS40-NS50 1.02 (DE-patched)",
    ),
    e(
        "d62cf2c04c40ab28143764163daddbcdd6a8fe0a80bca4393d691ac53d487b3d",
        "BP60NB10 1.00 (OEM)",
    ),
    e(
        "d633667aefe902a91243b1924a5d54e1a70c3bf46aebab86a8f938d2eaddeb69",
        "BP60NB10 1.00 (MK)",
    ),
    e(
        "d636058e9ae61a30e083d2456ef5a88acaf0f264b2bde9277ece495c2f8000f4",
        "BP50NB40-NB50 1.03 (MK)",
    ),
    e(
        "e02261a177377b288e4678f870a9850e9f80314fc96397ddb5d6794ac9c58b13",
        "WH14NS40-NS50 1.02 (DE-patched)",
    ),
    e(
        "ec7196b1b0a94e0dc2a184b2f31afef73f580d8ee3b307c173697e7e60165d2f",
        "BH16NS55 1.05 (MK)",
    ),
    e(
        "ecf3549955975cf097f83cc2a6ff278319aadd7a9aacb29821d8b3160495e0d5",
        "BU40N 1.01 RM00000 (MK)",
    ),
    e(
        "f41749d1a55070d91fb55ab482b344e2b21b826015d1732ba0a6385bb9eede6e",
        "BP50NB40-NB50 1.02 (MK)",
    ),
    e(
        "f479cf997d056af7bf8c8851863a382ecfe077bef9c1cdd1150a54a555811a7c",
        "BH16NS55 1.02 (DE-patched)",
    ),
    e(
        "f7fcf70d896f6a406c9ae2d350bb33bd8ca50103a13b56921c962143498fa6c3",
        "BE16NU50 1.02 (MK)",
    ),
    e(
        "f9c4c07204980c9525d4b0e9ff41bab7951659dd1edd81137733db206b902862",
        "WH16NS60 1.01 (MK)",
    ),
    e(
        "fa8868f4799a55329291b9705d3948ab26209317bf23b206069d3e933e03d916",
        "BP55EB40-NB50 1.02 (MK)",
    ),
    e(
        "fc4438b3528402ce5479cab80dc9d8ac9ca28f6cf200e06d93c6797f76b2c208",
        "BH16NS55 1.04 (MK)",
    ),
    e(
        "fc961c5a8fde372cc5099c2d28b1cd2ee4b93f55618edaf6cff038fc70abc5c2",
        "BU40N 1.04 (MK)",
    ),
];

/// Concise catalog-entry constructor (image_sha256 / source recorded later).
const fn e(fp: &'static str, desc: &'static str) -> FwEntry {
    FwEntry {
        fp,
        desc,
        image_sha256: "",
        source: "",
    }
}

#[cfg(test)]
#[path = "fw_ident_tests.rs"]
mod tests;
