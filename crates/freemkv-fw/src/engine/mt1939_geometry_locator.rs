//! Instruction signatures and connected source operands for classic geometry.
//! No firmware identities or absolute firmware/RAM addresses select a match.
use super::super::mt1939::masked_matches;
use anyhow::{ensure, Context, Result};

fn half(data: &[u8], pc: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        data.get(pc..pc + 2)
            .context("geometry instruction bounds")?
            .try_into()?,
    ))
}
fn literal(data: &[u8], pc: usize, register: u16) -> Result<u32> {
    let op = half(data, pc)?;
    ensure!(
        op & 0xff00 == 0x4800 | register << 8,
        "geometry literal register"
    );
    let pool = ((pc + 4) & !3) + usize::from(op & 255) * 4;
    Ok(u32::from_le_bytes(
        data.get(pool..pool + 4)
            .context("geometry literal bounds")?
            .try_into()?,
    ))
}
fn ram(value: u32) -> Result<u32> {
    ensure!(
        (0x01ff0000..0x02030000).contains(&value),
        "geometry RAM operand"
    );
    Ok(value)
}
fn target(data: &[u8], pc: usize, mnemonic: &str) -> Result<usize> {
    let ins = thumb_asm::isa::decode_at(data, pc).context("geometry branch decode")?;
    let decoded_name = if mnemonic == "bne" { "b" } else { mnemonic };
    ensure!(
        ins.mnemonic == decoded_name,
        "geometry branch kind at {pc:x}"
    );
    if mnemonic == "bne" {
        ensure!(
            half(data, pc)? & 0xff00 == 0xd100,
            "geometry branch condition"
        );
    }
    if mnemonic == "b" {
        ensure!(
            half(data, pc)? & 0xf800 == 0xe000,
            "geometry unconditional branch"
        );
    }
    let target = ins.branch_target().context("geometry branch target")? as usize;
    ensure!(
        target < data.len() && target & 1 == 0,
        "geometry branch bounds"
    );
    Ok(target)
}
/// Only literal displacement and explicitly declared branch fields vary.
fn find(data: &[u8], code: &[u16], lo: usize, hi: usize) -> Vec<usize> {
    let pattern: Vec<_> = code
        .iter()
        .map(|&op| {
            if op & 0xf800 == 0x4800 {
                (op & 0xff00, 0xff00)
            } else if op == 0xf000 || op == 0xf800 {
                (op, 0xf800)
            } else if op & 0xff00 == 0xd100 || op == 0xd400 || op == 0xd500 {
                (op & 0xff00, 0xff00)
            } else if op == 0xe000 {
                (op, 0xf800)
            } else {
                (op, 0xffff)
            }
        })
        .collect();
    masked_matches(data, &pattern, lo, hi.min(data.len()))
}
fn unique(values: Vec<usize>, label: &str) -> Result<usize> {
    ensure!(
        values.len() == 1,
        "geometry {label}: {} matches",
        values.len()
    );
    Ok(values[0])
}

#[derive(Debug)]
pub(super) struct Copy {
    pub site: usize,
    pub state: u32,
    pub status: u32,
    pub di: u32,
    pub translation: u32,
    pub leaf: u32,
}
impl Copy {
    pub fn detect(data: &[u8]) -> Result<Self> {
        let blocks = find(
            data,
            &[
                0x4900, 0x6908, 0x2202, 0x4310, 0x6108, 0x6828, 0x2240, 0x0021, 0xf000, 0xf800,
                0x6828, 0x2240, 0x18a1, 0x3070, 0xe000,
            ],
            0,
            data.len(),
        );
        let mut found = Vec::new();
        for block in blocks {
            if let Ok(value) = Self::at(data, block) {
                found.push(value);
            }
        }
        ensure!(
            found.len() == 1,
            "geometry two-record worker: {} matches",
            found.len()
        );
        Ok(found.remove(0))
    }
    fn at(data: &[u8], block: usize) -> Result<Self> {
        ensure!(
            literal(data, block, 1)? == 0x04050000,
            "DI copy controller register"
        );
        let leaf = target(data, block + 16, "bl")?;
        ensure!(
            target(data, block + 28, "b")? == block - 10,
            "DI second-copy join"
        );
        ensure!(
            target(data, block - 10, "bl")? == leaf,
            "DI copy calls disagree"
        );
        let _metadata = target(data, block - 6, "bl")?;
        let entry = unique(
            find(
                data,
                &[
                    0xb5f8, 0x4800, 0x2600, 0x2400, 0x2100, 0x7201, 0x4a00, 0x7810, 0x0780, 0xd400,
                    0x4f00, 0x7838, 0x0940, 0x2807, 0xd100, 0xf000, 0xf800,
                ],
                block.saturating_sub(0x300),
                block,
            ),
            "copy worker entry",
        )?;
        target(data, entry + 30, "bl")?;
        target(data, target(data, entry + 28, "bne")?, "bl")?;
        let selectors = find(
            data,
            &[0x7838, 0x0940, 0x4d00, 0x2807, 0xd100],
            entry,
            block,
        )
        .into_iter()
        .filter(|&p| target(data, p + 8, "bne").ok() == Some(block))
        .collect();
        let selector = unique(selectors, "copy DI selector")?;
        let compact_copy = find(
            data,
            &[
                0x2a00, 0xb530, 0xd025, 0x4288, 0xd023, 0x4b00, 0x0209, 0x681c, 0x0a09, 0x681b,
                0x1909, 0x0200, 0x0a00, 0x18c0,
            ],
            leaf,
            leaf + 28,
        ) == vec![leaf];
        let wide_copy = find(
            data,
            &[
                0xb5f0, 0x2a00, 0xd02b, 0x4288, 0xd029, 0x4c00, 0x020b, 0x6827, 0x0a1b, 0x19dd,
                0x0203, 0x0a1b, 0x19dc, 0x002b,
            ],
            leaf,
            leaf + 28,
        ) == vec![leaf];
        ensure!(compact_copy ^ wide_copy, "translated copy leaf");
        let translation_register = (half(data, leaf + 10)? >> 8) & 7;
        Ok(Self {
            site: block + 20,
            state: ram(literal(data, entry + 20, 7)?)?,
            status: ram(literal(data, entry + 12, 2)?)?,
            di: ram(literal(data, selector + 4, 5)?)?,
            translation: ram(literal(data, leaf + 10, translation_register)?)?,
            leaf: (leaf as u32) | 1,
        })
    }
}

#[derive(Debug)]
pub(super) struct Mapping {
    pub normalize: u32,
    pub first_end: u32,
    pub second_end: u32,
    pub last: u32,
    pub cache: u32,
}
impl Mapping {
    pub fn detect(data: &[u8]) -> Result<Self> {
        // Complete dense PSN->LBA leaf, including every arithmetic/branch opcode.
        let forward = unique(
            find(
                data,
                &[
                    0x4a00, 0xb530, 0x6813, 0x1c5b, 0x4900, 0x4298, 0xd925, 0x6813, 0x6889, 0x1a59,
                    0x4b00, 0x4c00, 0x18c9, 0x6823, 0x4d00, 0x6812, 0x1c5b, 0x4298, 0xd918, 0x6823,
                    0x1aaa, 0x1a9a, 0x4b00, 0x1851, 0x681a, 0x1c49, 0x1c52, 0x4290, 0x6822, 0x4d00,
                    0xd908, 0x681c, 0x1aaa, 0x1aa2, 0x1851, 0x681a, 0x1c49, 0x4b00, 0x1a9a, 0xe000,
                    0x1aaa, 0x1a80, 0x1840, 0xbd30, 0xe7fa, 0x6889, 0x1a40, 0x2101, 0x0509, 0x1a40,
                    0xbd30,
                ],
                0,
                data.len(),
            ),
            "native dense mapper",
        )?;
        ensure!(
            target(data, forward + 78, "b")? == forward + 82,
            "dense mapper subtraction join"
        );
        for (offset, reg, expected) in [
            (20, 3, 0xfff00001),
            (28, 5, 0x03ffffff),
            (58, 5, 0x07ffffff),
            (74, 3, 0x0bffffff),
        ] {
            ensure!(
                literal(data, forward + offset, reg)? == expected,
                "dense mapper arithmetic constant"
            );
        }
        let wrappers = find(
            data,
            &[
                0xb500, 0xf000, 0xf800, 0x4900, 0x6889, 0x1840, 0x2101, 0x0509, 0x1840, 0xbd00,
            ],
            0,
            data.len(),
        )
        .into_iter()
        .filter(|&p| target(data, p + 2, "bl").ok() == Some(forward))
        .collect();
        let wrapper = unique(wrappers, "dense normalization wrapper")?;
        let cache = ram(literal(data, forward + 8, 1)?)?;
        ensure!(
            literal(data, wrapper + 6, 1)? == cache,
            "normalization cache mismatch"
        );
        Ok(Self {
            normalize: (wrapper as u32) | 1,
            first_end: ram(literal(data, forward, 2)?)?,
            second_end: ram(literal(data, forward + 22, 4)?)?,
            last: ram(literal(data, forward + 44, 3)?)?,
            cache,
        })
    }
}

pub(super) fn detect(data: &[u8]) -> Result<super::GeometryPlan> {
    use sha2::{Digest, Sha256};
    let copy = Copy::detect(data)?;
    storage_contract(data, &copy)?;
    let mapper = Mapping::detect(data)?;
    let entry = unique(
        find(
            data,
            &[
                0xb5f8, 0x4800, 0x2500, 0x7005, 0x4800, 0x6005, 0x4800, 0x7005, 0x4e00, 0x81f5,
                0x4800, 0x2701, 0x8007, 0x7800, 0x4900, 0x7008, 0x0032, 0x320e, 0x7810, 0x4b00,
                0x7018, 0x4800, 0x7800, 0x2800, 0xd100,
            ],
            0,
            data.len(),
        ),
        "classic geometry initializer",
    )?;
    let end_cell = ram(literal(data, entry + 8, 0)?)?;
    let bypass = ram(literal(data, entry + 42, 0)?)?;
    let success = unique(
        find(
            data,
            &[0x4900, 0x7808, 0x4338, 0x7008, 0x2001, 0xbdf8],
            entry,
            entry + 0x240,
        ),
        "geometry success epilogue",
    )?;
    let mut bypass_target = target(data, entry + 48, "bne")?;
    for _ in 0..2 {
        if bypass_target == success {
            break;
        }
        bypass_target = target(data, bypass_target, "b")?;
    }
    ensure!(
        bypass_target == success,
        "geometry bypass does not join success"
    );
    let media = unique(
        find(
            data,
            &[
                0x4c00, 0x7820, 0x0900, 0x280c, 0xd100, 0x4800, 0x7800, 0x0780, 0xd500, 0x4b00,
            ],
            entry,
            success,
        ),
        "geometry DI-ready selection",
    )?;
    ensure!(
        literal(data, media, 4)? == copy.state
            && literal(data, media + 10, 0)? == copy.status
            && literal(data, media + 18, 3)? == copy.di,
        "geometry and worker state/DI disagree"
    );
    let reads = unique(
        find(
            data,
            &[
                0x3009, 0x9000, 0xf000, 0xf800, 0x4900, 0x6008, 0x9800, 0x1d00, 0x9000, 0xf000,
                0xf800, 0x6060, 0x9800, 0x1d00, 0xf000, 0xf800,
            ],
            media,
            success,
        ),
        "geometry three native words",
    )?;
    let reader = target(data, reads + 4, "bl")?;
    ensure!(
        target(data, reads + 18, "bl")? == reader && target(data, reads + 28, "bl")? == reader,
        "geometry word readers disagree"
    );
    ensure!(
        literal(data, reads + 8, 1)? == end_cell,
        "geometry last-sector destination"
    );
    ensure!(
        literal(data, reader, 1)? == copy.translation,
        "geometry reader translation mismatch"
    );
    let translated_reader = find(
        data,
        &[
            0x4900, 0xb510, 0x680b, 0x0202, 0x0a12, 0x18d2, 0x7812, 0x1c43, 0x680c, 0x021b, 0x0612,
            0x0a1b, 0x191b, 0x781b, 0x680c, 0x041b, 0x431a, 0x1c83, 0x021b, 0x0a1b, 0x191b, 0x781b,
            0x1cc0, 0x6809, 0x021b, 0x431a, 0x0200, 0x0a00, 0x1840, 0x7800, 0x4310, 0xbd10,
        ],
        reader,
        reader + 64,
    ) == vec![reader];
    let direct_reader = find(
        data,
        &[
            0x4900, 0x6809, 0x1840, 0x7802, 0x78c1, 0x0612, 0x4311, 0x7842, 0x7880, 0x0412, 0x0200,
            0x4310, 0x4308, 0x4770,
        ],
        reader,
        reader + 28,
    ) == vec![reader];
    ensure!(
        translated_reader ^ direct_reader,
        "geometry native big-endian reader"
    );
    let descriptor_load = unique(
        find(data, &[0x4c00], reads.saturating_sub(0x30), reads),
        "geometry descriptor",
    )?;
    let descriptor = ram(literal(data, descriptor_load, 4)?)?;
    ensure!(
        half(data, reads - 2)? == 0x7061,
        "geometry layer descriptor store"
    );
    let first = unique(
        find(
            data,
            &[
                0x68a0, 0x4900, 0x6008, 0x6860, 0x4900, 0x3118, 0x60c8, 0x6048,
            ],
            reads,
            success,
        ),
        "geometry first boundary",
    )?;
    ensure!(
        literal(data, first + 2, 1)? == mapper.first_end
            && literal(data, first + 8, 1)? == descriptor,
        "geometry first boundary/descriptor mismatch"
    );
    let second = unique(
        find(
            data,
            &[0x4a00, 0x6810, 0x4900, 0x6008, 0x6810, 0xf000, 0xf800],
            first,
            success,
        ),
        "geometry second boundary",
    )?;
    ensure!(
        literal(data, second, 2)? == end_cell && literal(data, second + 4, 1)? == mapper.second_end,
        "geometry second boundary mismatch"
    );
    let cache = unique(
        find(
            data,
            &[0x2082, 0x7270, 0x4800, 0x6085, 0x62b5, 0x62f5],
            second,
            success,
        ),
        "geometry cache reset",
    )?;
    ensure!(
        literal(data, cache + 4, 0)? == mapper.cache,
        "geometry mapper cache mismatch"
    );
    Ok(super::GeometryPlan {
        source_hash: Sha256::digest(data).into(),
        copy_site: copy.site,
        geometry_site: success + 8,
        operands: super::GeometryOperands {
            state: copy.state,
            di: copy.di,
            translation: copy.translation,
            copy_leaf: copy.leaf,
            word_reader: (reader as u32) | 1,
            bypass,
            status: copy.status,
            descriptor,
            last_physical: mapper.last,
            layer_one_end: mapper.second_end,
            normalize: mapper.normalize,
            end_cell,
        },
    })
}

/// Bind existing OEM pointer construction and its 896-byte clear request.
/// This is an existing use extent, not simulated DMA completion or allocation.
fn storage_contract(data: &[u8], copy: &Copy) -> Result<()> {
    let mut writers = find(
        data,
        &[0x4900, 0x6809, 0x03c2, 0x1889, 0x4a00, 0x6011],
        0,
        data.len(),
    );
    writers.extend(find(
        data,
        &[0x4900, 0x03c2, 0x6809, 0x1889, 0x4a00, 0x6011],
        0,
        data.len(),
    ));
    writers.retain(|&p| literal(data, p + 8, 2).ok() == Some(copy.di));
    let writer = unique(writers, "DI pointer setup")?;
    ram(literal(data, writer, 1)?)?;
    let mut clears = Vec::new();
    for at in find(
        data,
        &[
            0x4800, 0x7800, 0x4d00, 0x0780, 0xd405, 0x2207, 0x6828, 0x01d2, 0x2100, 0xf000, 0xf800,
        ],
        0,
        data.len(),
    ) {
        if literal(data, at, 0).ok() == Some(copy.status)
            && literal(data, at + 4, 5).ok() == Some(copy.di)
        {
            clears.push(at);
        }
    }
    for at in find(
        data,
        &[
            0x4800, 0x7800, 0x0780, 0xd406, 0x4800, 0x2207, 0x6800, 0x01d2, 0x2100, 0xf000, 0xf800,
        ],
        0,
        data.len(),
    ) {
        if literal(data, at, 0).ok() == Some(copy.status)
            && literal(data, at + 8, 0).ok() == Some(copy.di)
        {
            clears.push(at);
        }
    }
    target(data, unique(clears, "DI existing clear extent")? + 18, "bl")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_copy_signatures_match_reviewed_operands() {
        let Ok(root) = std::env::var("FREEMKV_GEOMETRY_CORPUS") else {
            return;
        };
        let receipt: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../internal/docs/audits/mtk-geometry-operands-20261101.json"
        ))
        .unwrap();
        for expected in receipt["images"].as_array().unwrap() {
            let hash = expected["source_sha256"].as_str().unwrap();
            let data =
                std::fs::read(std::path::Path::new(&root).join(hash).join("original.bin")).unwrap();
            let actual = Copy::detect(&data).unwrap();
            let operand = |name: &str| expected["operands"][name].as_u64().unwrap() as u32;
            assert_eq!(actual.site as u64, expected["copy_site"].as_u64().unwrap());
            assert_eq!(actual.state, operand("state"));
            assert_eq!(actual.status, operand("status"));
            assert_eq!(actual.di, operand("di"));
            assert_eq!(actual.translation, operand("translation"));
            assert_eq!(actual.leaf, operand("copy_leaf"));
            let derived = detect(&data).unwrap();
            assert_eq!(
                derived.copy_site as u64,
                expected["copy_site"].as_u64().unwrap()
            );
            assert_eq!(
                derived.geometry_site as u64,
                expected["geometry_site"].as_u64().unwrap()
            );
            let o = derived.operands;
            assert_eq!(
                [
                    o.state,
                    o.di,
                    o.translation,
                    o.copy_leaf,
                    o.word_reader,
                    o.bypass,
                    o.status,
                    o.descriptor,
                    o.last_physical,
                    o.layer_one_end,
                    o.normalize,
                    o.end_cell
                ],
                [
                    "state",
                    "di",
                    "translation",
                    "copy_leaf",
                    "word_reader",
                    "bypass",
                    "status",
                    "descriptor",
                    "last_physical",
                    "layer_one_end",
                    "normalize",
                    "end_cell"
                ]
                .map(operand)
            );
        }
    }
    #[test]
    fn signatures_reject_changed_code_and_ambiguity_without_selecting_by_hash() {
        let source = include_bytes!("../../tests/fixtures/BE14NU40_MT1939_JB7_1.01.bin");
        let original = detect(source).unwrap();
        let mut unrelated = source.to_vec();
        unrelated[0x1000] ^= 1;
        let changed = detect(&unrelated).unwrap();
        assert_eq!(changed.copy_site, original.copy_site);
        assert_eq!(changed.geometry_site, original.geometry_site);
        assert_ne!(changed.source_hash, original.source_hash);
        assert!(original.prepared_patches(&unrelated, 0x0200f000).is_err());
        let mut broken = source.to_vec();
        broken[original.copy_site] ^= 1;
        assert!(detect(&broken).is_err());
        let mut broken = source.to_vec();
        broken[original.geometry_site] ^= 1;
        assert!(detect(&broken).is_err());
        let duplicated = [source.as_slice(), source.as_slice()].concat();
        assert!(detect(&duplicated).is_err());
    }
}
