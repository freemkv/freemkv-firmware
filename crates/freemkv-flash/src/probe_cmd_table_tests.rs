use super::*;

/// Encode one 8-byte command record.
fn rec(handler: u32, opcode: u8, flags: u8) -> [u8; 8] {
    let mut r = [0u8; 8];
    r[0..4].copy_from_slice(&handler.to_le_bytes());
    r[4] = opcode;
    r[5] = flags;
    // reserved (r[6..8]) stays zero
    r
}

/// Build a synthetic image with a single command segment at `head`, isolated
/// by 0xFF fill so detection cannot latch onto surrounding bytes.
fn synthetic(head: usize, recs: &[[u8; 8]]) -> Vec<u8> {
    let mut img = vec![0xFFu8; head + recs.len() * 8 + 0x100];
    let mut p = head;
    for r in recs {
        img[p..p + 8].copy_from_slice(r);
        p += 8;
    }
    img
}

#[test]
fn parses_opcodes_head_and_counts() {
    let head = 0x150000;
    // Six real records incl. INQUIRY (0x12) and a vendor opcode (0xC0),
    // then a segment terminator.
    let recs = [
        rec(0x0001_AB10 | 1, 0x00, 0x01), // TEST UNIT READY (thumb bit set)
        rec(0x0001_AB20 | 1, 0x12, 0x01), // INQUIRY
        rec(0x0001_AB30 | 1, 0x28, 0x01), // READ10
        rec(0x0001_AB40 | 1, 0xA8, 0x01), // READ12
        rec(0x0001_AB50 | 1, 0x3C, 0x01), // READ BUFFER
        rec(0x0001_AB60 | 1, 0xC0, 0x01), // vendor
        rec(0x0000_0000, 0x00, 0x03),     // terminator
    ];
    let img = synthetic(head, &recs);

    let ct = analyze_command_table(&img);
    assert!(ct.found);
    assert_eq!(ct.head_offset, head);
    assert_eq!(ct.segment_count, 1);
    assert_eq!(ct.record_count, 6);
    assert_eq!(ct.opcodes.len(), 6);

    // 0x12 maps to INQUIRY, standard range.
    let inq = ct.opcodes.iter().find(|e| e.opcode == 0x12).unwrap();
    assert_eq!(scsi_opcode_name(inq.opcode), "INQUIRY");
    assert_eq!(opcode_range(inq.opcode), "standard");

    // 0xC0 is a vendor opcode with a blank name.
    let v = ct.opcodes.iter().find(|e| e.opcode == 0xC0).unwrap();
    assert_eq!(scsi_opcode_name(v.opcode), "");
    assert_eq!(opcode_range(v.opcode), "vendor");

    // Vendor 0xC0 used; 0xDE free.
    assert!(ct.vendor_used().contains(&0xC0));
    assert!(ct.vendor_free().contains(&0xDE));
    assert!(!ct.vendor_free().contains(&0xC0));
}

#[test]
fn recurring_opcode_across_segments() {
    // Two separate segments (per-disc-profile), each isolated by a 0xFF gap,
    // each carrying INQUIRY (0x12) with a DIFFERENT handler. The parser must
    // sweep both and merge them into one opcode entry with two handlers.
    let head = 0x148000;
    let seg2 = 0x149000;
    let mut img = vec![0xFFu8; 0x14A000];
    let seg1 = [
        rec(0x0001_0000 | 1, 0x12, 0x02), // INQUIRY, handler A
        rec(0x0001_0008 | 1, 0x28, 0x02),
        rec(0x0001_0010 | 1, 0xA8, 0x02),
        rec(0x0001_0018 | 1, 0x3C, 0x02),
        rec(0x0001_0020 | 1, 0xC0, 0x02),
        rec(0x0000_0000, 0x00, 0x03), // terminator
    ];
    let seg2_recs = [
        rec(0x0002_0000 | 1, 0x12, 0x02), // INQUIRY, handler B (recurrence)
        rec(0x0002_0008 | 1, 0x5A, 0x02),
        rec(0x0002_0010 | 1, 0xAD, 0x02),
        rec(0x0002_0018 | 1, 0xBE, 0x02),
        rec(0x0002_0020 | 1, 0xA3, 0x02),
        rec(0x0000_0000, 0x00, 0x03), // terminator
    ];
    for (base, recs) in [(head, &seg1), (seg2, &seg2_recs)] {
        let mut p = base;
        for r in recs {
            img[p..p + 8].copy_from_slice(r);
            p += 8;
        }
    }

    let ct = analyze_command_table(&img);
    assert!(ct.found);
    assert_eq!(ct.segment_count, 2);
    assert_eq!(ct.head_offset, head);
    // 0x12 seen once per segment, with two distinct handlers.
    let inq = ct.opcodes.iter().find(|e| e.opcode == 0x12).unwrap();
    assert_eq!(inq.record_count, 2);
    assert_eq!(inq.handlers.len(), 2);
    assert!(ct.vendor_used().contains(&0xC0));
}

#[test]
fn opaque_image_is_graceful() {
    // Random-ish bytes with no plausible run: found=false, no panic.
    let img: Vec<u8> = (0..0x160000u32)
        .map(|i| (i.wrapping_mul(0x9E37)) as u8)
        .collect();
    let ct = analyze_command_table(&img);
    // Either not found, or if a short accidental run appears it must not panic;
    // the JSON/MD emitters must handle both.
    let _ = command_table_json(&ct, "P", "R");
    let _ = command_table_md(&ct, "P", "R");
    if !ct.found {
        let j = command_table_json(&ct, "P", "R");
        assert!(j.contains("\"found\": false"));
    }
}

#[test]
fn real_image_opcode_table() {
    // Fixture path from the environment only (no owned path baked into this
    // public repo): `FREEMKV_KAT_BASE` = an OEM BU40N 1.00 image; unset skips.
    let Ok(path) = std::env::var("FREEMKV_KAT_BASE") else {
        eprintln!("skipping: FREEMKV_KAT_BASE unset (real firmware image)");
        return;
    };
    let Ok(img) = std::fs::read(&path) else {
        eprintln!("skipping: real firmware image not present at {path}");
        return;
    };
    let ct = analyze_command_table(&img);
    assert!(
        ct.found,
        "expected to find the command table in the real image"
    );
    assert!(
        (50..=100).contains(&ct.opcodes.len()),
        "expected ~74 distinct opcodes, got {}",
        ct.opcodes.len()
    );
    assert!(
        ct.vendor_free().contains(&0xDE),
        "expected vendor opcode 0xDE to be FREE in this image"
    );
}
