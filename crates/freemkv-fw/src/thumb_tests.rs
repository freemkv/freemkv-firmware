use super::*;

#[test]
fn find_bytes_word_and_start() {
    let img = [0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55];
    assert_eq!(find(&img, Needle::Bytes(&[0x22, 0x33]), 0), Some(2));
    // little-endian word 0x33221100 == bytes 00 11 22 33 at offset 0.
    assert_eq!(find(&img, Needle::Word(0x3322_1100), 0), Some(0));
    // `start` skips earlier matches.
    assert_eq!(find(&img, Needle::Bytes(&[0x22, 0x33]), 3), None);
}

#[test]
fn find_free_run_and_wrapper() {
    let mut img = vec![0u8; 32];
    for b in img.iter_mut().skip(10).take(8) {
        *b = 0xFF;
    }
    // find_free_space is exactly find(FreeRun, ..).
    assert_eq!(find_free_space(&img, 8, 0), Some(10));
    assert_eq!(find(&img, Needle::FreeRun(8), 0), Some(10));
    assert_eq!(find(&img, Needle::FreeRun(9), 0), None);
    // Nested/composed find: nothing more free past the run.
    let run = find(&img, Needle::FreeRun(4), 0).unwrap();
    assert_eq!(find(&img, Needle::FreeRun(4), run + 8), None);
}

#[test]
fn bl_encode_decode_roundtrip() {
    // Forward, backward, and a real observed site (0x9da80 -> 0x9bf50).
    let cases: &[(usize, u32)] = &[
        (0x9da80, 0x9bf50),
        (0x9e3f8, 0x9bf50),
        (0x1000, 0x1c3810),
        (0x1c3810, 0x1000),
        (0x100, 0x100 + 4), // minimal forward
    ];
    for &(site, target) in cases {
        let bytes = encode_bl(site, target).expect("in range");
        let mut img = vec![0u8; site + 8];
        img[site..site + 4].copy_from_slice(&bytes);
        assert_eq!(
            decode_bl(&img, site),
            Some(target),
            "roundtrip site=0x{site:x} target=0x{target:x}"
        );
    }
    // Out of BL range (> 16 MiB) is refused, never mis-encoded.
    assert_eq!(encode_bl(0, 0x0200_0000), None);
}

#[test]
fn find_bl_sites_locates_direct_calls() {
    // Two BL sites calling the same target, plus unrelated bytes between.
    let target = 0x1_5000u32;
    let mut img = vec![0u8; 0x8000];
    let a = 0x1000usize;
    let b = 0x2000usize;
    img[a..a + 4].copy_from_slice(&encode_bl(a, target).unwrap());
    img[b..b + 4].copy_from_slice(&encode_bl(b, target).unwrap());
    let sites = find_bl_sites(&img, target);
    assert!(sites.contains(&a) && sites.contains(&b), "sites: {sites:?}");
}

#[test]
fn asm_reproduces_kat_handler_bytes() {
    // The 3C-0E hijack handler, assembled through the dumb Asm verbs, must equal
    // the hand-built KAT bytes exactly (handler + literal pool). If the encoder
    // drifts one bit, this fails against a known-good artifact.
    const KAT: &str = "094b58780e280dd19878c0280ad1d878de2807d100b5\
0920f0210022034b9847022000bd024b1847380d00026b2d0a005bad0900";
    let mut a = Asm::new();
    let tail = a.label();
    a.ldr_lit(3, 0x0200_0d38); // ldr r3, =cdb_base
    a.ldrb_imm(0, 3, 1); // mode = cdb[1]
    a.cmp_imm(0, 0x0E);
    a.bne(tail);
    a.ldrb_imm(0, 3, 2); // cdb[2]
    a.cmp_imm(0, 0xC0);
    a.bne(tail);
    a.ldrb_imm(0, 3, 3); // cdb[3]
    a.cmp_imm(0, 0xDE);
    a.bne(tail);
    a.push(0x0100); // push {lr}
    a.movs_imm(0, 0x09);
    a.movs_imm(1, 0xF0);
    a.movs_imm(2, 0x00);
    a.ldr_lit(3, 0x000a_2d6b); // ldr r3, =sense_setter|1
    a.blx(3);
    a.movs_imm(0, 0x02);
    a.pop(0x0100); // pop {pc}
    a.bind(tail);
    a.ldr_lit(3, 0x0009_ad5b); // ldr r3, =oem_handler|1
    a.bx(3);
    let got = a.finish().expect("assemble");
    let hex: String = got.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, KAT, "assembled handler drifted from the KAT");
}

#[test]
fn command_table_walk_follows_chain_and_stops_at_terminator() {
    // Two segments: base seg has one real record then a chain(flag=4) whose
    // handler field points at the second segment; second seg has one real record
    // then a terminator(flag=3).
    let stride = 8;
    let seg2 = 0x40usize;
    let mut img = vec![0u8; 0x80];
    // seg1[0]: opcode 0x12, flags 0x01, handler 0x1111
    img[0] = 0x12;
    img[1] = 0x01;
    img[4..8].copy_from_slice(&0x1111u32.to_le_bytes());
    // seg1[1]: chain, flags 0x04, handler = seg2 base
    img[8] = 0x00;
    img[9] = 0x04;
    img[12..16].copy_from_slice(&(seg2 as u32).to_le_bytes());
    // seg2[0]: opcode 0x3C, flags 0x01, handler 0x2222
    img[seg2] = 0x3C;
    img[seg2 + 1] = 0x01;
    img[seg2 + 4..seg2 + 8].copy_from_slice(&0x2222u32.to_le_bytes());
    // seg2[1]: terminator flags 0x03
    img[seg2 + 9] = 0x03;
    let t = CommandTable {
        base: 0,
        stride,
        opcode_off: 0,
        flags_off: 1,
        handler_off: 4,
        term_flag: 0x03,
        max_records: 64,
    };
    let recs = t.walk(&img, 0x04);
    assert_eq!(recs.len(), 2, "expected both segments' real records");
    assert_eq!((recs[0].opcode, recs[0].handler), (0x12, 0x1111));
    assert_eq!((recs[1].opcode, recs[1].handler), (0x3C, 0x2222));
}

#[test]
fn prologue_check_accepts_push_lr_rejects_data() {
    let mut img = vec![0u8; 16];
    img[4..6].copy_from_slice(&0xB5F0u16.to_le_bytes()); // push {r4-r7,lr}
    assert!(prologue_is_push_lr(&img, 4, 4));
    assert!(!prologue_is_push_lr(&img, 8, 4));
}

#[test]
fn read_modify_insert() {
    let mut img = vec![0xFFu8; 16];
    write(&mut img, 4, &[0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(read_u32(&img, 4), 0xEFBE_ADDE);
    assert_eq!(read_u8(&img, 4), 0xDE);
    let addr = insert(&mut img, 8, &[1, 2, 3]);
    assert_eq!(addr, 8);
    assert_eq!(&img[8..11], &[1, 2, 3]);
}
