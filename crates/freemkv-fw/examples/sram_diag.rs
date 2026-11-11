use mediatek_optical::image::analysis::RamReferences;

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: sram_diag <firmware.bin>");
    let image = std::fs::read(&path).expect("read firmware");
    let refs = RamReferences::inspect(&image);

    println!("=== bytes() in 0x02001000..0x02002000 ===");
    for addr in refs.bytes().range(0x02001000..0x02002000) {
        println!("  {addr:#010x}");
    }

    println!("\n=== ALL fills() ===");
    for (prefix, addr, len, private) in refs.fills() {
        println!("  prefix=0x{prefix:06x} addr={addr:#010x} len={len:#x} private={private}");
    }

    println!("\n=== calls() in SRAM range ===");
    for (pc, addr, len) in refs.calls() {
        if (0x02000000..0x02002000).contains(addr) {
            println!("  pc=0x{pc:06x} addr={addr:#010x} len={len:#x}");
        }
    }

    println!(
        "\n=== incomplete seeds: {} total ===",
        refs.incomplete().len()
    );

    println!("\n=== bytes() contiguous ranges ===");
    let all: Vec<_> = refs.bytes().iter().copied().collect();
    if !all.is_empty() {
        let mut ranges = vec![];
        let (mut start, mut end) = (all[0], all[0]);
        for &a in &all[1..] {
            if a == end + 1 {
                end = a;
            } else {
                ranges.push((start, end));
                start = a;
                end = a;
            }
        }
        ranges.push((start, end));
        for (s, e) in &ranges {
            println!("  {s:#010x}..={e:#010x} ({} bytes)", e - s + 1);
        }
    }
}
