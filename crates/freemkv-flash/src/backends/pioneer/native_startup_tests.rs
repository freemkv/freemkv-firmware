//! Bounded execution of the OEM H8 bank guard, not a whole-drive emulator.
//! Instructions are fetched from the hash-bound native fixture. Unsupported
//! instructions fail; native flash-write and rejection calls are boundaries.
use std::collections::BTreeMap;

const BASE: u32 = 0x5509e8;
const CODE: &[u8] = include_bytes!("../../test-fixtures/pioneer-213u-bank-guard.bin");

#[derive(Debug, PartialEq, Eq)]
enum Boundary {
    Accepted,
    Reject(u32),
    Initialize(u32),
}

struct Cpu {
    er: [u32; 8],
    zero: bool,
    pc: u32,
    memory: BTreeMap<u32, u8>,
    reads: Vec<u32>,
    writes: Vec<(u32, usize)>,
    trace: Vec<u32>,
}

impl Cpu {
    fn new(bank_base: u32) -> Self {
        let mut cpu = Self {
            er: [0; 8],
            zero: false,
            pc: 0x5509f4,
            memory: BTreeMap::new(),
            reads: vec![],
            writes: vec![],
            trace: vec![],
        };
        // Start after stack frame allocation; no guard predicate depends on
        // caller registers. The target startup initializer supplies this base.
        cpu.er[7] = 0x10000;
        cpu.store(0x3442, bank_base, 4);
        cpu
    }
    fn store(&mut self, address: u32, value: u32, width: usize) {
        self.writes.push((address, width));
        let bytes = value.to_be_bytes();
        for (i, value) in bytes[4 - width..].iter().enumerate() {
            self.memory.insert(address + i as u32, *value);
        }
    }
    fn load(&mut self, address: u32, width: usize) -> u32 {
        self.reads.push(address);
        (0..width).fold(0, |v, i| {
            (v << 8) | u32::from(*self.memory.get(&(address + i as u32)).unwrap_or(&0xff))
        })
    }
    fn run(&mut self) -> Boundary {
        self.writes.clear();
        for _ in 0..64 {
            self.trace.push(self.pc);
            if self.pc == 0x550a76 {
                return Boundary::Accepted;
            }
            let at = usize::try_from(self.pc - BASE).unwrap();
            let op = &CODE[at..];
            let word = |offset| u16::from_be_bytes(op[offset..offset + 2].try_into().unwrap());
            let long = |offset| u32::from_be_bytes(op[offset..offset + 4].try_into().unwrap());
            let size = match op {
                [0x7a, sub, ..] => {
                    let reg = usize::from(sub & 7);
                    let value = long(2);
                    match sub >> 4 {
                        0 => {
                            self.er[reg] = value;
                            self.zero = value == 0;
                        }
                        1 => {
                            self.er[reg] = self.er[reg].wrapping_add(value);
                            self.zero = self.er[reg] == 0;
                        }
                        2 => self.zero = self.er[reg] == value,
                        _ => panic!("unsupported immediate opcode at {:x}", self.pc),
                    }
                    6
                }
                [0x01, 0x00, 0x6f, spec, ..] if spec & 0x80 != 0 => {
                    let base = usize::from((spec >> 4) & 7);
                    let src = usize::from(spec & 7);
                    let address = self.er[base].wrapping_add_signed(i32::from(word(4) as i16));
                    self.store(address, self.er[src], 4);
                    self.zero = self.er[src] == 0;
                    6
                }
                [0x01, 0x00, 0x69, spec, ..] if spec & 0x80 == 0 => {
                    let address = self.er[usize::from(spec >> 4)];
                    let value = self.load(address, 4);
                    self.er[usize::from(spec & 7)] = value;
                    self.zero = value == 0;
                    4
                }
                [0x01, 0x00, 0x78, base, 0x6b, dest, ..] if dest & 0xf8 == 0x20 => {
                    let address = self.er[usize::from(base >> 4)].wrapping_add(long(6));
                    let value = self.load(address, 4);
                    self.er[usize::from(dest & 7)] = value;
                    self.zero = value == 0;
                    10
                }
                [0x0f, spec, ..] => {
                    let value = self.er[usize::from((spec >> 4) & 7)];
                    self.er[usize::from(spec & 7)] = value;
                    self.zero = value == 0;
                    2
                }
                [0x69, spec, ..] => {
                    let address = self.er[usize::from((spec >> 4) & 7)];
                    let reg = usize::from(spec & 7);
                    if spec & 0x80 == 0 {
                        let value = self.load(address, 2);
                        self.er[reg] = (self.er[reg] & 0xffff0000) | value;
                        self.zero = value == 0;
                    } else {
                        self.store(address, self.er[reg], 2);
                        self.zero = self.er[reg] & 0xffff == 0;
                    }
                    2
                }
                [0x0b, spec, ..] if spec & 0x78 == 0x70 => {
                    let reg = usize::from(spec & 7);
                    self.er[reg] = self.er[reg].wrapping_add(if spec & 0x80 == 0 { 1 } else { 2 });
                    self.zero = self.er[reg] == 0;
                    2
                }
                [0x79, reg, ..] if reg & 0xf0 == 0 => {
                    let reg = usize::from(reg & 7);
                    self.er[reg] = (self.er[reg] & 0xffff0000) | u32::from(word(2));
                    self.zero = word(2) == 0;
                    4
                }
                [0x1f, spec, ..] => {
                    self.zero =
                        self.er[usize::from((spec >> 4) & 7)] == self.er[usize::from(spec & 7)];
                    2
                }
                [condition @ (0x40 | 0x46 | 0x47), displacement, ..] => {
                    let take = *condition == 0x40
                        || (*condition == 0x46 && !self.zero)
                        || (*condition == 0x47 && self.zero);
                    if take {
                        self.pc = (self.pc + 2).wrapping_add_signed(i32::from(*displacement as i8));
                        continue;
                    }
                    2
                }
                [0x5e, a, b, c, ..] => {
                    let target = (u32::from(*a) << 16) | (u32::from(*b) << 8) | u32::from(*c);
                    return match target {
                        0x4afa7c => Boundary::Reject(target),
                        0x550e04 => Boundary::Initialize(target),
                        _ => panic!("unexpected native call {target:x}"),
                    };
                }
                _ => panic!(
                    "unsupported opcode at {:x}: {:02x?}",
                    self.pc,
                    &op[..op.len().min(10)]
                ),
            };
            self.pc += size;
        }
        panic!("native guard exceeded instruction budget");
    }
}

#[test]
fn native_213u_guard_known_answers() {
    for (base, old_headers, target_headers) in [
        (0x5e8000, [0x5efffa, 0x5ffffa], [0x5f3ffa, 0x5ffffa]),
        (0x7d0000, [0x7dfffa, 0x7efffa], [0x7dbffa, 0x7e7ffa]),
    ] {
        let mut cpu = Cpu::new(base);
        for at in old_headers {
            cpu.store(at, 0xfedc4321, 4);
        }
        // Native compact source marker overlaps target's second marker. In
        // extended geometry erased interior bytes instead reach initialization.
        assert_eq!(
            cpu.run(),
            if base == 0x5e8000 {
                Boundary::Reject(0x4afa7c)
            } else {
                Boundary::Initialize(0x550e04)
            }
        );
        assert!(cpu.reads.contains(&target_headers[0]));
        assert!(cpu.reads.contains(&target_headers[1]));
        // Representative occupied source payload, not a retained customer bank
        // dump. Establishes the target guard's concrete nonblank counterexample.
        let mut occupied = Cpu::new(base);
        for at in target_headers {
            occupied.store(at, 0x12345678, 4);
        }
        for (index, at) in old_headers.into_iter().enumerate() {
            occupied.store(at, 0xfedc4321, 4);
            occupied.store(at + 4, index as u32 + 1, 2);
        }
        assert_eq!(occupied.run(), Boundary::Reject(0x4afa7c));
        assert!(occupied.trace.contains(&0x550a72));
        assert_eq!(
            occupied.writes,
            [(0x10002, 4), (0x10000, 2)],
            "rejection only writes its stack frame"
        );
        for (index, at) in old_headers.into_iter().enumerate() {
            assert_eq!(occupied.load(at, 4), 0xfedc4321);
            assert_eq!(occupied.load(at + 4, 2), index as u32 + 1);
        }
        for valid in target_headers {
            let mut native = Cpu::new(base);
            native.store(valid, 0xfedc4322, 4);
            assert_eq!(native.run(), Boundary::Accepted);
        }
    }
}

#[test]
fn native_212u_unchanged_banks_are_rejected() {
    let mut cpu = Cpu::new(0x5e8000);
    cpu.store(0x5efffa, 0xfedc4321, 4);
    cpu.store(0x5ffffa, 0xfedc4321, 4);
    cpu.store(0x5efffe, 1, 2);
    cpu.store(0x5ffffe, 2, 2);
    assert_eq!(
        cpu.run(),
        Boundary::Reject(0x4afa7c),
        "unchanged source banks must never be mistaken for a completed conversion"
    );
}

/// Feed actual offline-converter output into native instructions. This checks
/// the completed target record's guard only, not erase/program safety, source
/// boot continuity, competing headers, or the rest of target initialization.
pub(super) fn converted_record_reaches_native_acceptance(body: &[u8], footer: &[u8; 8]) {
    assert_eq!(body.len(), 0xbff8);
    assert_eq!(&footer[2..6], &0xfedc4322u32.to_be_bytes());
    for base in [0x5e8000, 0x7d0000] {
        let mut cpu = Cpu::new(base);
        for (offset, byte) in body.iter().chain(footer.iter()).enumerate() {
            cpu.memory.insert(base + offset as u32, *byte);
        }
        assert_eq!(cpu.run(), Boundary::Accepted);
        assert!(cpu.trace.contains(&0x550a60));
        assert!(!cpu.trace.contains(&0x550a72));
    }
}
