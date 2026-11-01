"""Bind native BD end-coordinate normalization without selecting a model."""
import re
from classic_mapping import literal


def consumers(data, end_cell):
    # LDR R0,literal; LDR R0,[R0]; LDR R1,literal; ADDS R0,R0,R1.
    pattern = re.compile(b'.\x48\x00\x68.\x49\x40\x18', re.S)
    sites = []
    for match in pattern.finditer(data):
        pc = match.start()
        if pc % 2 == 0 and literal(data, pc) == end_cell and literal(data, pc + 4) == 0xffefffff:
            sites.append(pc)
    # Several native consumers can share this operation. Keep them all; this
    # binds arithmetic, not command dispatch or complete host response delivery.
    return sites
