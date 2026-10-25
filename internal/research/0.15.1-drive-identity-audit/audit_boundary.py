"""Proof for every newly equal hardware pair in the audited counterfactual.

Read-only, narrow phase-output evidence; NOT a full mechanism decoder or a
conversion rule. COMP storage is excluded; expanded regions stay separate.
"""
import argparse
import json
from pathlib import Path
from settings_proof import Hardware, Value, Requirement, STARTUP, Blocked, prepare


PREFIX = bytes.fromhex('01006df31ab30c8b10730a93')


def phase_matches(data):
    found = []
    for start in range(0, len(data)-48, 2):
        if data[start:start+len(PREFIX)] != PREFIX:
            continue
        at = start+len(PREFIX)

        def load():
            nonlocal at
            if data[at:at+2] == bytes.fromhex('6930'):
                at += 2
                return 0
            if data[at:at+4] == bytes.fromhex('6f300002'):
                at += 4
                return 1
            raise ValueError()

        try:
            word = load()
            if data[at] != 0x5e:
                continue
            at += 4
            if data[at:at+9] != bytes.fromhex('0c8012c0e0036a80f9'):
                continue
            control = data[at+9]
            at += 10
            if load() != word or data[at] != 0x5e:
                continue
            at += 4
            if data[at:at+3] != bytes.fromhex('6a88f9'):
                continue
            output = data[at+3]
            at += 4
            if data[at:at+6] != bytes.fromhex('01006d735470'):
                continue
            if (control, output) in ((0x12, 0x10), (0x13, 0x11)):
                found.append((word, control, output))
        except (ValueError, IndexError):
            pass
    return found


def profile(directory):
    raw = (directory/'motion-source.bin').read_bytes()
    spans = sorted(json.loads((directory/'motion-spans.json').read_text()))
    regions, at = [], 0
    for offset, size in spans:
        assert at <= offset <= offset+size <= len(raw)
        regions.append(raw[at:offset])
        at = offset+size
    regions.append(raw[at:])
    regions.extend(path.read_bytes() for path in sorted(directory.glob('motion-source.bin.stream*')))
    matches = sorted(match for region in regions for match in phase_matches(region))
    if len(matches) != 2 or {m[0] for m in matches} != {0, 1} or len({m[2] for m in matches}) != 2:
        return None
    if matches == [(0, 0x12, 0x10), (1, 0x13, 0x11)]:
        return 'word0=A'
    if matches == [(0, 0x13, 0x11), (1, 0x12, 0x10)]:
        return 'word0=B'
    return None


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('census', type=Path)
    p.add_argument('decoded_directory', type=Path)
    p.add_argument('output', type=Path)
    args = p.parse_args()
    census = json.loads(args.census.read_text())
    pairs = [pair for merge in census['counterfactual']['merges']
             for pair in merge['newly_equal_unordered_pairs']]
    members = sorted({sha for pair in pairs for sha in pair})
    profiles = {sha: profile(args.decoded_directory/sha) for sha in members}
    assert all(profiles.values()), profiles
    hardware = Hardware('audit.without-three-pin-fields.v1', 'same-audited-platform')
    decisions = []
    for left, right in pairs:
        for source, target in [(left, right), (right, left)]:
            try:
                prepare(hardware, hardware,
                        {'mechanism.phase': Value('audit.phase', profiles[source])},
                        [Requirement('mechanism.phase', 'audit.phase', profiles[target])], [STARTUP])
                result = 'allow'
            except Blocked as error:
                result = str(error)
            assert result == 'settings_conversion_unavailable_or_ambiguous'
            decisions.append(dict(source=source, target=target, decision=result))
    report = dict(status='All newly equal hardware pairs remain blocked by the independent settings gate',
                  evidence_scope=__doc__, profiles=profiles, directed_pairs_checked=len(decisions),
                  decisions=decisions, production_conversion_rules_added=0,
                  limitation='Proves the changed boundary and generic policy in memory. Does not prove '
                  'complete mechanism semantics, physical compatibility, unchanged production admission '
                  'for every existing pair, or readiness to ship a movement conversion.')
    args.output.write_text(json.dumps(report, indent=2)+'\n')
    print(report['status'], 'directed pairs:', len(decisions))
    print('Profiles:', profiles)


if __name__ == '__main__':
    main()
