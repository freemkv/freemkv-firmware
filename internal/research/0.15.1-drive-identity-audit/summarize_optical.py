"""Summarize whole indexed Pioneer Normal recognition and a filter counterfactual.

Removing three pin fields is an experiment, NOT a proposed production rule.
Family equality changes are not full flash admission decisions.
"""
import argparse
import collections
import hashlib
import itertools
import json
from pathlib import Path


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('tsv', type=Path)
    p.add_argument('metadata', type=Path)
    p.add_argument('output', type=Path)
    args = p.parse_args()
    metadata = json.loads(args.metadata.read_text())
    rows = [line.split('\t') for line in args.tsv.read_text().splitlines()]
    assert len(rows) == len(metadata) == len({row[0] for row in rows})
    assert {row[0] for row in rows} == set(metadata)
    errors = [dict(sha256=r[0], error=r[2], path=metadata[r[0]]['path'])
              for r in rows if r[1] == 'ERROR']
    decoded = [r for r in rows if len(r) == 8]
    known = [r for r in decoded if r[1] != 'UNKNOWN']
    reduced = collections.defaultdict(list)
    for r in known:
        pins = ' '.join(field for field in r[4].split()
                        if not field.lower().startswith(('fe8f=', 'fe9d=', 'fe9f=')))
        reduced[(r[2], r[3], pins, r[5])].append(r)
    merges = []
    for group in reduced.values():
        previous = collections.defaultdict(list)
        for row in group:
            previous[row[1]].append(row[0])
        if len(previous) < 2:
            continue
        changes = []
        for left, right in itertools.combinations(previous.values(), 2):
            changes.extend([a, b] for a in left for b in right)
        merges.append(dict(old_families={key: dict(images=len(values), models=sorted({
                           metadata[sha].get('embedded_model', '') for sha in values}))
                           for key, values in previous.items()},
                           newly_equal_unordered_pairs=changes,
                           newly_equal_directed_pair_count=2*len(changes)))
    report = dict(scope=__doc__, normal_images=len(rows),
                  decoded=len(decoded), decode_errors=errors,
                  family_recognized_images=len(known),
                  family_unrecognized_images=len(decoded)-len(known),
                  startup_recognition=dict(collections.Counter(r[6] for r in decoded)),
                  native_word_surface_recognition=dict(collections.Counter(r[7] for r in decoded)),
                  counterfactual=dict(removed_fields=['FE8F', 'FE9D', 'FE9F'],
                                      original_groups=len({r[1] for r in known}),
                                      reduced_groups=len(reduced), merges=merges,
                                      splits=0,
                                      unrecognized_inputs_gain_no_compatibility=True,
                                      production_change=False),
                  adapter_input_result_sha256=hashlib.sha256(args.tsv.read_bytes()).hexdigest(),
                  image_results=[dict(sha256=r[0], model=metadata[r[0]].get('embedded_model'),
                                      path=metadata[r[0]]['path'], family=r[1],
                                      asic=r[2], board=r[3], pins=r[4], servo=r[5],
                                      startup=r[6], native_word_surface=r[7]) for r in decoded],
                  limitations=[
                      'Unrecognized startup comparisons do not imply neutral FFFF or permission to write.',
                      'Native surface recognition is static evidence, not a live read/write success.',
                      'Counterfactual family equality does not bypass ABI, receiver, format or preparation gates.',
                      'No replacement movement filter is selected or promoted by this audit.',
                      'Unknown and legacy unsupported images prevent a universal hardware claim.'
                  ])
    args.output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({k: report[k] for k in ('normal_images','decoded',
                     'family_recognized_images','family_unrecognized_images',
                     'startup_recognition','counterfactual')}, indent=2))


if __name__ == '__main__':
    main()
