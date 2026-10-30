"""Run the existing held-input settings test in bounded, independent shards."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import subprocess

TEST = 'mt1939_modify_tests::held_modify_corpus_roundtrips_every_advertised_choice'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--test-binary', type=Path, required=True)
parser.add_argument('--corpus', type=Path, required=True)
parser.add_argument('--hoard', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--workers', type=int, choices=range(1, 9), default=min(6, os.cpu_count() or 1))
args = parser.parse_args()
exe = args.test_binary.resolve()
listing = subprocess.check_output([str(exe), '--list'], text=True)
assert f'{TEST}: test' in listing, 'the executable is not the expected library test binary'
rows = json.loads(args.corpus.read_text())['images']
assert rows and len({r['sha256'] for r in rows}) == len(rows)
expected = {r['sha256']: r.get('output_sha256') for r in rows}
work = args.output.resolve().with_suffix('.workers')
work.mkdir(parents=True, exist_ok=True)


def run(index):
    shard = rows[index::args.workers]
    if not shard:
        return []
    manifest, receipt, log = (work / f'{index}.{suffix}' for suffix in ('json', 'jsonl', 'log'))
    manifest.write_text(json.dumps({'images': shard}) + '\n')
    env = dict(os.environ, FREEMKV_HELD_MODIFY_CORPUS=str(manifest),
               FREEMKV_NORMAL_MODIFY_HOARD=str(args.hoard.resolve()),
               FREEMKV_HELD_MODIFY_OUTPUT=str(receipt))
    with log.open('w') as stream:
        result = subprocess.run([str(exe), '--exact', TEST, '--nocapture'], env=env,
                                stdout=stream, stderr=subprocess.STDOUT)
    assert result.returncode == 0, f'shard {index} failed; see {log}'
    assert '1 passed; 0 failed' in log.read_text(), f'shard {index} did not execute its test'
    records = [json.loads(line) for line in receipt.read_text().splitlines()]
    assert {r['input_sha256'] for r in records} == {r['sha256'] for r in shard}
    for record in records:
        wanted = expected[record['input_sha256']]
        assert wanted is None or record['output_sha256'] == wanted, 'default output differs from retained BIN'
        assert all(record[key] == 'passed' for key in ('admission', 'audit', 'integrity'))
    print(f'Shard {index}: {len(records)} inputs passed', flush=True)
    return records


with ThreadPoolExecutor(max_workers=args.workers) as pool:
    records = [r for group in pool.map(run, range(args.workers)) for r in group]
assert len(records) == len(rows)
records.sort(key=lambda r: r['input_sha256'])
args.output.write_text(json.dumps({'test_binary_sha256': hashlib.sha256(exe.read_bytes()).hexdigest(),
    'inputs': len(records), 'advertised_choices_tested': sum(r['advertised_choices_tested'] for r in records),
    'images': records}, indent=2) + '\n')
print(f"PASS: {len(records)} inputs; {sum(r['advertised_choices_tested'] for r in records)} advertised choices")
