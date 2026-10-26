"""Query native loop candidates for an explicit hash set; never authorizes writes."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--hoard', type=Path, required=True)
parser.add_argument('--example', type=Path, required=True)
parser.add_argument('--inputs', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
producer = args.example.resolve()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


producer_sha = digest(producer)
inputs = json.loads(args.inputs.read_text())['images']
assert len({r['sha256'] for r in inputs}) == len(inputs), 'duplicate input hashes'


def query(record):
    source = args.hoard / record['path']
    assert digest(source) == record['sha256'], str(source)
    process = subprocess.run([str(producer), str(source), 'program-candidates'],
                             check=True, capture_output=True, text=True)
    result = json.loads(process.stdout)
    assert digest(source) == record['sha256'], 'source changed during query'
    return {'sha256': record['sha256'], 'path': record['path'], **result}


with ThreadPoolExecutor(max_workers=4) as pool:
    records = list(pool.map(query, inputs))
assert digest(producer) == producer_sha, 'producer changed during audit'
result = {'schema': 1, 'producer_sha256': producer_sha,
          'scope': 'native loop evidence; no caller/integrity/wrapper authorization',
          'images': records}
args.output.write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({'images': len(records), 'candidate_counts': {
    str(n): sum(len(r['candidates']) == n for r in records)
    for n in sorted({len(r['candidates']) for r in records})}}))
