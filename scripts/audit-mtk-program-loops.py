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
parser.add_argument('--query', choices=('program-candidates', 'application-evidence'), default='program-candidates')
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
    process = subprocess.run([str(producer), str(source), args.query],
                             check=True, capture_output=True, text=True)
    result = json.loads(process.stdout)
    assert digest(source) == record['sha256'], 'source changed during query'
    return {'sha256': record['sha256'], 'path': record['path'], **result}


with ThreadPoolExecutor(max_workers=4) as pool:
    records = list(pool.map(query, inputs))
assert digest(producer) == producer_sha, 'producer changed during audit'
result = {'schema': 1, 'producer_sha256': producer_sha,
          'scope': 'component evidence; no executable receiver authorization', 'query': args.query,
          'images': records}
args.output.write_text(json.dumps(result, indent=2) + '\n')
counts = [len(r['candidates']) if args.query == 'program-candidates'
          else sum(p['acceptance'] is not None for p in r['ranges']) for r in records]
summary = {'images': len(records), 'query': args.query,
           'match_counts': {str(n): counts.count(n) for n in sorted(set(counts))}}
if args.query == 'application-evidence':
    frames = [sum(p['state_slot'] is not None for p in r['ranges']) for r in records]
    summary['frame_counts'] = {str(n): frames.count(n) for n in sorted(set(frames))}
print(json.dumps(summary))
