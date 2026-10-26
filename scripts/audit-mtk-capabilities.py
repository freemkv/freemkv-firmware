"""Re-query baseline corpus buckets through the actual exact-image Modify planner."""
import argparse,csv,json,hashlib,subprocess,collections,tempfile
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
parser=argparse.ArgumentParser(description='Query exact-image Modify capabilities and optionally build/audit/gate every supported input.')
parser.add_argument('--hoard',type=Path,required=True)
parser.add_argument('--fw',type=Path,required=True)
parser.add_argument('--flash',type=Path)
parser.add_argument('--baseline',type=Path,default=Path(__file__).resolve().parents[1]/'internal/docs/audits/mediatek-modify-hook-inventory-20261025.csv')
parser.add_argument('--bucket',choices=('all','five-feature','base-only','unsupported'),default='all')
parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args()
root=args.hoard.resolve()
cli=args.fw.resolve()
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
producer=digest(cli)
flash_sha=digest(args.flash) if args.flash else None
rows=list(csv.DictReader(args.baseline.open()))
filters={
 'all':lambda r:True,
 'five-feature':lambda r:r['boot_unrestricted']=='False' and r['boot_hrl']=='True',
 'base-only':lambda r:r['result']=='accepted' and r['boot_hrl']=='False',
 'unsupported':lambda r:r['result']=='unsupported',
}
rows=[r for r in rows if filters[args.bucket](r)]
assert len({r['sha256'] for r in rows})==len(rows),'duplicate input hashes'
identities=json.loads((root/'index/identities.json').read_text())['identities']
paths={i['sha256']:i['path'] for identity in identities if identity['family']=='mediatek' for i in identity['images']}
def query(r):
 p=root/paths[r['sha256']];assert digest(p)==r['sha256']
 q=subprocess.run([str(cli),'capabilities',str(p)],capture_output=True,text=True,timeout=180)
 if q.returncode != 0:
  # The baseline's known malformed artifact is rejected before JSON reporting.
  # Keep that actual command rejection distinct from a Modify capability record.
  if r['result'] != 'invalid-input':
   raise RuntimeError(f'Unexpected capability query rejection: {r["sha256"]}: {q.stderr}')
  assert digest(p)==r['sha256'],'source changed during rejected query'
  return {'sha256':r['sha256'],'path':paths[r['sha256']],'baseline':r,'capability':None,
          'query_failure':{'returncode':q.returncode,'detail':'\n'.join(line for line in q.stderr.splitlines() if not line.startswith('Diagnostic log'))}}
 data=json.loads(q.stdout);assert data['input_sha256']==r['sha256'];assert digest(p)==r['sha256']
 result={'sha256':r['sha256'],'path':paths[r['sha256']],'baseline':r,'capability':data}
 if args.flash and data['status']=='supported':
  with tempfile.TemporaryDirectory(prefix='freemkv-corpus-build-') as temp:
   output=Path(temp)/'modified.bin'
   subprocess.run([str(cli),'modify',str(p),str(output),'--json','--audit'],capture_output=True,text=True,check=True,timeout=180)
   output_sha=digest(output)
   assert output_sha==data['output_sha256'],'preview/build mismatch'
   admission=subprocess.run([str(args.flash.resolve()),'--why',str(p),str(output)],capture_output=True,text=True,check=True,timeout=180)
   gate=admission.stdout.strip().splitlines()[0]
   assert gate.startswith(('admitted','refused:')),admission.stdout+admission.stderr
   result['build_validation']={'output_sha256':output_sha,'preview_matches_build':True,'structural_audit':'passed','flasher_gate':'admitted' if gate.startswith('admitted') else 'refused','flasher_detail':gate}
 assert digest(p)==r['sha256'],'source changed during build'
 return result
with ThreadPoolExecutor(max_workers=4) as pool: results=list(pool.map(query,rows))
assert digest(cli)==producer
assert not args.flash or digest(args.flash)==flash_sha,'flasher changed during audit'
out={'schema':1,'producer_sha256':producer,'flasher_sha256':flash_sha,'bucket':args.bucket,'scope':'exact-image Modify preview plus structural audit; optional actual builds and flasher gates; no physical validation','images':results}
args.output.write_text(json.dumps(out,indent=2)+'\n')
print('statuses',dict(collections.Counter(x['capability']['status'] if x['capability'] else 'query-rejected' for x in results)))
print('unrestricted',dict(collections.Counter(str(((x['capability'] or {}).get('report') or {}).get('boot_settings',{}).get('unrestricted')) for x in results)))
