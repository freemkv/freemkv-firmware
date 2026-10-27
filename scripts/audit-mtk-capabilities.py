"""Re-query baseline corpus buckets through the actual exact-image Modify planner."""
import argparse,csv,json,hashlib,subprocess,collections,tempfile
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
parser=argparse.ArgumentParser(description='Query exact-image Modify capabilities and optionally build/audit/gate every supported input.')
parser.add_argument('--hoard',type=Path,required=True)
parser.add_argument('--fw',type=Path,required=True)
parser.add_argument('--gate','--flash',dest='flash',type=Path,help='Path to freemkv-crossflash, the offline compatibility evaluator')
parser.add_argument('--baseline',type=Path,default=Path(__file__).resolve().parents[1]/'internal/docs/audits/mediatek-modify-hook-inventory-20261025.csv')
parser.add_argument('--bucket',choices=('all','five-feature','base-only','unsupported'),default='all')
parser.add_argument('--output',type=Path,required=True)
parser.add_argument('--artifacts',type=Path,help='Retain each built BIN and full Modify report for per-input review')
parser.add_argument('--keep-going',action='store_true',help='Record unexpected per-input failures, finish the corpus, and exit nonzero')
args=parser.parse_args()
root=args.hoard.resolve()
if args.artifacts:
 args.artifacts=args.artifacts.resolve()
 args.artifacts.mkdir(parents=True,exist_ok=True)
cli=args.fw.resolve()
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
producer=digest(cli)
flash_sha=digest(args.flash) if args.flash else None
if args.flash:
 help_result=subprocess.run([str(args.flash.resolve()),'--help'],capture_output=True,text=True,check=True,timeout=30)
 if 'freemkv-crossflash --why' not in help_result.stdout:
  parser.error('--gate requires freemkv-crossflash, not the main Flash CLI')
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
   directory=args.artifacts/r['sha256'] if args.artifacts else Path(temp)
   directory.mkdir(parents=True,exist_ok=True)
   output=directory/'modified.bin'
   if args.artifacts:
    (directory/'capabilities.json').write_text(json.dumps(data,indent=2)+'\n')
   reused=bool(args.artifacts and output.is_file() and (directory/'modify.json').is_file()
               and digest(output)==data['output_sha256'])
   if not reused:
    built=subprocess.run([str(cli),'modify',str(p),str(output),'--json','--audit'],capture_output=True,text=True,check=True,timeout=180)
    if args.artifacts:
     # Preserve complete successful evidence; a later gate error must not lose it.
     (directory/'modify.json').write_text(built.stdout)
     (directory/'modify.stderr.log').write_text(built.stderr)
   if args.artifacts:
    (directory/'build-receipt.json').write_text(json.dumps({'producer_sha256':producer,
     'input_sha256':r['sha256'],'output_sha256':data['output_sha256'],
     'audit':'passed','reused_verified_output':reused},indent=2)+'\n')
   output_sha=digest(output)
   assert output_sha==data['output_sha256'],'preview/build mismatch'
   admission=subprocess.run([str(args.flash.resolve()),'--why',str(p),str(output)],capture_output=True,text=True,check=True,timeout=180)
   if args.artifacts:
    (directory/'flash-admission.txt').write_text(admission.stdout+admission.stderr)
   gate=admission.stdout.strip().splitlines()[0]
   assert gate.startswith(('admitted','refused:')),admission.stdout+admission.stderr
   result['build_validation']={'output_sha256':output_sha,'preview_matches_build':True,'structural_audit':'passed','flasher_gate':'admitted' if gate.startswith('admitted') else 'refused','flasher_detail':gate}
   if args.artifacts:
    (directory/'failure.json').unlink(missing_ok=True)
 assert digest(p)==r['sha256'],'source changed during build'
 return result
def checked_query(row):
 try:
  return query(row)
 except Exception as error:
  if not args.keep_going:
   raise
  details={'type':type(error).__name__,'detail':str(error)}
  for field in ('stdout','stderr'):
   value=getattr(error,field,None)
   if value:
    details[field]=value
  capability=None
  if args.artifacts:
   directory=args.artifacts/row['sha256']
   directory.mkdir(parents=True,exist_ok=True)
   recorded=directory/'capabilities.json'
   if recorded.exists():
    capability=json.loads(recorded.read_text())
   (directory/'failure.json').write_text(json.dumps(details,indent=2)+'\n')
  return {'sha256':row['sha256'],'path':paths.get(row['sha256']),'baseline':row,
          'capability':capability,'unexpected_failure':details}
results=[]
with args.output.with_suffix('.progress.jsonl').open('w') as progress:
 with ThreadPoolExecutor(max_workers=4) as pool:
  for result in pool.map(checked_query,rows):
   results.append(result)
   progress.write(json.dumps(result)+'\n');progress.flush()
   if len(results)%25==0 or len(results)==len(rows):
    print(f'Processed {len(results)}/{len(rows)} inputs; {sum("unexpected_failure" in r for r in results)} unexpected failures',flush=True)
assert digest(cli)==producer
assert not args.flash or digest(args.flash)==flash_sha,'flasher changed during audit'
out={'schema':1,'producer_sha256':producer,'flasher_sha256':flash_sha,'bucket':args.bucket,'scope':'exact-image Modify preview plus structural audit; optional actual builds and flasher gates; no physical validation','images':results}
args.output.write_text(json.dumps(out,indent=2)+'\n')
print('statuses',dict(collections.Counter(x['capability']['status'] if x['capability'] else 'query-rejected' for x in results)))
print('unrestricted',dict(collections.Counter(str(((x['capability'] or {}).get('report') or {}).get('boot_settings',{}).get('unrestricted')) for x in results)))

if any('unexpected_failure' in row for row in results):
 raise SystemExit(1)
