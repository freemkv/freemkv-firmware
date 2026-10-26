"""Recheck baseline allocation refusals and independently map eligible FF holes.

This map describes allocator candidates, not a proof that all padding is unused.
"""
import argparse,csv,json,struct,re,hashlib,subprocess,concurrent.futures,tempfile
from pathlib import Path
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--hoard', required=True, type=Path)
parser.add_argument('--fw', required=True, type=Path)
parser.add_argument('--baseline', type=Path, default=Path(__file__).resolve().parents[1]/'internal/docs/audits/mediatek-modify-hook-inventory-20261025.csv')
parser.add_argument('--output', required=True, type=Path)
parser.add_argument('--flash', type=Path, help='also build/audit and check admission for OEM/dump cases')
args=parser.parse_args()
root=args.hoard.resolve();cli=str(args.fw.resolve())
producer_sha=hashlib.sha256(args.fw.read_bytes()).hexdigest()
flash_sha=hashlib.sha256(args.flash.read_bytes()).hexdigest() if args.flash else None
rows=[r for r in csv.DictReader(args.baseline.open()) if r['result']=='insufficient-safe-space']
identities=json.loads((root/'index/identities.json').read_text())['identities']
paths={image['sha256']:image['path'] for identity in identities if identity['family']=='mediatek' for image in identity['images']}
reserved=[(0,0x1000),(0x3000,0x3020),(0xfff0,0x10400),(0x10400,0x105c0),(0x105c0,0x10610),(0x1d8000,0x1ec100),(0x1f0000,0x200000)]
def run(r):
 file=root/paths[r['sha256']];b=file.read_bytes();assert hashlib.sha256(b).hexdigest()==r['sha256']
 coverage=[]
 for i in range(16):
  flag,start,end=struct.unpack_from('<III',b,0x10400+i*28)
  if flag==1 and start<=end<len(b):coverage.append((start,end+1))
 holes=[]
 for match in re.finditer(b'\xff{4,}',b):
  lo,hi=match.span();lo=max(lo,0x9c00)
  pieces=[(lo,hi)] if lo<hi else []
  for a,z in reserved:
   pieces=[p for x,y in pieces for p in ([(x,y)] if z<=x or a>=y else ([(x,a)] if x<a else [])+([(z,y)] if z<y else []))]
  for x,y in pieces:
   for a,z in coverage:
    l=(max(x,a)+3)&~3;h=min(y,z)
    if h-l>=4:holes.append((l,h))
 holes=sorted(set(holes));merged=[]
 for l,h in holes:
  if merged and l<=merged[-1][1]:merged[-1]=(merged[-1][0],max(h,merged[-1][1]))
  else:merged.append((l,h))
 q=subprocess.run([cli,'capabilities',str(file)],capture_output=True,text=True,check=True,timeout=120)
 assert hashlib.sha256(file.read_bytes()).hexdigest()==r['sha256'], 'source changed'
 result={**r,'path':paths[r['sha256']],'coverage':coverage,'eligible_holes':[{'start':l,'end':h,'bytes':h-l} for l,h in merged], 'total_eligible_bytes':sum(h-l for l,h in merged),'largest_hole':max([h-l for l,h in merged],default=0),'capability':json.loads(q.stdout)}
 if args.flash and Path(paths[r['sha256']]).parts[0] in ('oem','dump') and result['capability']['status']=='supported':
  with tempfile.TemporaryDirectory(prefix='freemkv-allocation-validation-') as temp:
   output=Path(temp)/'modified.bin'
   built=subprocess.run([cli,'modify',str(file),str(output),'--json','--audit'],capture_output=True,text=True,check=True,timeout=120)
   report=json.loads(built.stdout)
   output_sha=hashlib.sha256(output.read_bytes()).hexdigest()
   assert output_sha==result['capability']['output_sha256'], 'preview/build output mismatch'
   admission=subprocess.run([str(args.flash.resolve()),'--why',str(file),str(output)],capture_output=True,text=True,check=True,timeout=120)
   assert 'admitted' in admission.stdout, admission.stdout+admission.stderr
   result['build_validation']={'output_sha256':output_sha,'preview_matches_build':True,'structural_audit':'passed','flasher_gate':'admitted','levers':{p['id']:p['outcome'] for p in report['levers']}}
 assert hashlib.sha256(file.read_bytes()).hexdigest()==r['sha256'], 'source changed during build validation'
 print(r['model'],r['revision'],'largest',result['largest_hole'],'total',result['total_eligible_bytes'],result['capability'].get('detail'),flush=True)
 return result
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:results=list(pool.map(run,rows))
assert hashlib.sha256(args.fw.read_bytes()).hexdigest()==producer_sha, 'modifier changed during audit'
assert not args.flash or hashlib.sha256(args.flash.read_bytes()).hexdigest()==flash_sha, 'flasher changed during audit'
args.output.write_text(json.dumps({'schema':1,'producer_sha256':producer_sha,'flasher_sha256':flash_sha,'images':results},indent=2)+'\n')
