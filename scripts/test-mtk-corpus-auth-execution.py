"""Execute every installed authentication hook from retained corpus artifacts."""
import json,importlib.util,hashlib,argparse
from pathlib import Path
root=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--review',type=Path,required=True)
parser.add_argument('--hoard',type=Path,required=True)
parser.add_argument('--corpus',type=Path,default=Path('final-corpus.json'))
parser.add_argument('--artifacts',type=Path,default=Path('final-images'))
parser.add_argument('--output',type=Path,default=Path('final-auth-cpu.jsonl'))
args=parser.parse_args()
spec=importlib.util.spec_from_file_location('hooks',root/'scripts/test-mtk-hook-execution.py');hooks=importlib.util.module_from_spec(spec);spec.loader.exec_module(hooks)
p=args.review;h=args.hoard;rows=json.loads((p/args.corpus).read_text())['images'];cases=0;images=0
with (p/args.output).open('w') as output:
 for row in rows:
  if (row.get('capability')or{}).get('status')!='supported':continue
  report=json.loads((p/args.artifacts/row['sha256']/'modify.json').read_text());facts={k:v for lever in report['levers'] for k,v in lever['facts'].items()};site=facts.get('auth_cell_site',0)
  if not site:continue
  original=(h/row['path']).read_bytes();assert hashlib.sha256(original).hexdigest()==row['sha256'];modified=(p/args.artifacts/row['sha256']/'modified.bin').read_bytes();assert hashlib.sha256(modified).hexdigest()==row['build_validation']['output_sha256']
  comparison=int.from_bytes(original[site:site+2],'little');assert comparison in (0x280c,0x290c);reg=(comparison>>8)&7;branch=int.from_bytes(original[site+2:site+4],'little');assert branch&0xff00==0xd100;deny=site+6+int.from_bytes(bytes([branch&255]),'little',signed=True)*2
  refusal=facts.get('auth_cell_native_refusal');flag_base=facts.get('flag_base',0x02000e40);count=0
  for setting in (0,1,255,2):
   for value in range(256 if refusal else 16):
    old_target,old_flags=hooks.execute(original,site,deny,value,setting,reg,flag_base)
    target,flags=hooks.execute(modified,site,deny,value,setting,reg,flag_base,refusal)
    expected=(refusal if setting==0 and value==12 else old_target) if refusal else (deny if setting==0 else site+4 if setting==1 else old_target)
    assert target==expected,(row['sha256'],value,setting,target,expected)
    assert flags==old_flags,(row['sha256'],value,setting,'CMP flags')
    cases+=1;count+=1
  output.write(json.dumps({'input_sha256':row['sha256'],'cases':count,'continuations':'passed','registers':'passed','stack':'passed','flags':'passed'})+'\n');output.flush();images+=1
  if images%25==0:print(images,cases,flush=True)
print('PASS',images,'images',cases,'cases')
