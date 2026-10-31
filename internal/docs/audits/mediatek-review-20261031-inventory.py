"""Inventory literal halfword masks; this is not a replacement for source contracts."""
import re,json,pathlib,hashlib,concurrent.futures,collections,subprocess
repo=pathlib.Path.cwd()
metadata=json.loads(subprocess.check_output(['cargo','metadata','--format-version','1'],text=True))
dep=pathlib.Path(next(p['manifest_path'] for p in metadata['packages'] if p['name']=='mediatek-optical')).parent
files=list((repo/'crates/freemkv-fw/src/engine').glob('*.rs'))+list((dep/'src/image/analysis').glob('*.rs'))
pair=re.compile(r'\((0[xX][\da-fA-F_]+|\d+),\s*(0[xX][\da-fA-F_]+|\d+)\)')
patterns=[]
for f in sorted(files):
 if 'test' in f.name:continue
 text=f.read_text();text=re.split(r'#\[cfg\(test\)\]\s*(?:#\[path[^\n]*\]\s*)?mod ',text)[0]
 scan_text=re.sub(r'//[^\n]*',lambda m:' '*len(m[0]),text)
 for m in re.finditer(r'&\[([^\[\]]*)\]',scan_text,re.S):
  body=re.sub(r'//[^\n]*','',m[1]);values=pair.findall(body)
  if not values or re.sub(r'[\s,]','',pair.sub('',body)):continue
  pairs=[(int(a.replace('_',''),0),int(b.replace('_',''),0)) for a,b in values]
  if any(a>65535 or b>65535 for a,b in pairs):continue
  prefix=text[max(0,m.start()-250):m.start()]
  name=re.search(r'(?:const|let)\s+(\w+)[^=]*=\s*$',prefix)
  role=re.search(r'area:\s*UhdArea::(\w+),\s*name:\s*"([^"]+)"',prefix)
  label=name[1] if name else ':'.join(role.groups()) if role else 'inline-mask'
  patterns.append({'owner':'freemkv-fw' if f.is_relative_to(repo) else 'mediatek-optical','file':str(f.relative_to(repo if f.is_relative_to(repo) else dep)),'line':text[:m.start()].count('\n')+1,'name':label,'halfwords':pairs,'normalized':[(a&b,b) for a,b in pairs],'source_sha256':hashlib.sha256(f.read_bytes()).hexdigest()})
outpath=repo/'internal/docs/audits/mediatek-review-20261031-signatures.json'
prior=json.loads(outpath.read_text()) if outpath.exists() else {'patterns':[]}
cache={str(p['normalized']):p['corpus_matches'] for p in prior['patterns']}
key=lambda p:str([list(v) for v in p['normalized']])
new={key(p):p for p in patterns if key(p) not in cache}
compiled=[]
for k,p in new.items():
 parts=[]
 for a,b in p['normalized']:
  for shift in (0,8):
   v=(a>>shift)&255;mask=(b>>shift)&255
   parts.append(b'['+b''.join(('\\x%02x'%i).encode() for i in range(256) if i&mask==v)+b']')
 compiled.append((k,re.compile(b'(?=('+b''.join(parts)+b'))',re.S)))
rows=json.loads((repo/'internal/docs/audits/mediatek-oem-only-123-retained-20261031.json').read_text())['images']
def scan(row):
 data=(pathlib.Path('/opt/review-home/Developer/firmware-extractor/hoard')/row['path']).read_bytes()
 assert hashlib.sha256(data).hexdigest()==row['sha256']
 return row['sha256'],{k:sum(m.start()%2==0 for m in pat.finditer(data)) for k,pat in compiled}
if __name__=='__main__':
 with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:results=list(pool.map(scan,rows))
 for k in new:cache[k]={sha:counts[k] for sha,counts in results if counts[k]}
 groups=collections.defaultdict(list)
 for p in patterns:
  p['corpus_matches']=cache[key(p)];p['matching_inputs']=len(p['corpus_matches'])
  groups[key(p)].append(p['owner']+':'+p['file']+':'+str(p['line'])+':'+p['name'])
 out={'scope':'All literal borrowed arrays containing only numeric halfword (value,mask) pairs in engine and dependency image/analysis production code, including inline masks and UHD layout definitions. Excludes dynamically constructed/decoded grammars and receiver analysis. Normalized mask scans are syntactic candidates, NOT accepted source contracts; even raw file offsets and overlapping matches.','declarations':len(patterns),'unique_normalized_patterns':len(groups),'owners':dict(collections.Counter(p['owner'] for p in patterns)),'duplicates':[v for v in groups.values() if len(v)>1],'patterns':patterns,'native_role_variants':dict(collections.Counter(a['role']+':'+a.get('variant','unbound') for r in rows for a in r['uhd_code']['areas']))}
 outpath.write_text(json.dumps(out,indent=2)+'\n');print({k:v for k,v in out.items() if k not in ('patterns','native_role_variants')})
