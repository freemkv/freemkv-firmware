"""Paired baseline/final production API timings across the frozen retained corpus."""
import json,pathlib,subprocess,time,hashlib,statistics,platform
repo=pathlib.Path.cwd();root=pathlib.Path('/tmp/freemkv-review-benchmark');root.mkdir(exist_ok=True)
rows=json.loads((repo/'internal/docs/audits/mediatek-oem-only-123-retained-20261031.json').read_text())['images']
executables={'before':pathlib.Path('/tmp/freemkv-review-baseline/builder'),'after':repo/'target/release/examples/firmware_execution_evidence'}
results=[]
for n,row in enumerate(rows):
 item={'input_sha256':row['sha256'],'group':row['acceptance_group']}
 # Alternate ordering to reduce systematic warm-cache and thermal bias.
 for label in (('before','after') if n%2==0 else ('after','before')):
  directory=root/label;directory.mkdir(exist_ok=True)
  source=pathlib.Path('/opt/review-home/Developer/firmware-extractor/hoard')/row['path']
  assert hashlib.sha256(source.read_bytes()).hexdigest()==row['sha256']
  started=time.perf_counter();p=subprocess.run([str(executables[label]),str(source),str(directory)],capture_output=True,text=True,check=True)
  elapsed=time.perf_counter()-started;doc=json.loads(p.stdout)
  item[label]={'production_api_seconds':doc['build_seconds'],'process_seconds':elapsed,'output_sha256':doc['output_sha256']}
 assert item['before']['output_sha256']==item['after']['output_sha256']
 results.append(item);print(n+1,flush=True)
summary={}
for group in ['all']+sorted({r['group'] for r in results}):
 chosen=[r for r in results if group=='all' or r['group']==group]
 before=sum(r['before']['production_api_seconds'] for r in chosen);after=sum(r['after']['production_api_seconds'] for r in chosen)
 summary[group]={'inputs':len(chosen),'before_api_seconds':before,'after_api_seconds':after,'reduction_percent':100*(before-after)/before,'median_paired_ratio':statistics.median(r['after']['production_api_seconds']/r['before']['production_api_seconds'] for r in chosen)}
out={'method':'Single paired round over all 123 actual inputs, sequential processes, alternating before/after order. API timer covers native analysis, planning, emission, integrity and boot settings; excludes artifact parsing and subsequent evidence/audit export. No isolated decoder microbenchmark; no inferred firmware execution speedup. Timing has normal host/thermal variance.','platform':platform.platform(),'executables':{k:{'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for k,p in executables.items()},'summary':summary,'images':results}
(repo/'internal/docs/audits/mediatek-review-20261031-performance.json').write_text(json.dumps(out,indent=2)+'\n');print(summary)
