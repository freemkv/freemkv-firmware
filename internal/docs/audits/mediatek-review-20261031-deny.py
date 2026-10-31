import sys,json,gzip,hashlib,pathlib,concurrent.futures
sys.path.insert(0,str(pathlib.Path.cwd()/'scripts/firmware_execution'))
from stages import DECODER,compare_hook
root=pathlib.Path('/tmp/freemkv-review-clean-final')
def check(folder):
 doc=json.loads((folder/'modify.json').read_text());c=doc['execution_contracts'];stub=c['facts'].get('deny_stub_va')
 if not stub:return None
 original=(folder/'original.bin').read_bytes();modified=(folder/'modified.bin').read_bytes()
 continuation=next(i.address+i.size for i in DECODER.disasm(modified[stub:stub+16],stub) if i.mnemonic=='blx')
 baseline=compare_hook('deny-reset',original,modified,doc['engine'],c)
 assert baseline['status']=='passed',baseline
 mutations=[]
 for offset,opcode in ((0,'0322'),(2,'6e21'),(4,'00bd')):
  data=bytearray(modified);data[continuation+offset:continuation+offset+2]=bytes.fromhex(opcode)
  result=compare_hook('deny-reset',original,bytes(data),doc['engine'],c)
  assert result['status']=='failed' and result.get('failures'),result
  mutations.append({'offset':offset,'replacement':opcode,'detected':True,'failure_count':len(result['failures'])})
 return {'input_sha256':folder.name,'output_sha256':hashlib.sha256(modified).hexdigest(),'baseline_cases':baseline['cases'],'mutants':mutations}
if __name__=='__main__':
 with concurrent.futures.ProcessPoolExecutor(max_workers=4) as p:rows=[r for r in p.map(check,sorted(x.parent for x in root.glob('*/modify.json'))) if r]
 out={'actual_outputs':len(rows),'detected_mutants':sum(len(r['mutants']) for r in rows),'images':rows}
 assert out['actual_outputs']==94 and out['detected_mutants']==282
 pathlib.Path('internal/docs/audits/mediatek-review-20261031-deny-mutations.json').write_text(json.dumps(out,indent=2)+'\n')
 print(out['actual_outputs'],out['detected_mutants'])
