#!/usr/bin/env python3
"""Every-inventory-input production differential audit; fail-closed bounded CPU evidence."""
import argparse
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
import hashlib
import gzip
import io
import tarfile
import stages
import json
from pathlib import Path
import subprocess
import sys
import time
import tomllib
import capstone
import unicorn
from stages import compare_hook


def sha(data): return hashlib.sha256(data).hexdigest()

def command(argv, timeout=180):
    p=subprocess.run(list(map(str,argv)),capture_output=True,text=True,timeout=timeout)
    if p.returncode: raise AssertionError(f'exit {p.returncode}: {p.stderr[-1600:]}')
    return json.loads(p.stdout)


def source_files(repo):
    paths=sorted(set(list((repo/'crates/freemkv-fw/src').rglob('*.rs'))+
                     list((repo/'crates/freemkv-flash/src').rglob('*.rs'))+
                     list((repo/'crates/freemkv-chipset/src').rglob('*.rs'))+
                     [repo/'Cargo.lock',repo/'Cargo.toml']+
                     list((repo/'crates').glob('*/Cargo.toml'))+
                     list((repo/'scripts/firmware_execution').glob('*.py'))+
                     list((repo/'scripts/firmware_execution').glob('*.json'))+
                     list((repo/'scripts/firmware_execution').glob('*.txt'))+
                     list((repo/'scripts').glob('audit-mtk-*.py'))+
                     [repo/'scripts/build-mtk-disc-fixtures.py']+
                     list((repo/'crates/freemkv-flash/locales').glob('*.json'))+
                     [repo/'crates/freemkv-fw/examples/firmware_execution_evidence.rs']))
    return {str(p.relative_to(repo)):sha(p.read_bytes()) for p in paths}


def dependency_files(root):
    paths=list((root/'src').rglob('*'))+[root/'Cargo.toml',root/'build.rs']
    return {str(p.relative_to(root)):sha(p.read_bytes()) for p in sorted(paths) if p.is_file()}


def dependency_package(repo):
    host=next(line.split(': ',1)[1] for line in subprocess.check_output(['rustc','-vV'],text=True).splitlines() if line.startswith('host: '))
    metadata=json.loads(subprocess.check_output(['cargo','metadata','--offline','--format-version','1','--filter-platform',host],cwd=repo,text=True))
    return next(p for p in metadata['packages'] if p['name']=='mediatek-optical')


def source_snapshot(repo, receipt, output, dependency_root):
    """Freeze exact executable sources before any test worker starts."""
    snapshot=output/'source-snapshot.tar.gz'
    items=[(name,repo/name,digest) for name,digest in receipt['source_files'].items()]
    items.extend(('dependency/mediatek-optical/'+name,dependency_root/name,digest)
                 for name,digest in receipt['dependency_source_files'].items())
    with snapshot.open('wb') as raw:
        with gzip.GzipFile(filename='',mode='wb',fileobj=raw,mtime=0) as zipped:
            with tarfile.open(fileobj=zipped,mode='w') as archive:
                for name,path,digest in sorted(items):
                    data=path.read_bytes()
                    assert sha(data)==digest,'source drift while freezing '+name
                    info=tarfile.TarInfo(name);info.size=len(data);info.mode=0o644
                    archive.addfile(info,io.BytesIO(data))
    return {'file':snapshot.name,'sha256':sha(snapshot.read_bytes()),'files':len(items),'bytes':snapshot.stat().st_size}


def process(row, options):
    hoard,output,builder,fw,cli,only_conversion,only_ordinary,producer_only,require_conversion,disc_options=options
    result={'path':row['path'],'input_sha256':row['sha256'],
            'identified_family':row.get('identified_family'),'catalogue_patched':row.get('catalogue_patched'),
            'inventory_bytes':row.get('bytes'),'requested_conversion_goal_qualified':False,'conversion_cpu_qualification':'unqualified: no production output executed','catalogue_identity':row.get('catalogue_identity'),'status':'failed','stages':[],'coverage_gaps':[]}
    source=(Path(hoard)/row['path']).resolve()
    if not source.is_file():
        result.update(status='missing',reason='inventory source unavailable');return result
    data=source.read_bytes();result['actual_bytes']=len(data)
    if sha(data)!=row['sha256']:
        result.update(status='hash-mismatch',reason='inventory source digest mismatch');return result
    folder=Path(output)/row['sha256'];folder.mkdir(parents=True,exist_ok=True)
    try:
        built=command([builder,source,folder]);result['build']=built
        assert built['input_sha256']==row['sha256'],'builder source digest differs from inventory'
        if built['status'] not in ('supported','unchanged'):
            result['status']='production-refusal'
            if built['status']=='invalid-input' and len(data)<2097152:
                result['status']='fragment-or-unrecognized-refusal'
            result['qualification']='none; explicit refusal is not a passing execution test'
            result['coverage_gaps'].append('No final output; OEM/patched CPU comparison unavailable')
            return result
        old=(folder/'original.bin').read_bytes();new=(folder/'modified.bin').read_bytes()
        assert len(old)==len(new),'production output length differs from canonical image'
        assert sha(old)==built['canonical_sha256'] and sha(new)==built['output_sha256']
        if cli:
            production=folder/'production.bin'
            report=command([fw,'modify',source,production,'--json'])
            (folder/'production.json').write_text(json.dumps(report,indent=2)+'\n')
            assert production.read_bytes()==new,'production API/CLI output mismatch'
            result['cli_api_identical']=True
        doc=json.loads((folder/'modify.json').read_text());contracts=doc['execution_contracts']
        result['contracts_sha256']=sha(json.dumps(contracts,sort_keys=True).encode())
        result['canonical_sha256']=sha(old);result['output_sha256']=sha(new)
        result['modify_report_sha256']=sha((folder/'modify.json').read_bytes())
        result['native_parameter_getter']=contracts.get('native_parameter_getter')
        result['classic_application_readiness']=contracts.get('classic_application_readiness')
        result['preserved_native_workflows']=contracts.get('preserved_native_workflows',[])
        facts=contracts['facts']; installed=[]
        contracts['_hoard']=hoard
        for key,name in [('handler_va','vendor-handler'),('boot_stub_va','boot'),
                         ('speed_stub_va','speed'),('region_stub_va','region'),
                         ('gatea_stub_va','vid'),('ake_stub_va','ake'),
                         ('deny_stub_va','deny-reset'),('hrl_stub_va','hrl'),
                         ('auth_cell_stub_va','auth_cell'),('bd_stub_va','bd_site'),
                         ('uhd_stub_va','uhd_site')]:
            if facts.get(key): installed.append(name)
        installed.extend('conversion:'+str(c['site']) for c in contracts.get('media_conversion_helpers',[]))
        result['installed_hook_roles']=installed
        result['registered_hook_reports']=[h for l in doc['levers'] for h in l['hooks']]
        result['lever_outcomes']=[{'id':l['id'],'outcome':l['outcome']} for l in doc['levers']]
        trace_path=folder/'cpu-traces.jsonl.gz'
        stages.TRACE_SINK=gzip.open(trace_path,'wt')
        for hook in installed:
            if producer_only or only_conversion and not hook.startswith('conversion:') or only_ordinary and hook.startswith('conversion:'):
                result['stages'].append({'stage':hook,'status':'not-requested','cases':0,'coverage_gaps':['Hook explicitly excluded by focused run mode; the full corpus run is still required']});continue
            try:
                stage=compare_hook(hook,old,new,built['engine'],contracts)
            except Exception as error:
                stage={'stage':hook,'status':'failed','error':str(error),'cases':0}
            if hook.startswith('conversion:'):
                coverage=stage.get('generated_branch_coverage')
                complete=coverage is not None and not coverage['uncovered'] and not coverage['unvisited_instructions']
                stage['required_generated_coverage_complete']=complete
                if not complete and stage['status']=='passed':
                    stage['status']='failed'
                    stage['error']='Installed conversion helper lacks complete generated instruction/conditional-edge coverage'
            result['stages'].append(stage)
        if disc_options:
            from disc import audit_image, load_fixtures, read_json
            fixture_path, worker_path, fixture_binding, worker_digest = disc_options
            try:
                fixtures = load_fixtures(fixture_path)
                assert fixtures['binding'] == fixture_binding, 'disc fixtures changed during run'
                assert sha(Path(worker_path).read_bytes()) == worker_digest, 'disc worker receipt changed during run'
                workers = {r['source_sha256']:r for r in read_json(worker_path)['images']}
                stage = audit_image(folder, fixtures, workers)
            except Exception as error:
                stage = {'stage':'captured-disc-geometry','status':'failed','cases':0,'error':str(error)}
            result['stages'].append(stage)
        else:
            result['stages'].append({'stage':'captured-disc-geometry','status':'not-requested','cases':0,
                'coverage_gaps':['Captured disc tests require --disc-fixtures and --disc-worker-receipt.']})
        stages.TRACE_SINK.close();stages.TRACE_SINK=None
        result['trace_sha256']=sha(trace_path.read_bytes())
        result['trace_file']=str(trace_path)
        result['changed_bytes']=sum(a!=b for a,b in zip(old,new))
        result['changed_ranges']=[]
        start=None
        for i,(a,b) in enumerate(zip(old,new)):
            if a!=b and start is None: start=i
            if a==b and start is not None: result['changed_ranges'].append([start,i]);start=None
        if start is not None: result['changed_ranges'].append([start,len(old)])
        # Preserve the source-side reviewed optical roles verbatim unless an actual
        # complete conversion plan names the site. This is byte equality, not a
        # claim about dynamic execution or hardware classification.
        conversion=set(contracts.get('media_conversion_sites',[]))
        conversion_spans=[(c['site'],c['site']+len(c['original_bytes'])) for c in contracts.get('media_conversion_helpers',[])]
        checks=[]
        for area in row.get('uhd_code',{}).get('areas',[]):
            a=area.get('site');n=area.get('length',0)
            if a is None: continue
            changed=old[a:a+n]!=new[a:a+n]
            touched=[s for s,e in conversion_spans if s<a+n and a<e]
            unregistered=[i for i in range(a,a+n) if old[i]!=new[i] and not any(s<=i<e for s,e in conversion_spans)]
            checks.append({'role':area['role'],'site':a,'length':n,'changed':changed,
                           'conversion_registered':bool(touched),'registered_patch_sites':touched,'unregistered_changed_bytes':unregistered})
            assert not unregistered,'reviewed OEM role changed outside registered conversion spans: '+area['role']
        result['reviewed_oem_roles_byte_comparison']=checks
        result['coverage_gaps'].extend([
            'No whole-firmware boot, optical acquisition, physical layer reads, AACS or MMIO qualification',
            'Unexecuted native/resident services and dynamic branch targets remain unresolved',
            'Finite software inputs do not establish every firmware path or all initial machine states',
            'Changed-byte ranges retained; arbitrary changed regions are not automatically approved'])
        conversion_reports=[h for h in result['registered_hook_reports'] if h['id']=='uhd-conversion']
        if conversion_reports:
            result['conversion']=conversion_reports[0]
        else:
            result['conversion']={'status':'unavailable','reason':'no registered complete conversion hook'}
        profiles=json.loads(Path(__file__).with_name('profiles.json').read_text())['profiles']
        auth=next((s for s in result['stages'] if s['stage']=='auth_cell'),None)
        result['input_class_coverage']=[{'id':p['id'],'supplied_media_state':p['media_state'],
            'auth_band':p['auth_band'],'bounded_auth_band_contract_passed':bool(auth and auth['status']=='passed'),
            'optical_media_path_qualified':False,'reason':'Named auth bands and CDB key classes do not establish optical acquisition/read paths'} for p in profiles]
        conversion_stages=[s for s in result['stages'] if s['stage'].startswith('conversion:')]
        result['installed_conversion_helper_contracts_passed']=bool(conversion_stages) and all(s['status']=='passed' and s.get('cases',0)>0 for s in conversion_stages)
        result['requested_conversion_goal_qualified']=False
        result['production_conversion_sites']=sorted(conversion)
        result['production_conversion_group_installed']=bool(conversion)
        if require_conversion and row.get('acceptance_group','').endswith('conversion-required'):
            from installed import check_installed
            result['required_installed_conversion']=check_installed(old,new,contracts,result['registered_hook_reports'])
        result['conversion_cpu_qualification']='bounded installed-helper contracts passed; whole optical/media workflow remains unqualified' if result['installed_conversion_helper_contracts_passed'] else 'unqualified: installed helper contracts missing or failed'
        result['conversion_source_readiness']=result['conversion']
        if any(s['status']=='failed' for s in result['stages']):result['status']='failed'
        elif any(s['status']=='unqualified' or s.get('coverage_gaps') for s in result['stages']):result['status']='partial'
        else:result['status']='bounded-pass'
        if not installed:result['status']='static-only'
        if result.get('required_installed_conversion',{}).get('status')=='failed':
            result['status']='failed';result['error']='Required actual final-BIN conversion group missing or invalid'
    except Exception as error:
        result['error']=str(error)
        diagnostic=folder/'audit-failure.json'
        if diagnostic.is_file():
            result['structural_audit_failure']=json.loads(diagnostic.read_text())
            result['failure_artifact_hashes']={p.name:sha(p.read_bytes()) for p in folder.glob('failed-*') if p.is_file()}
            result['failure_artifact_hashes'][diagnostic.name]=sha(diagnostic.read_bytes())
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--inventory',type=Path,required=True);p.add_argument('--hoard',type=Path,required=True)
    p.add_argument('--builder',type=Path,required=True);p.add_argument('--fw',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--workers',type=int,default=4)
    p.add_argument('--baseline-receipt',type=Path,help='Optional JSON or JSON.gz prior receipt for exact canonical/output preservation comparisons; CPU failures remain failures')
    p.add_argument('--disc-fixtures',type=Path,help='Compact captured-DI/ISO fixture directory; execute all bound OEM and modified geometry contracts')
    p.add_argument('--disc-worker-receipt',type=Path,help='Source-bound DI worker receipt (JSON or JSON.gz); required with --disc-fixtures')
    p.add_argument('--dependency-commit',default='45e5a98b6085e938986456b098434720dd8ae368',help='Explicit expected mediatek-optical commit; verified against its Cargo.lock package source')
    p.add_argument('--only-ordinary',action='store_true',help='Focused ordinary hook run; conversion helpers are explicitly not-requested')
    p.add_argument('--only-conversion',action='store_true',help='Focused installed conversion helper run; every omitted ordinary hook is explicitly not-requested')
    p.add_argument('--producer-only',action='store_true',help='Actual API/CLI and structural output checks only; every CPU hook explicitly not-requested')
    p.add_argument('--require-installed-conversion',action='store_true',help='Fail conversion-required scope rows unless an actual complete final-BIN group exists; refusal is not conversion success')
    p.add_argument('--build',action='store_true',help='Build production executables and require identical source manifests before/after cargo')
    p.add_argument('--no-cli',action='store_true',help='API output only; records absence of CLI comparison')
    args=p.parse_args();repo=Path(__file__).resolve().parents[2]
    assert not(args.only_conversion and args.only_ordinary),'choose only one focused mode'
    assert bool(args.disc_fixtures) == bool(args.disc_worker_receipt), 'supply both disc fixture and worker receipt paths'
    disc_options = None
    if args.disc_fixtures:
        from disc import load_fixtures
        fixtures = load_fixtures(args.disc_fixtures)
        disc_options = (str(args.disc_fixtures.resolve()), str(args.disc_worker_receipt.resolve()),
                        fixtures['binding'], sha(args.disc_worker_receipt.read_bytes()))
    build_binding=None
    if args.build:
        assert args.builder.resolve()==repo/'target/release/examples/firmware_execution_evidence' and args.fw.resolve()==repo/'target/release/freemkv-fw','--build requires the local release artifacts'
        before=source_files(repo)
        build_package=dependency_package(repo)
        build_dependency_root=Path(build_package['manifest_path']).parent
        dependency_before=dependency_files(build_dependency_root)
        build_command=['cargo','build','--release','-p','freemkv-fw','--example','firmware_execution_evidence','--bin','freemkv-fw']
        build=subprocess.run(build_command,cwd=repo,capture_output=True,text=True,timeout=1200)
        print(build.stderr,file=sys.stderr)
        assert build.returncode==0,'production build failed'
        after=source_files(repo)
        assert before==after,'source changed while building production executables'
        assert dependency_before==dependency_files(build_dependency_root),'dependency source changed while building production executables'
        build_binding={'command':build_command,'source_files_sha256':sha(json.dumps(before,sort_keys=True).encode()),
            'source_files_unchanged':True,'build_stderr_sha256':sha(build.stderr.encode()),
            'dependency_source_files_sha256':sha(json.dumps(dependency_before,sort_keys=True).encode()),
            'cargo':subprocess.check_output(['cargo','--version'],text=True).strip(),
            'rustc':subprocess.check_output(['rustc','--version'],text=True).strip()}
    inventory=json.loads(args.inventory.read_text())['images']
    baseline={}
    if args.baseline_receipt:
        raw=args.baseline_receipt.read_bytes()
        baseline_data=json.loads(gzip.decompress(raw) if args.baseline_receipt.suffix=='.gz' else raw)
        baseline={r['input_sha256']:r for r in baseline_data['images']}
    hashes=[r['sha256'] for r in inventory];assert len(hashes)==len(set(hashes)),'duplicate inventory hashes'
    lock=(repo/'Cargo.lock').read_text();pin=args.dependency_commit
    assert len(pin)==40 and all(c in '0123456789abcdef' for c in pin),'expected an exact dependency commit'
    dependency=[v for v in tomllib.loads(lock)['package'] if v['name']=='mediatek-optical']
    assert len(dependency)==1 and dependency[0].get('source','').endswith('#'+pin),'unexpected mediatek-optical package source pin'
    package=dependency_package(repo)
    assert package['source']==dependency[0]['source'],'Cargo metadata dependency source differs from lock'
    dependency_root=Path(package['manifest_path']).parent
    args.output.mkdir(parents=True,exist_ok=True)
    receipt={'schema':'mediatek-production-differential-v2','status':'running','started_unix':time.time(),
        'scope':'All supplied corpus entries accounted for; bounded installed-hook CPU comparisons only',
        'requested_conversion_goal_qualified':False,
        'optical_span_byte_equality_is_conversion_coverage':False,
        'requested_input_classes':json.loads(Path(__file__).with_name('profiles.json').read_text())['profiles'],
        'whole_firmware_paths_qualified':False,'physical_uhd_qualified':False,
        'cpu_profiles':{'MT1939':'ARM926 ARMv5 Thumb1','MT1959':'Cortex-A8 ARMv7 ARM+Thumb2'},
        'cpu_profile_basis':'User-specified family ISA assumption; not a hardware-identification proof. Common generated helpers retain a separate Thumb1 CFG contract.',
        'unicorn':unicorn.__version__,
        'capstone':capstone.__version__,'python':sys.version,'dependency_commit':pin,
        'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip(),
        'source_files':source_files(repo),
        'dependency_source_files':dependency_files(dependency_root),
        'related_prepared_helper_receipts':{str(p.relative_to(repo)):sha(p.read_bytes()) for p in (repo/'internal/docs/audits').glob('*prepared-helper-cpu*.json')},
        'native_policy_oracle_receipts':{str(p.relative_to(repo)):sha(p.read_bytes()) for p in (repo/'internal/docs/audits').glob('mt1959-native-*policy-20261031.json')},
        'inventory_sha256':sha(args.inventory.read_bytes()),
        'disc_fixture_binding':disc_options[2] if disc_options else None,
        'disc_worker_receipt_sha256':disc_options[3] if disc_options else None,
        'baseline_receipt_sha256':sha(args.baseline_receipt.read_bytes()) if args.baseline_receipt else None,
        'builder_sha256':sha(args.builder.read_bytes()),'cli_sha256':sha(args.fw.read_bytes()),
        'build_binding':build_binding,'cli_comparison_enabled':not args.no_cli,'expected_images':len(inventory),'images':[]}
    if build_binding:
        assert build_binding['source_files_sha256']==sha(json.dumps(receipt['source_files'],sort_keys=True).encode()),'source changed between build and run binding'
        assert build_binding['dependency_source_files_sha256']==sha(json.dumps(receipt['dependency_source_files'],sort_keys=True).encode()),'dependency source changed between build and run binding'
    receipt['source_snapshot']=source_snapshot(repo,receipt,args.output,dependency_root)
    options=(str(args.hoard.resolve()),str(args.output.resolve()),str(args.builder.resolve()),str(args.fw.resolve()),not args.no_cli,args.only_conversion,args.only_ordinary,args.producer_only,args.require_installed_conversion,disc_options)
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        futures={pool.submit(process,row,options):row for row in inventory}
        for f in as_completed(futures):
            row=futures[f]
            try:r=f.result()
            except Exception as error:r={'input_sha256':row['sha256'],'path':row['path'],'status':'worker-failed','error':str(error)}
            if args.baseline_receipt:
                old=baseline.get(row['sha256'])
                available=old is not None and all(k in old and k in r for k in ('canonical_sha256','output_sha256'))
                r['baseline_comparison']={'status':'compared' if available else 'unavailable',
                    'baseline_label':old.get('baseline_label') if old else None,
                    'canonical_identical':available and old['canonical_sha256']==r['canonical_sha256'],
                    'output_identical':available and old['output_sha256']==r['output_sha256'],
                    'baseline_output_sha256':old.get('output_sha256') if old else None,
                    'scope':'Exact bytes only; does not qualify unexecuted paths or override CPU failures'}
            receipt['images'].append(r)
            print(f'{len(receipt["images"])}/{len(inventory)} {row["sha256"][:12]} {r["status"]}',flush=True)
            (args.output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    receipt['images'].sort(key=lambda r:r['path'])
    receipt['totals']=dict(Counter(r['status'] for r in receipt['images']))
    receipt['stage_totals']=dict(Counter(s['status'] for r in receipt['images'] for s in r.get('stages',[])))
    receipt['stage_counts_by_role']=dict(Counter(s['stage']+':'+s['status'] for r in receipt['images'] for s in r.get('stages',[])))
    coverages=[s['generated_branch_coverage'] for r in receipt['images'] for s in r.get('stages',[]) if 'generated_branch_coverage' in s]
    receipt['generated_coverage_totals']={key:sum(c[key] for c in coverages) for key in ('conditional_edges','covered_edges','reachable_generated_instructions','covered_generated_instructions')}
    receipt['generated_coverage_totals']['unvisited_instructions']=sum(len(c['unvisited_instructions']) for c in coverages)
    receipt['generated_coverage_totals']['uncovered_edges']=sum(len(c['uncovered']) for c in coverages)
    for prefix,conversion in [('conversion',True),('ordinary',False)]:
        covered=[s['generated_branch_coverage'] for r in receipt['images'] for s in r.get('stages',[])
                 if s['stage'].startswith('conversion:')==conversion and 'generated_branch_coverage' in s]
        totals={key:sum(c[key] for c in covered) for key in ('conditional_edges','covered_edges','reachable_generated_instructions','covered_generated_instructions')}
        totals['unvisited_instructions']=sum(len(c['unvisited_instructions']) for c in covered)
        totals['uncovered_edges']=sum(len(c['uncovered']) for c in covered)
        receipt[prefix+'_generated_coverage_totals']=totals
    receipt['cpu_cases']=sum(s.get('cases',0) for r in receipt['images'] for s in r.get('stages',[]))
    receipt['attempted_cpu_cases']=sum(s.get('cases',0)+len(s.get('failures',[])) for r in receipt['images'] for s in r.get('stages',[]))
    receipt['bounded_contract_acceptance_passed']=not any(r['status'] in ('failed','worker-failed','missing','hash-mismatch') or any(s['status']=='failed' for s in r.get('stages',[])) for r in receipt['images'])
    receipt['all_inventory_images_qualified']=all(r['status']=='bounded-pass' for r in receipt['images'])
    receipt['source_files_unchanged']=receipt['source_files']==source_files(repo)
    receipt['dependency_sources_unchanged']=receipt['dependency_source_files']==dependency_files(dependency_root)
    receipt['binaries_unchanged']=receipt['builder_sha256']==sha(args.builder.read_bytes()) and receipt['cli_sha256']==sha(args.fw.read_bytes())
    receipt['finished_unix']=time.time()
    receipt['status']='completed-with-gaps' if receipt['source_files_unchanged'] and receipt['dependency_sources_unchanged'] and receipt['binaries_unchanged'] else 'source-drift-invalidated'
    (args.output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({k:receipt[k] for k in ('status','totals','stage_totals','cpu_cases','source_files_unchanged')}))
    return 1 if not receipt['bounded_contract_acceptance_passed'] or not receipt['source_files_unchanged'] or not receipt['dependency_sources_unchanged'] or not receipt['binaries_unchanged'] else 0

if __name__=='__main__':sys.exit(main())
