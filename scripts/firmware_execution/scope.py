#!/usr/bin/env python3
"""Frozen OEM-only126 production/CLI/helper audit plus native-role matrix.

One corpus run owns actual production authoring. Explicit refusals are retained;
only their original OEM code is executed through --native-only evidence.
"""
import argparse
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
import gzip
import json
from pathlib import Path
import subprocess
import sys
import time

import corpus
import native
import stages

ROLES=('DiscInformation','ControlBit','ControlField','ForwardCalculation',
       'ReverseCalculation','ParameterNibble')
EXPECTED_GROUPS={'newer-native':85,'older-conversion-required':12,
                 'classic-conversion-required':29}
REFUSAL_PREFIXES=('40118f8171da','d286c5a7ea4a','5e2ec51fb355')
FEATURE_FACTS={'speed':{'speed':'speed_stub_va'},'region':{'region':'region_stub_va'},
 'encryption':{'ake':'ake_stub_va','deny-reset':'deny_stub_va'},'hrl':{'hrl':'hrl_stub_va'},
 'unrestricted':{'vid':'gatea_stub_va','auth_cell':'auth_cell_stub_va',
                 'bd_site':'bd_stub_va','uhd_site':'uhd_stub_va'}}
MINIMUM_FEATURE_ROLE={'speed':'speed','region':'region','encryption':'ake','hrl':'hrl','unrestricted':'vid'}


# Exact reviewed boundary statements only. Missing source contracts, absent
# helpers, incomplete generated CFG and arbitrary new gaps never enter here.
REVIEWED_GAPS={
 'Native reset completion remains external; post-call replay/return tested independently with declared ABI return-state inputs':'unchanged-native reset completion; separately executed generated continuation',
 'Native position reflection/range worker bodies remain outside this decode boundary':'separate full native layer decoder test; external range/controller lifecycle', 
 'Vendor tests stop at OEM handler/first response-writer call; later reply loops, commit, reset/save/flash/debug dispatch and opaque services remain unqualified':'unchanged-native-response/service boundary outside advertised settings SET/GET contract',
 'Native initialization call and its return remain unexecuted; hardware/resident effects unknown':'unchanged-native-initialization boundary',
 'Forced-region contract conflict: ABI BD states 0x0a..0x0c are routed to OEM by the emitted <0x11 guard; source comments name 0x2a..0x2c instead. BootSettings exposes only OEM/free.':'unadvertised experimental region setting; advertised OEM/free separately executed',
 'Encryption Off reaches native reset; reset effects and return path unqualified':'unchanged-native-reset/resident boundary',
 'Source-bound local reset and boot clear are separate from complete per-disc insertion/rearm ordering':'external insertion/lifecycle producer',
 'Density selection/flags only; no measurement return, arithmetic MMIO or controller completion is manufactured':'external measurement/MMIO completion',
 'Actual final-BIN/held ARM divide/normalization only; phase producer/lifetime and controller sink remain separate requirements':'external phase/controller producer',
 'Source-bound post-acquisition parser context only; no full acquisition, ready/controller completion or physical read qualification':'external acquisition/controller completion',
 'DI entered after acquisition/BD-prefix validation; no acquisition, ready flag or native return/hardware completion qualified':'external acquisition/controller completion',
 'Selector qualified; downstream arithmetic gets a separate native-worker boundary test':'separate native-worker contract',
 'Startup coefficient values supplied as labeled synthetic runtime table inputs; actual initialized NV profile/producer remains unknown':'explicit parameterized NV-table inputs',
 'Out-of-range getter requests stop at real OEM logging call; logger/resident return and subsequent clamp remain unexecuted':'unchanged-native logger/resident boundary',
 'Parameterized synthetic runtime table inputs prove selection/index behavior; actual initialized calibration values/producer remain unknown':'explicit parameterized calibration-table inputs',
 'Full native layer decode/store suffix only; subsequent range/controller lifecycle remains unexecuted':'external range/controller lifecycle',
 'Arithmetic entered with declared inherited bases/measurement and phase byte; enclosing producers, phase transitions and final controller sink remain unexecuted':'held native operand/phase/controller boundaries',
 'Native identifier/format/layer admission slice after attribute/acquisition predicates; later shared format/layer stores and complete parser caller are outside this stage':'held native parser/acquisition boundary',
}


def review_gaps(result):
    reviewed=[];unreviewed=[]
    for stage in result.get('stages',[])+result.get('native_role_execution',{}).get('stages',[]):
        for gap in stage.get('coverage_gaps',[]):
            category=REVIEWED_GAPS.get(gap)
            if gap.startswith('Vendor tests stop') and not result.get('advertised_settings_dispatch',{}).get('qualified'):
                category=None
            if gap.startswith('Forced-region contract conflict:') and stage.get('advertised_settings')!=[255,1] and set(stage.get('advertised_settings',[]))!={1,255}:
                category=None
            item={'stage':stage['stage'],'gap':gap,'boundary_class':category}
            (reviewed if category is not None else unreviewed).append(item)
    return {'reviewed_boundaries':reviewed,'unreviewed_software_gaps':unreviewed}


def native_row(row, prior, hoard, output, builder):
    folder=Path(output)/row['sha256']
    final=prior.get('output_sha256') is not None
    result={'input_sha256':row['sha256'],'final_bin_compared':final,'stages':[]}
    try:
        if final:
            original=(folder/'original.bin').read_bytes();modified=(folder/'modified.bin').read_bytes()
            assert corpus.sha(original)==prior['canonical_sha256']
            assert corpus.sha(modified)==prior['output_sha256']
            doc=json.loads((folder/'modify.json').read_text());contracts=doc['execution_contracts']
            base=contracts['base'];roles=contracts['native_media_roles'];engine=doc['engine']
        else:
            assert prior['status']=='production-refusal','native-only allowed only after explicit production refusal'
            assert row['sha256'].startswith(REFUSAL_PREFIXES),'unexpected production refusal'
            source=Path(hoard)/row['path'];assert corpus.sha(source.read_bytes())==row['sha256']
            isolated=folder/'native-only';isolated.mkdir(parents=True,exist_ok=True)
            built=corpus.command([builder,source,isolated,'--native-only'])
            assert built['status']=='native-contracts-only' and built['input_sha256']==row['sha256']
            original=(isolated/'original.bin').read_bytes();modified=None
            assert corpus.sha(original)==built['canonical_sha256']
            roles=json.loads((isolated/'native.json').read_text())
            # Native roles never access freeMKV flags. Provide a declared mapped
            # observation address solely to satisfy the generic CPU runner ABI.
            base={'flags':0x0202ff00};engine=row['identified_family']
            result['native_only_build']=built
            result['native_contracts_sha256']=corpus.sha((isolated/'native.json').read_bytes())
        result['canonical_sha256']=corpus.sha(original)
        trace=folder/'native-traces.jsonl.gz'
        with gzip.open(trace,'wt') as sink:
            stages.TRACE_SINK=sink
            for role in ROLES:
                try:stage=native.compare(role,original,modified,engine,base,roles)
                except Exception as error:stage={'stage':'native:'+role,'status':'failed','cases':0,'error':str(error)}
                result['stages'].append(stage)
        stages.TRACE_SINK=None
        result['trace_file']=str(trace);result['trace_sha256']=corpus.sha(trace.read_bytes())
        result['status']='failed' if any(s['status']!='passed' for s in result['stages']) else 'bounded-native-pass'
    except Exception as error:
        stages.TRACE_SINK=None;result.update(status='failed',error=str(error))
    return result


def settings_dispatch_proof(folder,doc,trace_hash,complementary):
    indices={'speed':1,'region':2,'unrestricted':3,'hrl':5,'encryption':6}
    path=folder/'cpu-traces.jsonl.gz'
    if not path.exists():return {'qualified':False,'reason':'no actual CPU traces'}
    assert corpus.sha(path.read_bytes())==trace_hash,'CPU trace drift before settings-dispatch qualification'
    seen=set()
    with gzip.open(path,'rt') as stream:
        for line in stream:
            item=json.loads(line)
            if item.get('stage')!='vendor-handler':break
            key=item.get('input')
            if item.get('status')=='passed' and isinstance(key,list) and key[0]=='safe-prefix':
                seen.add(tuple(key[1:]))
    advertised=doc['execution_contracts']['advertised_boot_choices']
    required={(3,index,255) for feature,index in indices.items() if feature in advertised}
    required.update((2,indices[feature],choice[2]) for feature,choices in advertised.items()
                    for choice in choices if feature in indices)
    missing=sorted(required-seen)
    return {'qualified':not missing and bool(complementary),'missing_cases':missing,
            'required_GET_SET_prefix_cases':sorted(required),'cpu_trace_sha256':trace_hash,
            'complementary_handler_Rust_KAT_evidence':complementary,
            'limits':'Actual advertised GET/SET dispatch, bounds and first writer call are CPU-tested. Later handler services are complementary Rust/template-review evidence, not claimed per-firmware CPU execution.'}


def capability_matrix(row, result):
    folder=Path(result['_folder']);doc=None
    if result.get('output_sha256'):
        doc=json.loads((folder/'modify.json').read_text())
    stages_by_name={s['stage']:s for s in result.get('stages',[])}
    capabilities={}
    facts=(doc or {}).get('execution_contracts',{}).get('facts',{})
    for feature,settings in (doc or {}).get('boot_settings',{}).items():
        names={n for n,key in FEATURE_FACTS.get(feature,{}).items() if facts.get(key)}
        if feature in MINIMUM_FEATURE_ROLE:names.add(MINIMUM_FEATURE_ROLE[feature])
        names.update(('boot','vendor-handler'))
        selected=[stages_by_name[n] for n in sorted(names) if n in stages_by_name]
        missing=sorted(names-set(stages_by_name))
        supported=settings.get('supported') is True
        if not supported:status='not-advertised'
        elif feature not in FEATURE_FACTS or missing:status='unqualified-missing-stage'
        elif any(s['status']=='failed' for s in selected):status='failed'
        elif any(s['status']!='passed' or not s.get('cases') for s in selected):status='unqualified'
        elif any(s.get('coverage_gaps') for s in selected):status='bounded-pass-with-gaps'
        else:status='bounded-pass'
        capabilities[feature]={'supported':supported,'advertised_choices':settings.get('choices',[]),
            'status':status,'required_stages':sorted(names),'missing_stages':missing,'stages':[{'stage':s['stage'],'status':s['status'],'cases':s.get('cases',0),
                'coverage_gaps':s.get('coverage_gaps',[])} for s in selected]}
    return {'input_sha256':row['sha256'],'path':row['path'],'acceptance_group':row['acceptance_group'],
            'provenance_kind':row['provenance_kind'],'production_status':result['status'],
            'final_bin_available':bool(result.get('output_sha256')),
            'canonical_sha256':result.get('canonical_sha256'),'output_sha256':result.get('output_sha256'),
            'api_cli_identical':result.get('cli_api_identical',False),
            'capabilities':capabilities,'installed_conversion':result.get('required_installed_conversion'),
            'installed_conversion_cpu_passed':result.get('installed_conversion_helper_contracts_passed',False),
            'ordinary_and_helper_stages':[{'stage':s['stage'],'status':s['status'],'cases':s.get('cases',0),
                 'coverage_gaps':s.get('coverage_gaps',[]),'error':s.get('error'),
                 'failures':s.get('failures',[])[:2]} for s in result.get('stages',[])],
            'native_role_execution':result.get('native_role_execution'),
            'coverage_gap_review':review_gaps(result),
            'advertised_settings_dispatch':result.get('advertised_settings_dispatch')}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('inventory','hoard','builder','fw','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--dependency-commit',required=True)
    p.add_argument('--workers',type=int,default=4)
    p.add_argument('--build',action='store_true')
    p.add_argument('--handler-rust-test-log',type=Path,help='Parent-reviewed final-source Rust handler/KAT test log; hashed as complementary evidence')
    args=p.parse_args();repo=Path(__file__).resolve().parents[2]
    inventory=json.loads(args.inventory.read_text());rows=inventory['images']
    assert len(rows)==126 and len({r['sha256'] for r in rows})==126,'expected exact unique126 OEM-only scope'
    assert Counter(r['acceptance_group'] for r in rows)==Counter(EXPECTED_GROUPS),'scope group membership differs'
    assert all(r['catalogue_patched'] is False for r in rows),'modified input in OEM-only scope'
    expected_refusals={r['sha256'] for r in rows if r['sha256'].startswith(REFUSAL_PREFIXES)}
    assert len(expected_refusals)==3,'expected explicit three raw-readback producer refusals'
    args.output.mkdir(parents=True,exist_ok=True)
    assert not (args.output/'receipt.json').exists(),'fresh output required; never overwrite a frozen run'
    argv=[sys.executable,str(Path(__file__).with_name('corpus.py')),
          '--inventory',str(args.inventory.resolve()),'--hoard',str(args.hoard.resolve()),
          '--builder',str(args.builder.resolve()),'--fw',str(args.fw.resolve()),
          '--output',str(args.output.resolve()),'--workers',str(args.workers),
          '--dependency-commit',args.dependency_commit,'--require-installed-conversion']
    if args.build:argv.append('--build')
    completed=subprocess.run(argv,cwd=repo)
    receipt_path=args.output/'receipt.json'
    assert receipt_path.exists(),'corpus failed before writing frozen receipt'
    receipt=json.loads(receipt_path.read_text())
    corpus_receipt_hash=corpus.sha(receipt_path.read_bytes())
    complementary=None
    if args.handler_rust_test_log:
        log=args.handler_rust_test_log.read_bytes();text=log.decode(errors='replace')
        assert 'test result: ok.' in text and 'test result: FAILED' not in text,'complementary Rust test log lacks successful result'
        complementary={'path':str(args.handler_rust_test_log.resolve()),'sha256':corpus.sha(log),
                       'source_files_sha256':corpus.sha(json.dumps(receipt['source_files'],sort_keys=True).encode()),
                       'scope':'Parent-reviewed final-source Rust handler/template KAT evidence; complements CPU-tested advertised settings prefix, does not claim per-firmware service execution'}
    receipt['scope_driver']={'corpus_command':argv,'corpus_exit':completed.returncode,
                             'corpus_receipt_before_native_sha256':corpus_receipt_hash,
                             'started_native_unix':time.time()}
    assert receipt['source_files_unchanged'] and receipt['dependency_sources_unchanged'] and receipt['binaries_unchanged'],'corpus source freeze invalidated'
    by_sha={r['input_sha256']:r for r in receipt['images']}
    assert set(by_sha)=={r['sha256'] for r in rows},'corpus omitted scope membership'
    newer=[r for r in rows if r['acceptance_group']=='newer-native']
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        pending={pool.submit(native_row,r,by_sha[r['sha256']],str(args.hoard.resolve()),
                             str(args.output.resolve()),str(args.builder.resolve())):r for r in newer}
        for future in as_completed(pending):
            row=pending[future]
            try:result=future.result()
            except Exception as error:result={'status':'failed','error':str(error),'stages':[]}
            by_sha[row['sha256']]['native_role_execution']=result
            print('native',row['sha256'][:12],result['status'],flush=True)
    dep=corpus.dependency_package(repo);dep_root=Path(dep['manifest_path']).parent
    frozen=receipt['source_files']==corpus.source_files(repo) and receipt['dependency_source_files']==corpus.dependency_files(dep_root)
    frozen=frozen and receipt['builder_sha256']==corpus.sha(args.builder.read_bytes()) and receipt['cli_sha256']==corpus.sha(args.fw.read_bytes())
    receipt['scope_driver']['all_sources_and_binaries_unchanged_after_native']=frozen
    receipt['scope_driver']['finished_unix']=time.time()
    receipt['native_stage_totals']=dict(Counter(s['status'] for r in receipt['images']
                                      for s in r.get('native_role_execution',{}).get('stages',[])))
    receipt['native_cpu_cases']=sum(s.get('cases',0) for r in receipt['images']
                                  for s in r.get('native_role_execution',{}).get('stages',[]))
    actual_refusals={r['input_sha256'] for r in receipt['images'] if r['status']=='production-refusal'}
    produced=[r for r in receipt['images'] if r.get('output_sha256')]
    reasons=[]
    if completed.returncode:reasons.append('corpus command failed')
    if not frozen:reasons.append('source/dependency/binary freeze invalidated')
    if actual_refusals!=expected_refusals:reasons.append('producer refusals differ from three explicit raw readbacks')
    if len(produced)!=123:reasons.append('expected123 actual authored outputs')
    if any(not r.get('cli_api_identical') for r in produced):reasons.append('actual API/CLI comparison missing')
    if any(r['status'] not in ('bounded-pass','partial','production-refusal') for r in receipt['images']):reasons.append('production or ordinary/helper row failed or unqualified')
    if any(s.get('status')!='passed' or s.get('cases',0)<=0 for r in produced for s in r.get('stages',[])):
        reasons.append('installed ordinary/helper stage failed, unqualified or unexecuted')
    conversion_rows=[by_sha[r['sha256']] for r in rows if r['acceptance_group'].endswith('conversion-required')]
    if len(conversion_rows)!=41 or not all(r.get('installed_conversion_helper_contracts_passed') is True and r.get('required_installed_conversion',{}).get('status')=='installed-structural-only' for r in conversion_rows):
        reasons.append('41 actual installed conversion groups lack structural/functional passing evidence')
    if any(r.get('native_role_execution',{}).get('status')!='bounded-native-pass' for r in receipt['images'] if r['input_sha256'] in {x['sha256'] for x in newer}):reasons.append('newer native-role execution failed or missing')
    matrix=[]
    for row in rows:
        result=by_sha[row['sha256']]
        if result.get('output_sha256'):
            folder=args.output/row['sha256'];doc=json.loads((folder/'modify.json').read_text())
            result['advertised_settings_dispatch']=settings_dispatch_proof(folder,doc,result['trace_sha256'],complementary)
        result['_folder']=str(args.output/row['sha256'])
        matrix.append(capability_matrix(row,result));del result['_folder']
    if any(set(m['capabilities'])!=set(FEATURE_FACTS) or not all(c['supported'] for c in m['capabilities'].values()) for m in matrix if m['final_bin_available']):reasons.append('authorable output does not advertise exactly five supported features')
    if any(c['status'].startswith('unqualified') or c['status']=='failed' for m in matrix for c in m['capabilities'].values()):reasons.append('advertised capability missing or failed execution contract')
    if any(m['coverage_gap_review']['unreviewed_software_gaps'] for m in matrix):reasons.append('unreviewed software coverage gaps remain')
    final={'schema':'mediatek-oem126-capability-matrix-v1','software_contract_acceptance_passed':not reasons,
           'acceptance_failures':reasons,'counts':EXPECTED_GROUPS,'authorable_final_bins':len(produced),
           'explicit_production_refusals':sorted(actual_refusals),'native_cpu_cases':receipt['native_cpu_cases'],
           'source_freeze_valid':frozen,'physical_reading_qualified':False,
           'scope':'Actual API/CLI outputs, installed helpers and bounded advertised/native software contracts; OEM-only native checks on explicit refusals never count as authored final BINs.',
           'images':matrix}
    receipt['scope_software_contract_acceptance_passed']=not reasons
    receipt_path.write_text(json.dumps(receipt,indent=2)+'\n')
    final['receipt_sha256']=corpus.sha(receipt_path.read_bytes())
    (args.output/'capability-matrix.json').write_text(json.dumps(final,indent=2)+'\n')
    print(json.dumps({k:v for k,v in final.items() if k!='images'},indent=2))
    return 0 if not reasons else 1


if __name__=='__main__':sys.exit(main())
