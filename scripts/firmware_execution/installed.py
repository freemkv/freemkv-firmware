"""Structural admission gate for actual final-BIN conversion execution tests."""
import hashlib
from stages import DECODER


def check_installed(original,modified,contracts,hook_reports):
    helpers=contracts.get('media_conversion_helpers',[])
    complete=[h for h in hook_reports if h.get('id')=='uhd-conversion' and (h.get('variant') or '').startswith('complete media group:')]
    failures=[]
    if not complete:failures.append('No registered complete conversion group in actual production output')
    if not helpers:failures.append('No actual installed conversion helpers; pending/refusal/source byte equality is not conversion execution')
    for h in helpers:
        site,target=h['site'],h['target'];raw=bytes(h['original_bytes'])
        if original[site:site+len(raw)]!=raw:failures.append(f'Unbound original helper span {site:#x}')
        ins=next(DECODER.disasm(modified[site:site+4],site,count=1),None)
        if ins is None or ins.mnemonic!='bl' or int(ins.op_str.lstrip('#'),0)!=target:
            failures.append(f'Actual final-BIN BL does not reach registered helper {site:#x}')
        data=modified[target:target+h['helper_len']]
        if hashlib.sha256(data).hexdigest()!=h['helper_sha256']:failures.append(f'Actual helper bytes differ {site:#x}')
    return {'status':'failed' if failures else 'installed-structural-only','helper_count':len(helpers),
            'failures':failures,'functional_execution_passed':False,
            'scope':'Only actual final-BIN installation; independent CPU/semantic/coverage tests are additionally required'}
