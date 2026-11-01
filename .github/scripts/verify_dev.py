"""Require successful dev CI with executed lint for the exact candidate tree."""
import json
import os
import subprocess


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def same_tree(base):
    return command('git', 'rev-parse', base + '^{tree}') == command('git', 'rev-parse', 'HEAD^{tree}')


def eligible(run, jobs):
    return (run.get('conclusion') == 'success'
            and run.get('event') == 'push'
            and run.get('head_branch') == 'dev'
            and any(job.get('name') == 'lint'
                    and job.get('conclusion') == 'success'
                    and any(step.get('name') == 'Lint Rust targets'
                            and step.get('conclusion') == 'success'
                            for step in job.get('steps', []))
                    for job in jobs))


def verify(repo):
    runs = json.loads(command('gh', 'api', f'repos/{repo}/actions/workflows/ci.yml/runs?branch=dev&event=push&status=success&per_page=30'))['workflow_runs']
    for run in runs:
        command('git', 'fetch', '--no-tags', 'origin', run['head_sha'])
        if not same_tree(run['head_sha']):
            continue
        # The complete job set matters: never rely on the first API page alone.
        pages = json.loads(command('gh', 'api', '--paginate', '--slurp', f'repos/{repo}/actions/runs/{run["id"]}/jobs?per_page=100'))
        jobs = [job for page in pages for job in page['jobs']]
        if eligible(run, jobs):
            print(f'Exact source tree has successful dev CI and lint: {run["id"]} ({run["head_sha"]})')
            return run['id']
    raise RuntimeError('No successful dev push with executed lint matches this exact tree; validate dev before QA')


if __name__ == '__main__':
    verify(os.environ['GITHUB_REPOSITORY'])
