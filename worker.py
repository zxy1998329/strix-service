import fcntl
import json
import os
import signal
import subprocess
import tempfile
import time
from pathlib import Path

import docker
import runtime_config

from service import DATA, database, job_dir, latest_run, read_json, update_job, validate_target

STOP = False


def stop_worker(*_):
    global STOP
    STOP = True


def cleanup_sandboxes(root):
    """Only remove containers whose exact run IDs belong to this job."""
    run_ids = []
    for path in (root / 'strix_runs').glob('*/run.json'):
        value = read_json(path, {}).get('run_id')
        if value and isinstance(value, str):
            run_ids.append(value)
    if not run_ids:
        return
    client = docker.from_env()
    try:
        for run_id in run_ids:
            for container in client.containers.list(all=True, filters={'label': f'strix-run-id={run_id}'}):
                container.remove(force=True)
    finally:
        client.close()


def safe_text(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 5 * 1024 * 1024:
        return ''
    return path.read_text(encoding='utf-8', errors='replace')


def make_report(job, terminal, exit_code=None, reason=None):
    root = job_dir(job['id'])
    run = latest_run(root)
    raw = read_json(run / 'run.json', {}) if run else {}
    coverage = read_json(run / 'coverage.json', {}) if run else {}
    findings = read_json(run / 'vulnerabilities.json', []) if run else []
    raw_report = safe_text(run / 'penetration_test_report.md') if run else ''
    if isinstance(findings, dict):
        findings = findings.get('vulnerabilities', [])
    if not isinstance(findings, list):
        findings = []
    warnings = ['本报告需要人工复核；没有发现漏洞不等于系统安全。',
                '模型费用可能无法准确计量，软件预算不是账户硬限额。']
    if terminal != 'completed' or raw.get('status') != 'completed':
        warnings.append('扫描未正常完成，仅包含终止前已取得的结果。')
    if not findings:
        warnings.append('未生成结构化漏洞条目；不能依据数量 0 给出安全通过结论。')
    gaps = coverage.get('gaps', [])
    if gaps:
        warnings.append('覆盖记录存在缺口，需检查原始运行数据。')
    if not raw_report:
        warnings.append('Strix 未生成原始文字报告。')
    result = {'id': job['id'], 'kind': job['kind'], 'name': job['name'], 'target': job['target'],
              'status': terminal, 'review_required': True, 'exit_code': exit_code, 'reason': reason,
              'strix_status': raw.get('status'), 'structured_findings_count': len(findings),
              'findings': findings, 'coverage_gaps': gaps, 'warnings': warnings,
              'llm_usage': raw.get('llm_usage', {}), 'raw_report': raw_report}
    if job['kind'].startswith('greybox'):
        import greybox
        result = greybox.redact(result,greybox.load(root))
        raw_report = result['raw_report']
    (root / 'report.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    header = f"# 扫描结果（需人工复核）\n\n任务：{job['id']}\n\n类型：{job['kind']}\n\n状态：{terminal}\n\n"
    if reason:
        header += f'结束说明：{reason}\n\n'
    header += '\n'.join('- ' + text for text in warnings)
    header += '\n\n---\n\n## Strix 原始报告\n\n'
    (root / 'report.md').write_text(header + (raw_report or '本次未产生原始报告。'), encoding='utf-8')
    return {'review_required': True, 'structured_findings_count': len(findings), 'warnings': warnings,
            'reason': reason, 'exit_code': exit_code}


def claim_job():
    with database() as conn:
        conn.execute('BEGIN IMMEDIATE')
        row = conn.execute("SELECT * FROM jobs WHERE status='queued' ORDER BY created LIMIT 1").fetchone()
        if row:
            conn.execute("UPDATE jobs SET status='running',updated=? WHERE id=?", (time.time(), row['id']))
            return dict(row)


def child_environment(secret_dir, settings=None):
    # Deliberately do not forward API service tokens, arbitrary integration credentials or PATH overrides.
    env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': secret_dir, 'LANG': 'C.UTF-8',
           'PYTHONUNBUFFERED': '1', 'LLM_DISABLE_STREAMING': 'true',
           'LITELLM_LOCAL_MODEL_COST_MAP': 'True',
           'STRIX_SANDBOX_MEM_LIMIT': os.environ.get('SANDBOX_MEMORY', '4g'),
           'STRIX_SANDBOX_CPUS': os.environ.get('SANDBOX_CPUS', '2'), 'STRIX_SANDBOX_PIDS_LIMIT': '512'}
    for name in ('LLM_TIMEOUT', 'STRIX_IMAGE',
                 'SSL_CERT_FILE', 'REQUESTS_CA_BUNDLE', 'STRIX_DOCKER_SANDBOX_NETWORK'):
        if os.environ.get(name):
            env[name] = os.environ[name]
    if settings is not None:
        env.update(runtime_config.model_environment(settings))
        return env
    for name in ('STRIX_LLM', 'STRIX_API_TYPE', 'LLM_API_BASE', 'LLM_EXTRA_BODY'):
        if os.environ.get(name):
            env[name] = os.environ[name]
    key_file = os.environ.get('LLM_API_KEY_FILE')
    if not key_file:
        raise RuntimeError('LLM_API_KEY_FILE is required')
    key = Path(key_file).read_text().strip()
    if not key:
        raise RuntimeError('Model API key is empty')
    env['LLM_API_KEY'] = key
    if not env.get('STRIX_LLM'):
        raise RuntimeError('STRIX_LLM is required')
    return env


def run_job(job):
    root = job_dir(job['id'])
    process = None
    terminal, reason, exit_code = 'failed', None, None
    try:
        settings = runtime_config.for_job(root)
        current = runtime_config.get_settings()
        if not (current['enabled'] if current else os.environ.get('WEB_CONFIG_REQUIRED', 'false') != 'true' and os.environ.get('ENABLE_SCANS', '').lower() == 'true'):
            raise RuntimeError('Scanning disabled')
        if os.environ.get('EGRESS_POLICY_ACK', '').lower() != 'true':
            raise RuntimeError('Administrator must enforce sandbox network ACLs and acknowledge EGRESS_POLICY_ACK')
        if job['kind'] in ('blackbox','greybox'):
            validate_target(job['target'], settings)  # Re-check DNS and submission-time policy.
            if current:
                validate_target(job['target'], current)  # A subsequently revoked target stays revoked.
            scope = f"Only test the explicitly authorized origin {job['target']}. Do not follow redirects, links or callbacks to any other origin. Do not scan the host, cloud metadata, management networks or unrelated systems."
        else:
            scope = 'Only audit the supplied project at /workspace/source. Run any supplied application only inside this sandbox. Do not scan external domains, the host, LAN or other containers. Do not fix source files. This is an isolated disposable project copy.'
        scope += '\nUse non-destructive checks; no brute force, denial of service, persistence, deletion or external callbacks. Do not create subagents. Limit tests to the authorized scope. Write the final report in Chinese. Record every validated finding with create_vulnerability_report before finish_scan. Record coverage and gaps honestly. Distinguish code-only risks from dynamically validated findings. Never call an incomplete scan clean.'
        instruction = root / 'scope.txt'
        requirements = read_json(root / 'requirements.json', {}).get('instructions','')
        if requirements:
            scope += '\nUser test requirements (must remain within the authorized target and above restrictions):\n' + requirements
        if job['kind'] == 'greybox':
            scope += '\nAuthenticated grey-box assessment. Read /workspace/auth.json for task-scoped test accounts and instructions. For method=headers accounts, apply every auth entry to each request to the authorized origin: type=header uses the exact name and value (do not add Bearer automatically); type=cookie combines name=value pairs into the Cookie header. Isolate each account session. Empty auth means anonymous and must not be presented as authenticated. For legacy password accounts, follow the login path and steps using browser/HTTP tools. For Cookie/Bearer accounts explicitly inject Cookie/Authorization into requests to the authorized origin ONLY; use isolated sessions per account. Never send credentials to another origin, query string, third-party site, report or evidence. Confirm authentication before claiming authenticated coverage: HTTP 200 alone is only connectivity. Record authentication failures, expiry and role switching using coverage entries. Compare supplied accounts according to roles. If unable to establish a session report the gap rather than presenting anonymous tests as authenticated. Never print credentials.'
        instruction.write_text(scope, encoding='utf-8')
        timeout = int(settings['timeout'] if settings else os.environ.get('SCAN_TIMEOUT_SECONDS', '0'))
        max_turns = int(settings['max_turns'] if settings else os.environ.get('SCAN_MAX_TURNS', '0'))
        budget = float(settings['budget'] if settings else os.environ.get('SCAN_MAX_BUDGET_USD', '0'))
        if not ((timeout == 0 or 30 <= timeout <= 14400) and 0 <= max_turns <= 2147483647 and 0 <= budget <= 100):
            raise RuntimeError('Invalid administrator scan limits')
        with tempfile.TemporaryDirectory(prefix='strix-job-', dir='/dev/shm') as secrets:
            env = child_environment(secrets, settings)
            env['LLM_DISABLE_STREAMING'] = 'true'
            env['TIKTOKEN_CACHE_DIR'] = '/opt/tokenizer-cache'
            env['STRIX_RUN_RECORD_TIMINGS'] = 'true'
            env['STRIX_TELEMETRY'] = 'false'
            env['STRIX_MODEL_RATE_RETRY'] = 'true'
            redactions = [env.get('LLM_API_KEY', '')]
            if settings:
                redactions += list(settings.get('extra_headers', {}).values())
                redactions += list(settings.get('provider_env', {}).values())
            if job['kind'] == 'greybox':
                import greybox
                for account in greybox.load(root).get('accounts', []):
                    redactions += [account.get(key, '') for key in ('password','cookie','token')]
                    redactions += [entry.get('value', '') for entry in account.get('auth', [])]
            redaction_file = Path(secrets) / 'model-redactions.json'
            redaction_file.write_text(json.dumps([value for value in redactions if isinstance(value,str) and value]))
            redaction_file.chmod(0o600)
            env['STRIX_MODEL_REDACTION_FILE'] = str(redaction_file)
            config = Path(secrets) / 'config.json'
            config.write_text('{"env":{}}')
            config.chmod(0o600)
            command = ['/usr/local/bin/strix', '-n', '--config', str(config), '--target', job['target'],
                       '--scan-mode', 'quick', '--scope-mode', 'full', '--max-turns', str(max_turns or 2147483647),
                       '--instruction-file', str(instruction)]
            if job['kind'] == 'greybox':
                import greybox
                auth_file = Path(secrets) / 'auth.json'
                auth_file.write_text(json.dumps(greybox.load(root),ensure_ascii=False))
                auth_file.chmod(0o600)
                command += ['--workspace-file',str(auth_file)+':auth.json']
            if budget:
                command += ['--max-budget', str(budget)]
            with (root / 'worker.log').open('wb') as log:
                process = subprocess.Popen(command, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT,
                                           start_new_session=True)
                started = time.monotonic()
                while process.poll() is None:
                    with database() as conn:
                        state = conn.execute('SELECT status FROM jobs WHERE id=?', (job['id'],)).fetchone()[0]
                    if STOP or state == 'cancel_requested' or (timeout and time.monotonic() - started > timeout):
                        terminal = 'cancelled' if STOP or state == 'cancel_requested' else 'timed_out'
                        reason = 'Worker stopped or user cancelled' if terminal == 'cancelled' else 'Wall-clock time limit reached'
                        os.killpg(process.pid, signal.SIGTERM)
                        try:
                            process.wait(timeout=15)
                        except subprocess.TimeoutExpired:
                            os.killpg(process.pid, signal.SIGKILL)
                            process.wait()
                        break
                    time.sleep(1)
                exit_code = process.returncode
                if reason is None:
                    run = latest_run(root)
                    state = read_json(run / 'run.json', {}).get('status') if run else None
                    terminal = 'completed' if exit_code in (0, 2) and state == 'completed' else 'failed'
                    reason = None if terminal == 'completed' else 'Strix failed or did not complete; administrator can inspect worker.log'
    except Exception as error:
        # Do not return vendor errors or raw stderr: they can contain credentials or application data.
        reason = f'Worker error ({type(error).__name__}); check server configuration and restricted logs'
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        try:
            cleanup_sandboxes(root)
        except Exception:
            terminal = 'failed'
            reason = 'Sandbox cleanup failed; administrator intervention required'
            stop_worker()
        detail = make_report(job, terminal, exit_code, reason)
        update_job(job['id'], terminal, detail)


def main():
    os.umask(0o077)
    DATA.mkdir(parents=True, exist_ok=True)
    lock = (DATA / 'worker.lock').open('w')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit('Only one worker is supported for this local database')
    signal.signal(signal.SIGTERM, stop_worker)
    signal.signal(signal.SIGINT, stop_worker)
    # Recover interrupted jobs after a worker/container restart, never run them silently again.
    with database() as conn:
        interrupted = [dict(row) for row in conn.execute("SELECT * FROM jobs WHERE status IN ('running','cancel_requested')")]
    for job in interrupted:
        try:
            cleanup_sandboxes(job_dir(job['id']))
        except Exception:
            raise SystemExit('Cannot clean interrupted sandbox; refusing to start new jobs')
        detail = make_report(job, 'failed', reason='Worker restarted; prior job interrupted')
        update_job(job['id'], 'failed', detail)
    while not STOP:
        job = claim_job()
        if job:
            if job['kind'] == 'greybox_verify':
                try:
                    import greybox
                    current = runtime_config.get_settings()
                    if not current or not current['enabled']:
                        raise RuntimeError('Scanning disabled')
                    validate_target(job['target'],current)
                    results = greybox.verify(job,job_dir(job['id']),runtime_config.for_job(job_dir(job['id'])))
                    update_job(job['id'],'completed',{'verification':results,'reason':'接口验证完成，不代表已完成漏洞扫描'})
                except Exception as error:
                    update_job(job['id'],'failed',{'reason':'接口验证失败：'+type(error).__name__})
            else:
                run_job(job)
        else:
            time.sleep(1)


if __name__ == '__main__':
    main()

