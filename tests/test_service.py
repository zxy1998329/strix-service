import io
import json
import os
import sqlite3
import socket
import stat
import subprocess
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
import service
import worker
import model_guard


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.original_data = service.DATA
        self.original_worker_data = worker.DATA
        service.DATA = self.root / 'data'
        worker.DATA = service.DATA
        tokens = self.root / 'tokens.json'
        tokens.write_text(json.dumps({'alice': 'a' * 40, 'bob': 'b' * 40}))
        self.env = patch.dict(os.environ, {'SERVICE_TOKENS_FILE': str(tokens), 'ENABLE_SCANS': 'true',
            'ALLOWED_TARGET_HOSTS': 'test.company', 'ALLOWED_TARGET_CIDRS': '10.20.30.40/32',
            'ALLOWED_TARGET_PORTS': '80,443', 'SCAN_SCOPE_RESTRICTIONS_ENABLED': 'true'})
        self.env.start()
        self.client = TestClient(service.app)
        self.auth = {'Authorization': 'Bearer ' + 'a' * 40}

    def tearDown(self):
        self.client.close()
        self.env.stop()
        service.DATA = self.original_data
        worker.DATA = self.original_worker_data
        self.temp.cleanup()

    def zip_bytes(self, name='src/app.py', content='print(1)'):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            archive.writestr(name, content)
        return stream.getvalue()

    def submit(self, blob=None):
        return self.client.post('/v1/scans/whitebox', headers=self.auth,
            data={'authorized': 'true', 'name': 'demo'},
            files={'project': ('project.zip', blob or self.zip_bytes(), 'application/zip')})

    def test_auth_and_owner_isolation(self):
        self.assertEqual(self.client.post('/v1/scans/blackbox', json={}).status_code, 401)
        response = self.submit()
        self.assertEqual(response.status_code, 202, response.text)
        job_id = response.json()['id']
        self.assertTrue((service.job_dir(job_id) / 'source/src/app.py').is_file())
        self.assertEqual(self.client.get(f'/v1/scans/{job_id}', headers=self.auth).status_code, 200)
        self.assertEqual(self.client.get(f'/v1/scans/{job_id}', headers={'Authorization': 'Bearer ' + 'b' * 40}).status_code, 404)
        self.assertEqual(self.client.get(f'/v1/scans/{job_id}/report', headers=self.auth).status_code, 409)

    def test_custom_requirements_whitebox_and_blackbox(self):
        result=self.client.post('/v1/scans/whitebox',headers=self.auth,data={'authorized':'true','instructions':'重点检测 SQL 注入'},files={'project':('app.zip',self.zip_bytes())})
        self.assertEqual(result.status_code,202,result.text)
        self.assertEqual(self.client.get('/v1/scans/'+result.json()['id'],headers=self.auth).json()['instructions'],'重点检测 SQL 注入')
        with patch('socket.getaddrinfo',return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('10.20.30.40',443))]):
            result=self.client.post('/v1/scans/blackbox',headers=self.auth,json={'target':'https://test.company/','authorized':True,'instructions':'排除退出接口'})
            self.assertEqual(result.status_code,202,result.text)
            self.assertEqual(self.client.get('/v1/scans/'+result.json()['id'],headers=self.auth).json()['instructions'],'排除退出接口')
        self.assertEqual(self.client.post('/v1/scans/blackbox',headers=self.auth,json={'target':'https://test.company/','authorized':True,'instructions':'a'*4001}).status_code,422)

    def test_live_findings_before_report_and_owner_isolation(self):
        job_id = self.submit().json()['id']
        run = service.job_dir(job_id) / 'strix_runs' / 'demo'
        run.mkdir(parents=True)
        (run / 'run.json').write_text('{}')
        finding = {'id':'v1','title':'SQL injection','severity':'high','evidence':'test evidence','remediation_steps':'Use parameters'}
        (run / 'vulnerabilities.json').write_text(json.dumps([finding]))
        result = self.client.get(f'/v1/scans/{job_id}',headers=self.auth).json()
        self.assertFalse(result['report_ready'])
        self.assertEqual(result['findings'],[finding])
        self.assertEqual(result['findings_count'],1)
        self.assertEqual(self.client.get(f'/v1/scans/{job_id}',headers={'Authorization':'Bearer '+'b'*40}).status_code,404)
        (run / 'vulnerabilities.json').write_text('incomplete')
        self.assertEqual(self.client.get(f'/v1/scans/{job_id}',headers=self.auth).json()['findings'],[])

    def test_execution_progress_uses_real_tool_and_coverage_records(self):
        import time
        from datetime import datetime, timezone
        job_id = self.submit().json()['id']
        service.update_job(job_id, 'running', {})
        run = service.job_dir(job_id) / 'strix_runs' / 'demo'
        run.mkdir(parents=True)
        stamp = datetime.fromtimestamp(time.time()-180, timezone.utc).isoformat()
        (run/'run.json').write_text(json.dumps({'tool_calls':[{'tool':'terminal_execute','started_at':stamp,'duration_ms':1000}],
            'llm_requests':[{'started_at':stamp,'outcome':'error','status':429,'retry_attempt':1}]}))
        (run/'coverage.json').write_text(json.dumps({'entries':[{'surface':'/search','risk_area':'SQL injection','outcome':'reported','evidence':'parameter test'}],'gaps':['authentication not tested']}))
        result = self.client.get(f'/v1/scans/{job_id}',headers=self.auth).json()['execution']
        self.assertEqual(result['tool_calls_count'],1)
        self.assertEqual(result['coverage_count'],1)
        self.assertTrue(result['activity_warning'])
        self.assertEqual(len(result['events']),2)
        self.assertEqual(result['coverage'][0]['surface'],'/search')
        self.assertEqual(result['coverage_gaps'],['authentication not tested'])

    def test_authorization_and_disabled(self):
        self.assertEqual(self.client.post('/v1/scans/whitebox', headers=self.auth,
            files={'project': ('x.zip', self.zip_bytes())}).status_code, 400)
        with patch.dict(os.environ, {'ENABLE_SCANS': 'false'}):
            self.assertEqual(self.submit().status_code, 503)

    def test_malicious_zip_paths(self):
        for name in ['../escape.py', '/absolute', 'C:/x', 'a\\b', './x', 'a/../../b']:
            with self.subTest(name=name):
                self.assertEqual(self.submit(self.zip_bytes(name)).status_code, 400)
        self.assertFalse((service.DATA / 'escape.py').exists())

    def test_symlink_duplicate_and_zipbomb(self):
        for variant in ['symlink', 'duplicate', 'bomb']:
            data = io.BytesIO()
            with zipfile.ZipFile(data, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
                if variant == 'symlink':
                    info = zipfile.ZipInfo('link')
                    info.create_system = 3
                    info.external_attr = (stat.S_IFLNK | 0o777) << 16
                    archive.writestr(info, '/etc/passwd')
                elif variant == 'duplicate':
                    archive.writestr('App.py', 'x')
                    archive.writestr('app.py', 'y')
                else:
                    archive.writestr('huge', b'0' * (10 * 1024 * 1024))
            self.assertEqual(self.submit(data.getvalue()).status_code, 400, variant)

    def test_size_limit_and_queue_limit(self):
        with patch.object(service, 'UPLOAD_LIMIT', 10):
            self.assertEqual(self.submit().status_code, 413)
        for _ in range(3):
            self.assertEqual(self.submit().status_code, 202)
        self.assertEqual(self.submit().status_code, 429)

    def test_blackbox_allowlist_dns_and_queue_recheck(self):
        address = [(2, 1, 6, '', ('10.20.30.40', 443))]
        with patch('service.socket.getaddrinfo', return_value=address):
            response = self.client.post('/v1/scans/blackbox', headers=self.auth,
                json={'target': 'https://test.company', 'authorized': True})
            self.assertEqual(response.status_code, 202, response.text)
            for bad in ['file:///etc/passwd', 'https://evil.company', 'https://test.company:22',
                        'https://u:p@test.company', 'https://test.company/a', 'https://test.company/?x=1']:
                with self.assertRaises(ValueError):
                    service.validate_target(bad)
        for bad_address in ['127.0.0.1', '169.254.169.254', '10.20.30.41', '::ffff:127.0.0.1']:
            with patch('service.socket.getaddrinfo', return_value=[(2, 1, 6, '', (bad_address, 443))]):
                with self.assertRaises(ValueError):
                    service.validate_target('https://test.company')

    def test_cancel_and_atomic_claim(self):
        job_id = self.submit().json()['id']
        self.assertEqual(self.client.post(f'/v1/scans/{job_id}/cancel', headers=self.auth).json()['status'], 'cancelled')
        self.assertIsNone(worker.claim_job())
        job_id = self.submit().json()['id']
        self.assertEqual(worker.claim_job()['id'], job_id)
        self.assertIsNone(worker.claim_job())

    def test_normalized_report_never_calls_empty_findings_safe(self):
        job_id = self.submit().json()['id']
        job = service.owned_job(job_id, 'alice')
        run = service.job_dir(job_id) / 'strix_runs/demo'
        run.mkdir(parents=True)
        (run / 'run.json').write_text(json.dumps({'status': 'completed', 'run_id': 'demo', 'llm_usage': {}}))
        (run / 'penetration_test_report.md').write_text('# Found an issue', encoding='utf-8')
        (run / 'coverage.json').write_text(json.dumps({'gaps': [{'kind': 'missing'}]}))
        detail = worker.make_report(job, 'completed', 0)
        self.assertTrue(detail['review_required'])
        self.assertEqual(detail['structured_findings_count'], 0)
        self.assertGreaterEqual(len(detail['warnings']), 4)
        self.assertEqual(self.client.get(f'/v1/scans/{job_id}/report', headers=self.auth).status_code, 200)
        self.assertEqual(self.client.get(f'/v1/scans/{job_id}/report?format=json', headers=self.auth).json()['status'], 'completed')

    def test_worker_missing_key_still_generates_failure_report(self):
        job_id = self.submit().json()['id']
        job = worker.claim_job()
        with patch.dict(os.environ, {'EGRESS_POLICY_ACK': 'true', 'LLM_API_KEY_FILE': '/missing'}):
            worker.run_job(job)
        self.assertEqual(service.owned_job(job_id, 'alice')['status'], 'failed')
        self.assertTrue((service.job_dir(job_id) / 'report.md').is_file())

    def test_worker_process_report_and_cancel(self):
        # Exercise the real subprocess lifecycle with a fake scanner; no model calls.
        fake = self.root / 'fake_scanner.py'
        fake.write_text('''import pathlib,json,sys,time
if "--sleep" in sys.argv: time.sleep(30)
p=pathlib.Path('strix_runs/fake'); p.mkdir(parents=True)
(p/'run.json').write_text(json.dumps({'status':'completed','run_id':'fake','llm_usage':{'requests':1}}))
(p/'penetration_test_report.md').write_text('# Test report')
(p/'vulnerabilities.json').write_text(json.dumps([{'title':'Synthetic finding'}]))
sys.exit(2)
''')
        real_popen = subprocess.Popen
        for cancel in (False, True):
            job_id = self.submit().json()['id']
            job = worker.claim_job()
            (service.job_dir(job_id)/'requirements.json').write_text(json.dumps({'instructions':'Focus on SQL injection; exclude logout'}))
            def spawn(command, **kwargs):
                self.assertIn('Focus on SQL injection; exclude logout',Path(command[command.index('--instruction-file')+1]).read_text())
                self.assertNotIn('--max-budget', command)
                self.assertEqual(command[command.index('--max-turns')+1], '2147483647')
                return real_popen(['python', str(fake)] + (['--sleep'] if cancel else []), **kwargs)
            timer = None
            if cancel:
                timer = threading.Timer(.3, lambda: service.update_job(job_id, 'cancel_requested', {}))
                timer.start()
            with patch.dict(os.environ, {'EGRESS_POLICY_ACK': 'true'}), \
                    patch('worker.child_environment', return_value={'PATH': os.environ['PATH']}), \
                    patch('worker.cleanup_sandboxes'), patch('worker.subprocess.Popen', side_effect=spawn):
                worker.run_job(job)
            if timer:
                timer.join()
            state = service.owned_job(job_id, 'alice')
            self.assertEqual(state['status'], 'cancelled' if cancel else 'completed')
            self.assertTrue((service.job_dir(job_id) / 'report.json').is_file())
            if not cancel:
                self.assertEqual(json.loads(state['detail'])['structured_findings_count'], 1)


    def test_paused_job_is_visible_and_can_be_resumed(self):
        response = self.submit()
        self.assertEqual(response.status_code, 202, response.text)
        job_id = response.json()['id']
        root = service.job_dir(job_id)
        guard = model_guard.default_state(3)
        guard.update({'paused': True, 'paused_at': 100, 'count': 3,
                      'reason': '主备模型连续 3 次失败：HTTP 429',
                      'failures': [{'id': 'a' * 32, 'role': 'backup', 'model': 'backup-model',
                                    'status': 429, 'error': None, 'message': 'rate limited',
                                    'started': 90, 'finished': 91}]})
        model_guard.write(root, guard)
        service.update_job(job_id, 'paused', {})
        status = self.client.get(f'/v1/scans/{job_id}', headers=self.auth)
        self.assertEqual(status.status_code, 200, status.text)
        body = status.json()
        self.assertEqual(body['status'], 'paused')
        self.assertTrue(body['pause']['paused'])
        self.assertEqual(body['pause']['failures'][0]['status'], 429)
        self.assertEqual(self.client.get(f'/v1/scans/{job_id}', headers={'Authorization': 'Bearer ' + 'b' * 40}).status_code, 404)
        resume = self.client.post(f'/v1/scans/{job_id}/resume', headers=self.auth)
        self.assertEqual(resume.status_code, 202, resume.text)
        self.assertEqual(resume.json()['status'], 'running')
        self.assertFalse(model_guard.read(root)['paused'])
        self.assertEqual(self.client.post(f'/v1/scans/{job_id}/resume', headers=self.auth).status_code, 409)


if __name__ == '__main__':
    unittest.main()

