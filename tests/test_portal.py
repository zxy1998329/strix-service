import json
import os
from unittest.mock import patch
from fastapi.testclient import TestClient
import unittest

import service
import portal
import runtime_config
import worker
import test_service as base_tests


class PortalTests(unittest.TestCase):
    setUp = base_tests.ServiceTests.setUp
    tearDown = base_tests.ServiceTests.tearDown
    zip_bytes = base_tests.ServiceTests.zip_bytes
    submit = base_tests.ServiceTests.submit

    def login(self, client=None, role='admin', employee='', password='296419'):
        client = client or self.client
        response = client.post('/web/login', json={'role': role, 'employee': employee, 'password': password})
        self.assertEqual(response.status_code, 200, response.text)
        return {'x-csrf-token': response.json()['csrf']}

    def test_admin_log_tail_redacts_and_rejects_employee(self):
        headers = self.login()
        response = self.client.post('/v1/scans/whitebox', headers=headers,
            data={'authorized': 'true'}, files={'project': ('demo.zip', self.zip_bytes())})
        self.assertEqual(response.status_code, 202, response.text)
        job_id = response.json()['id']
        runtime_config.save_settings({'api_key': 'synthetic-log-secret', 'enabled': False})
        path = service.job_dir(job_id) / 'worker.log'
        endpoint = '/v1/scans/' + job_id + '/logs'
        self.assertEqual(self.client.get(endpoint).status_code, 200)
        download = endpoint + '?download=true'
        self.assertEqual(self.client.get(download).status_code, 404)
        path.write_text('start synthetic-log-secret\n' + 'x' * 20000 + '\nAuthorization: Bearer synthetic-log-secret\nCookie: session=private\n\x1b[31mHTTP 429\x1b[0m', encoding='utf-8')
        response = self.client.get(endpoint)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()['truncated'])
        self.assertIn('HTTP 429', response.json()['text'])
        self.assertNotIn('synthetic-log-secret', response.text)
        self.assertNotIn('session=private', response.text)
        self.assertNotIn('\x1b', response.json()['text'])
        self.assertEqual(response.headers['cache-control'], 'no-store')
        self.assertNotIn('start', response.json()['text'])
        response = self.client.get(download)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['content-disposition'], f'attachment; filename="worker-{job_id}.log"')
        self.assertEqual(response.headers['cache-control'], 'no-store')
        self.assertTrue(response.text.startswith('start [已脱敏]'))
        self.assertIn('x' * 20000, response.text)
        self.assertTrue(response.text.endswith('HTTP 429'))
        self.assertNotIn('synthetic-log-secret', response.text)
        self.assertNotIn('session=private', response.text)
        self.assertNotIn('\x1b', response.text)
        path.unlink()
        path.symlink_to(service.job_dir(job_id) / 'requirements.json')
        self.assertEqual(self.client.get(endpoint).status_code, 400)
        self.assertEqual(self.client.get(download).status_code, 400)
        path.unlink()
        with service.database() as conn:
            conn.execute('DELETE FROM portal_settings')
        self.login(role='user', employee='001234')
        employee_job = self.client.post('/v1/scans/whitebox', headers={'Authorization': 'Bearer ' + 'a' * 40},
            data={'authorized': 'true'}, files={'project': ('demo.zip', self.zip_bytes())})
        employee_endpoint = '/v1/scans/' + employee_job.json()['id'] + '/logs'
        employee_headers = {'Authorization': 'Bearer ' + 'a' * 40}
        self.assertEqual(self.client.get(employee_endpoint, headers=employee_headers).status_code, 403)
        self.assertEqual(self.client.get(employee_endpoint + '?download=true', headers=employee_headers).status_code, 403)

    def test_scope_form_updates_allowlist_without_changing_model_or_secrets(self):
        import socket
        headers=self.login()
        runtime_config.save_settings({'api_key':'scope-test-secret','model':'openai/test-model','extra_body':{'temperature':0.3}})
        before=runtime_config.get_settings()
        payload={'scope_restrictions_enabled':True,'allowed_hosts':'new.company','allowed_cidrs':'10.20.30.55/32','allowed_ports':'8443'}
        response=self.client.put('/web/admin/config',headers=headers,json=payload)
        self.assertEqual(response.status_code,200,response.text)
        self.assertNotIn('scope-test-secret',response.text)
        after=runtime_config.get_settings()
        for key in ('api_key','model','api_base','extra_body','enabled','timeout','budget','max_turns'):
            self.assertEqual(after[key],before[key])
        with patch('socket.getaddrinfo',return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('10.20.30.55',8443))]):
            self.assertEqual(service.validate_target('https://new.company:8443/'),'https://new.company:8443/')
            with self.assertRaises(ValueError):service.validate_target('https://test.company/')
        invalid=self.client.put('/web/admin/config',headers=headers,json={'allowed_cidrs':'not-a-network'})
        self.assertEqual(invalid.status_code,400)
        self.assertEqual(runtime_config.get_settings()['allowed_cidrs'],'10.20.30.55/32')
        user_headers=self.login(role='user',employee='001234')
        self.assertEqual(self.client.get('/web/admin/config').status_code,403)
        self.assertEqual(self.client.put('/web/admin/config',headers=user_headers,json=payload).status_code,403)

    def test_scope_switch_defaults_off_and_preserves_rules(self):
        import socket
        headers=self.login()
        self.assertFalse(runtime_config.public_settings()['scope_restrictions_enabled'])
        runtime_config.save_settings({'allowed_hosts':'registered.company','allowed_cidrs':'10.20.30.40/32','allowed_ports':'443'})
        dns=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('10.40.50.60',8443))]
        with patch('socket.getaddrinfo',return_value=dns):
            self.assertEqual(service.validate_target('https://other.company:8443/'),'https://other.company:8443/')
            self.assertEqual(self.client.put('/web/admin/config',headers=headers,json={'scope_restrictions_enabled':True}).status_code,200)
            with self.assertRaises(ValueError):service.validate_target('https://other.company:8443/')
            self.assertEqual(self.client.put('/web/admin/config',headers=headers,json={'scope_restrictions_enabled':False}).status_code,200)
            self.assertEqual(service.validate_target('https://other.company:8443/'),'https://other.company:8443/')
        self.assertEqual(runtime_config.get_settings()['allowed_hosts'],'registered.company')
        self.assertEqual(self.client.put('/web/admin/config',headers=headers,json={'scope_restrictions_enabled':'false'}).status_code,400)
        for ip in ('127.0.0.1','169.254.169.254','0.0.0.0'):
            with patch('socket.getaddrinfo',return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',(ip,443))]):
                with self.assertRaises(ValueError):service.validate_target('https://other.company/')

    def test_employee_registration_admin_visibility_and_isolation(self):
        headers = self.login(role='user', employee='001234')
        job = self.client.post('/v1/scans/whitebox', headers=headers,
            data={'authorized': 'true', 'name': 'Employee project'},
            files={'project': ('code.zip', self.zip_bytes())}).json()
        self.assertEqual(self.client.get('/web/tasks').json()['total'], 1)
        with TestClient(service.app) as other:
            self.login(other, role='user', employee='006789')
            self.assertEqual(other.get('/web/tasks').json()['total'], 0)
            self.assertEqual(other.get('/v1/scans/' + job['id']).status_code, 404)
            self.assertEqual(other.get('/web/report/' + job['id']).status_code, 404)
            self.assertEqual(other.get('/web/admin/config').status_code, 403)
        with TestClient(service.app) as admin:
            self.login(admin)
            self.assertEqual(admin.get('/web/tasks').json()['total'], 1)
            self.assertEqual(admin.get('/v1/scans/' + job['id']).status_code, 200)
            users = admin.get('/web/admin/users').json()['items']
            self.assertEqual({row['employee'] for row in users}, {'001234', '006789'})

    def test_csrf_login_validation_and_disabled_account(self):
        for employee in ['123', 'abcdef', '１２３４５６']:
            self.assertEqual(self.client.post('/web/login', json={'role': 'user', 'employee': employee}).status_code, 401)
        headers = self.login(role='user', employee='001234')
        self.assertEqual(self.client.post('/web/logout').status_code, 403)
        self.assertEqual(self.client.post('/web/logout', headers={**headers, 'Origin': 'http://evil.test'}).status_code, 403)
        with TestClient(service.app) as admin:
            admin_headers = self.login(admin)
            self.assertEqual(admin.post('/web/admin/users/001234/toggle', headers=admin_headers).status_code, 200)
        self.assertEqual(self.client.get('/web/me').status_code, 401)
        self.assertEqual(self.client.post('/web/login', json={'role': 'user', 'employee': '001234'}).status_code, 401)

    def test_encrypted_config_secret_retention_and_snapshot(self):
        headers = self.login()
        config = runtime_config.defaults()
        config.update(api_key='TEST-SECRET-NEVER-RETURN', extra_headers={'X-Secret': 'header-secret'},
                      provider_env={'AWS_SECRET_ACCESS_KEY': 'cloud-secret'}, model='openai/first-model',
                      api_type='responses', enabled=True)
        with patch.dict(os.environ, {'EGRESS_POLICY_ACK': 'true'}):
            response = self.client.put('/web/admin/config', json=config, headers=headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertNotIn('TEST-SECRET', response.text)
        self.assertNotIn('header-secret', response.text)
        self.assertTrue(response.json()['api_key_present'])
        with service.database() as conn:
            encrypted = conn.execute('SELECT encrypted FROM portal_settings').fetchone()[0]
        self.assertNotIn('TEST-SECRET', encrypted)
        submitted = self.client.post('/v1/scans/whitebox', headers=headers,
            data={'authorized': 'true', 'name': 'snapshot'}, files={'project': ('code.zip', self.zip_bytes())})
        self.assertEqual(submitted.status_code, 202, submitted.text)
        job_id = submitted.json()['id']
        self.assertNotIn(b'TEST-SECRET', (service.job_dir(job_id) / 'settings.enc').read_bytes())
        with patch.dict(os.environ, {'EGRESS_POLICY_ACK': 'true'}):
            response = self.client.put('/web/admin/config', json={'model': 'openai/second-model', 'api_key': '', 'api_key_reference': runtime_config.get_settings()['revision']}, headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(runtime_config.get_settings()['api_key'], 'TEST-SECRET-NEVER-RETURN')
        self.assertEqual(runtime_config.for_job(service.job_dir(job_id))['model'], 'openai/first-model')
        env = worker.child_environment('/dev/shm', runtime_config.get_settings())
        self.assertEqual(env['STRIX_API_TYPE'], 'responses')
        self.assertEqual(env['AWS_SECRET_ACCESS_KEY'], 'cloud-secret')
        self.assertNotIn('SERVICE_TOKENS_FILE', env)

    def test_settings_validation_no_unsafe_environment_and_no_network_ack(self):
        headers = self.login()
        for payload in [{'provider_env': {'LD_PRELOAD': '/tmp/evil'}},
                        {'extra_body': {'messages': []}}, {'extra_headers': {'A': 'x\ny'}},
                        {'timeout': -1}, {'api_type': 'made-up'}, {'api_base': 'https://u:p@example.com'}]:
            response = self.client.put('/web/admin/config', headers=headers, json=payload)
            self.assertEqual(response.status_code, 400, response.text)
        with patch.dict(os.environ, {'EGRESS_POLICY_ACK': 'false'}):
            self.assertEqual(self.client.put('/web/admin/config', headers=headers, json={'enabled': True}).status_code, 400)

    def test_admin_password_change_and_login_rate_limit(self):
        headers = self.login()
        result = self.client.post('/web/admin/password', headers=headers,
            json={'current_password': '296419', 'new_password': 'a-new-password'})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(self.client.get('/web/me').status_code, 401)
        self.assertEqual(self.client.post('/web/login', json={'role': 'admin', 'password': '296419'}).status_code, 401)
        self.login(password='a-new-password')

    def test_native_routes_without_api_key(self):
        value = runtime_config.defaults()
        value.update(model='ollama/qwen3', api_base='http://localhost:11434', api_type='native', api_key='')
        env = runtime_config.model_environment(value)
        self.assertNotIn('STRIX_API_TYPE', env)
        self.assertNotIn('LLM_API_KEY', env)
        self.assertIn('原生路由', portal._probe_model_basic(value)['message'])

    def test_basic_form_preserves_hidden_settings_and_key(self):
        headers=self.login()
        config=runtime_config.defaults()
        config.update(api_key='keep-this-key',extra_headers={'X-Custom':'private'},
                      extra_body={'enable_thinking':False},allowed_hosts='test.company',
                      allowed_cidrs='10.20.30.40/32',allowed_ports='443',timeout=900,max_turns=25)
        runtime_config.save_settings(config)
        with patch.dict(os.environ,{'EGRESS_POLICY_ACK':'true'}):
            response=self.client.put('/web/admin/config',headers=headers,json={
                'api_type':'chat_completions','api_base':'https://api.siliconflow.cn/v1',
                'model':'openai/deepseek-ai/DeepSeek-V3.2','api_key':'','api_key_reference':runtime_config.get_settings()['revision'],'enabled':True})
        self.assertEqual(response.status_code,200,response.text)
        saved=runtime_config.get_settings()
        for key in ('api_key','extra_headers','extra_body','allowed_hosts','allowed_cidrs','allowed_ports','timeout','max_turns'):
            self.assertEqual(saved[key],config[key])
        self.assertTrue(saved['enabled'])

    def test_two_protocol_choices_map_to_real_strix_routes(self):
        for protocol, model, expected in [('openai','deepseek-ai/DeepSeek-V3.2','openai/deepseek-ai/DeepSeek-V3.2'),
                                          ('anthropic','claude-test','anthropic/claude-test'),
                                          ('anthropic','openai/claude-test','anthropic/claude-test')]:
            with self.subTest(protocol=protocol,model=model):
                value=runtime_config.defaults()
                value.update(api_type=protocol,model=model,api_key='dummy')
                runtime_config.validate_settings(value)
                env=runtime_config.model_environment(value)
                self.assertEqual(env['STRIX_LLM'],expected)
                self.assertEqual(env.get('STRIX_API_TYPE'),'chat_completions' if protocol=='openai' else None)

    def test_probe_errors_show_diagnostics_without_credentials(self):
        import io
        import urllib.error
        config = runtime_config.defaults()
        config.update(api_type='openai', model='test', api_key='private-test-key',
                      extra_headers={'X-Token': 'private-header'})
        raw = b'{"error":"model unavailable", "api_key":"unknown-secret", "echo":"private-test-key private-header"}'
        with patch('portal.urllib.request.build_opener') as opener:
            opener.return_value.open.side_effect = urllib.error.HTTPError('https://example.test', 400, 'Bad Request', {}, io.BytesIO(raw))
            result = portal._probe_model_basic(config)
        self.assertFalse(result['ok'])
        self.assertEqual(result['status_code'], 400)
        self.assertIn('model unavailable', result['detail'])
        for secret in ('private-test-key', 'private-header', 'unknown-secret'):
            self.assertNotIn(secret, result['detail'])
        with patch('portal.urllib.request.build_opener') as opener:
            opener.return_value.open.side_effect = urllib.error.URLError('DNS lookup failed')
            self.assertIn('DNS lookup failed', portal._probe_model_basic(config)['detail'])

    def test_probe_uses_unsaved_form_and_does_not_persist(self):
        headers = self.login()
        payload = dict(api_type='openai', api_base='https://new.example/v1', model='new-model', api_key='new-key', question='测试问题')
        with patch('portal.probe_model', return_value={'ok': True}) as probe:
            response = self.client.post('/web/admin/test-model', headers=headers, json=payload)
            self.assertEqual(response.status_code, 200, response.text)
            for key, value in payload.items():
                if key=='question':continue
                self.assertEqual(probe.call_args.args[0][key], value)
        self.assertIsNone(runtime_config.get_settings())
        runtime_config.save_settings(dict(api_key='saved-key'))
        before = runtime_config.get_settings()
        payload['api_key'] = ''
        with patch('portal.probe_model', return_value={'ok': True}) as probe:
            self.assertEqual(self.client.post('/web/admin/test-model', headers=headers, json=payload).status_code, 200)
            self.assertEqual(probe.call_args.args[0]['api_key'], '')
            self.assertEqual(probe.call_args.args[0]['model'], 'new-model')
        self.assertEqual(runtime_config.get_settings(), before)

    def test_custom_question_and_answer(self):
        config = runtime_config.defaults()
        config.update(api_type='openai', model='test')
        with patch('portal.urllib.request.build_opener') as opener:
            opener.return_value.open.return_value.__enter__.return_value.read.return_value = json.dumps({'choices':[{'message':{'content':'测试回答'}}]}).encode()
            result = portal._probe_model_basic(config, '我的问题')
            body = json.loads(opener.return_value.open.call_args.args[0].data)
            self.assertEqual(body['messages'][0]['content'], '我的问题')
            self.assertNotIn('tools', body)
            self.assertEqual(result['answer'], '测试回答')
            self.assertTrue(result['custom_question'])
        headers = self.login()
        payload = dict(api_type='openai', api_base='https://test.example/v1', model='test', api_key='', question='自定义问题')
        with patch('portal.probe_model', return_value={'ok':True}) as probe:
            self.assertEqual(self.client.post('/web/admin/test-model', headers=headers, json=payload).status_code, 200)
            self.assertEqual(probe.call_args.args[1], '自定义问题')
        payload['question'] = 'x' * 4001
        self.assertEqual(self.client.post('/web/admin/test-model', headers=headers, json=payload).status_code, 400)

    def test_masked_key_reference_and_explicit_clear(self):
        headers = self.login()
        runtime_config.save_settings({'api_key':'abcd-hidden-secret-wxyz'})
        public = self.client.get('/web/admin/config').json()
        self.assertEqual(public['api_key_masked'], 'abcd••••••••wxyz')
        self.assertNotIn('hidden-secret', json.dumps(public))
        payload = dict(api_type='openai',api_base='https://example.test/v1',model='test',api_key='',api_key_reference=public['revision'],question='测试问题')
        with patch('portal.probe_model',return_value={'ok':True}) as probe:
            self.assertEqual(self.client.post('/web/admin/test-model',headers=headers,json=payload).status_code,200)
            self.assertEqual(probe.call_args.args[0]['api_key'],'abcd-hidden-secret-wxyz')
        self.assertEqual(self.client.put('/web/admin/config',headers=headers,json={'api_key':''}).status_code,200)
        self.assertEqual(runtime_config.get_settings()['api_key'],'')
        self.assertEqual(self.client.post('/web/admin/test-model',headers=headers,json=payload).status_code,409)

    def test_two_protocol_probes_use_correct_paths_and_auth(self):
        for protocol in ('openai','anthropic'):
            value=runtime_config.defaults()
            value.update(api_type=protocol,model='test-model',api_base='https://gateway.example/v1',api_key='dummy-key')
            response={'choices':[{'message':{'tool_calls':[{'id':'test'}]}}]} if protocol=='openai' else {'content':[{'type':'tool_use'}]}
            with patch('portal.urllib.request.build_opener') as opener:
                opener.return_value.open.return_value.__enter__.return_value.read.return_value=json.dumps(response).encode()
                result=portal._probe_model_basic(value)
                request=opener.return_value.open.call_args.args[0]
                self.assertTrue(result['ok'])
                self.assertTrue(result['tool_calls'])
                self.assertTrue(request.full_url.endswith('/chat/completions' if protocol=='openai' else '/messages'))
                self.assertEqual(request.get_header('Authorization' if protocol=='openai' else 'X-api-key'),
                                 'Bearer dummy-key' if protocol=='openai' else 'dummy-key')
                self.assertEqual(json.loads(request.data)['model'],'test-model')




