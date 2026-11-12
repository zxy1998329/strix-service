"""Tests for the primary/backup model circuit breaker and request router."""
import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import model_failover


def targets(revision='rev-1'):
    return {'revision': revision,
            'primary': {'role': 'primary', 'api_type': 'chat_completions', 'protocol': 'openai',
                        'api_base': 'https://primary.example/v1', 'model': 'openai/primary-model',
                        'model_name': 'primary-model', 'api_key': 'primary-secret',
                        'extra_headers': {'X-Primary': 'yes'}, 'extra_body': {'temperature': 0.1}},
            'backup': {'role': 'backup', 'api_type': 'chat_completions', 'protocol': 'openai',
                       'api_base': 'https://backup.example/v1', 'model': 'openai/backup-model',
                       'model_name': 'backup-model', 'api_key': 'backup-secret',
                       'extra_headers': {'X-Backup': 'yes'}, 'extra_body': {'temperature': 0.2}}}


class BreakerStateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        model_failover.reset_state(self.root, 'rev-1')

    def tearDown(self):
        self.temp.cleanup()

    def test_failure_opens_once_and_probe_recovers(self):
        with patch('model_failover.time.time', return_value=100):
            state = model_failover.mark_primary_failure(self.root, 'rev-1', 'HTTP 500')
        self.assertEqual(state['active'], 'backup')
        self.assertEqual(state['switches'], 1)
        self.assertEqual(state['next_probe_at'], 160)
        with patch('model_failover.time.time', return_value=120):
            again = model_failover.mark_primary_failure(self.root, 'rev-1', 'HTTP 502')
        self.assertEqual(again['active'], 'backup')
        self.assertEqual(again['switches'], 1)
        self.assertEqual(again['next_probe_at'], 180)
        with patch('model_failover.time.time', return_value=181):
            failed = model_failover.mark_probe_result(self.root, 'rev-1', False, 'timeout')
        self.assertEqual(failed['active'], 'backup')
        self.assertEqual(failed['next_probe_at'], 241)
        with patch('model_failover.time.time', return_value=242):
            recovered = model_failover.mark_probe_result(self.root, 'rev-1', True)
        self.assertEqual(recovered['active'], 'primary')
        self.assertIsNone(recovered['next_probe_at'])
        self.assertTrue(recovered['last_probe_ok'])

    def test_stale_revision_is_not_overwritten(self):
        model_failover.write_state(self.root, model_failover.default_state('new-rev'))
        state = model_failover.mark_primary_failure(self.root, 'old-rev', 'HTTP 500')
        self.assertIsNone(state)
        self.assertEqual(model_failover.raw_state(self.root)['revision'], 'new-rev')
        self.assertEqual(model_failover.raw_state(self.root)['active'], 'primary')

    def test_state_file_has_no_credentials(self):
        model_failover.mark_primary_failure(self.root, 'rev-1', 'HTTP 500')
        text = (self.root / 'model_health.json').read_text()
        self.assertNotIn('secret', text)
        self.assertNotIn('api_key', text)


class RouterTests(unittest.TestCase):
    def setUp(self):
        import httpx
        self.httpx = httpx
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        model_failover.reset_state(self.root, 'rev-1')
        self.config = targets()
        self.router = model_failover.Router(self.config, self.root, self.root / 'model_route.json')

    def tearDown(self):
        self.temp.cleanup()

    def request(self, url):
        return self.httpx.Request('POST', url, headers={
            'Authorization': 'Bearer primary-secret', 'X-Primary': 'yes', 'Content-Type': 'application/json'},
            content=json.dumps({'model': 'primary-model', 'temperature': 0.1,
                                'messages': [{'role': 'user', 'content': 'hi'}]}).encode())

    def test_rewrite_changes_url_model_auth_and_extra_body(self):
        out = self.router.rewrite(self.request('https://primary.example/v1/chat/completions'),
                                  self.config['backup'])
        self.assertEqual(str(out.url), 'https://backup.example/v1/chat/completions')
        self.assertEqual(out.headers['Authorization'], 'Bearer backup-secret')
        self.assertEqual(out.headers['X-Backup'], 'yes')
        self.assertNotIn('X-Primary', out.headers)
        body = json.loads(out.content)
        self.assertEqual(body['model'], 'backup-model')
        self.assertEqual(body['temperature'], 0.2)

    def test_route_file_has_no_credentials(self):
        self.router.active()
        self.router.note_failure('HTTP 500')
        text = (self.root / 'model_route.json').read_text()
        self.assertEqual(json.loads(text)['active'], 'backup')
        self.assertEqual(json.loads(text)['reason'], 'HTTP 500')
        self.assertNotIn('secret', text)

    def test_active_follows_shared_state(self):
        self.assertEqual(self.router.active()['role'], 'primary')
        model_failover.mark_primary_failure(self.root, 'rev-1', 'HTTP 500')
        self.assertEqual(self.router.active()['role'], 'backup')
        model_failover.mark_probe_result(self.root, 'rev-1', True)
        self.assertEqual(self.router.active()['role'], 'primary')

    def test_stale_job_keeps_local_route_without_clobbering_state(self):
        stale = dict(self.config)
        stale['revision'] = 'old-rev'
        router = model_failover.Router(stale, self.root, self.root / 'stale-route.json')
        router.note_failure('HTTP 500')
        self.assertEqual(router.active()['role'], 'backup')
        self.assertEqual(model_failover.raw_state(self.root)['revision'], 'rev-1')


class FailoverHttpxTests(unittest.TestCase):
    def setUp(self):
        import httpx
        self.httpx = httpx
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        model_failover.reset_state(self.root, 'rev-1')
        self.config = targets()

    def tearDown(self):
        self.temp.cleanup()

    def test_sync_primary_failure_retries_backup_once(self):
        import model_calls
        seen = []

        def handler(request):
            seen.append(request)
            if str(request.url).startswith('https://primary.example'):
                return self.httpx.Response(500, json={'error': 'down'})
            return self.httpx.Response(200, json={'choices': [{'message': {'content': 'ok'}}],
                                                  'usage': {'prompt_tokens': 11, 'completion_tokens': 3}})

        original_sync = self.httpx.Client.send
        original_async = self.httpx.AsyncClient.send
        router = model_failover.Router(self.config, self.root, self.root / 'route.json')
        with patch.object(self.httpx.Client, 'send', original_sync), \
                patch.object(self.httpx.AsyncClient, 'send', original_async):
            metrics = model_calls.install_httpx(self.root, router)
            with self.httpx.Client(transport=self.httpx.MockTransport(handler)) as client:
                response = client.post('https://primary.example/v1/chat/completions',
                                       json={'model': 'primary-model', 'messages': [{'role': 'user', 'content': 'hi'}]})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(seen), 2)
        self.assertEqual(str(seen[0].url), 'https://primary.example/v1/chat/completions')
        self.assertEqual(str(seen[1].url), 'https://backup.example/v1/chat/completions')
        self.assertEqual(seen[1].headers['Authorization'], 'Bearer backup-secret')
        self.assertEqual(json.loads(seen[1].content)['model'], 'backup-model')
        state = model_failover.read_state(self.root, 'rev-1')
        self.assertEqual(state['active'], 'backup')
        self.assertEqual(state['switches'], 1)
        self.assertEqual(metrics.active, {})

    def test_async_backup_is_used_directly_while_open(self):
        import model_calls
        model_failover.mark_primary_failure(self.root, 'rev-1', 'HTTP 500')
        seen = []

        async def handler(request):
            seen.append(request)
            return self.httpx.Response(200, json={'choices': [{'message': {'content': 'ok'}}]})

        original_sync = self.httpx.Client.send
        original_async = self.httpx.AsyncClient.send
        router = model_failover.Router(self.config, self.root, self.root / 'route.json')

        async def run():
            async with self.httpx.AsyncClient(transport=self.httpx.MockTransport(handler)) as client:
                return await client.post(
                    'https://primary.example/v1/chat/completions',
                    json={'model': 'primary-model', 'messages': [{'role': 'user', 'content': 'hi'}]})

        with patch.object(self.httpx.Client, 'send', original_sync), \
                patch.object(self.httpx.AsyncClient, 'send', original_async):
            model_calls.install_httpx(self.root, router)
            response = asyncio.run(run())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(seen), 1)
        self.assertEqual(str(seen[0].url), 'https://backup.example/v1/chat/completions')


class ProbeTests(unittest.TestCase):
    def test_disabled_backup_is_not_used(self):
        import runtime_config
        value = runtime_config.defaults()
        value.update(model='primary-model', api_type='openai', api_base='https://primary.example/v1',
                     backup_enabled=False, backup_model='backup-model', backup_api_type='openai',
                     backup_api_base='https://backup.example/v1')
        targets = runtime_config.model_targets(value)
        self.assertIsNone(targets['backup'])

    def test_probe_sends_hi_to_primary(self):
        import runtime_config
        value = runtime_config.defaults()
        value.update(model='primary-model', api_type='openai', api_base='https://primary.example/v1',
                     api_key='primary-secret', backup_enabled=True, backup_model='backup-model',
                     backup_api_type='openai', backup_api_base='https://backup.example/v1')
        with patch('model_failover.urllib.request.build_opener') as opener:
            response = opener.return_value.open.return_value.__enter__.return_value
            response.read.return_value = b'{"choices": []}'
            ok, error = model_failover.probe_primary(value)
            request = opener.return_value.open.call_args.args[0]
        self.assertTrue(ok)
        self.assertIsNone(error)
        self.assertEqual(request.full_url, 'https://primary.example/v1/chat/completions')
        self.assertEqual(json.loads(request.data)['messages'][0]['content'], 'hi')
        self.assertEqual(request.get_header('Authorization'), 'Bearer primary-secret')


if __name__ == '__main__':
    unittest.main()
